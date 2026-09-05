// SEC-06 (GitHub issue #6): rotateSession's revoke-then-insert used to be
// two separate statements with no affected-row check, so two concurrent
// `/auth/refresh` calls against the same bearer session could each pass the
// earlier liveness check and mint a distinct successor token. This file
// exercises the fixed, atomic implementation in `sessions.mjs` under real
// concurrency against a real PostgreSQL instance (`TEST_DATABASE_URL`) —
// never against a fixture or mocked pool, and never logging/asserting on
// real token values beyond presence/absence.
import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { buildApp } from '../../src/app.mjs';
import { createPool } from '../../src/db.mjs';
import { bindSessionToDevice, issueSession, resolveSession, rotateSession } from '../../src/auth/sessions.mjs';

const databaseUrl = process.env.TEST_DATABASE_URL;
const integrationTest = databaseUrl ? test : test.skip;

const config = Object.freeze({
  nodeEnv: 'test',
  logLevel: 'silent',
  requestIdHeader: 'x-request-id',
  opaqueServerSetup: null,
  sessionTtlSeconds: 900,
  authRateLimitMax: 1000,
  authRateLimitWindowSeconds: 300
});

async function withApp(fn) {
  const pool = createPool({ databaseUrl, databaseSsl: false });
  const app = buildApp(config, { pool });
  try {
    await fn(app, pool);
  } finally {
    await app.close();
  }
}

/**
 * Sets up a live, device-bound session the way `/auth/opaque/login` +
 * `/devices` would, but directly against the pool: this file is scoped to
 * `rotateSession`'s concurrency behavior, not the OPAQUE handshake or
 * device-enrollment routes (already covered by http.test.mjs and
 * bearer-enrollment.test.mjs).
 */
async function createDeviceBoundSession(pool, { ttlSeconds = config.sessionTtlSeconds, deviceId = `device-${randomUUID()}` } = {}) {
  const accountId = `acct-${randomUUID()}`;
  await pool.query('INSERT INTO accounts (account_id) VALUES ($1)', [accountId]);
  await pool.query(
    "INSERT INTO devices (device_id, account_id, name, enrollment_mode) VALUES ($1, $2, 'Test device', 'bearer-session-v1')",
    [deviceId, accountId]
  );
  const session = await issueSession(pool, accountId, ttlSeconds);
  await bindSessionToDevice(pool, session.sessionId, deviceId);
  return { accountId, deviceId, sessionId: session.sessionId, accessToken: session.accessToken };
}

/**
 * Forces every `pool.connect()` call made while the barrier is armed to
 * block until `count` callers have all arrived, then releases them all at
 * once. `rotateSession` is currently the only call site in this codebase
 * that uses `pool.connect()` (every other query goes through `pool.query`
 * directly), so this precisely synchronizes concurrent `rotateSession`
 * invocations to start their transactions together — the "barrier" the
 * task spec calls for — instead of relying on hoping Node's scheduler
 * interleaves two `Promise.all`'d requests without one completing first.
 */
function barrierConnect(pool, count) {
  const originalConnect = pool.connect.bind(pool);
  let arrived = 0;
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  pool.connect = async (...args) => {
    arrived += 1;
    if (arrived >= count) release();
    await gate;
    return originalConnect(...args);
  };
  return () => {
    pool.connect = originalConnect;
  };
}

/**
 * Makes any successor `INSERT` whose `device_id` starts with the given
 * marker prefix fail, to test rollback. Deliberately a real Postgres
 * trigger/function rather than a monkey-patched `pg` client: `pg-pool`
 * reuses client objects and internally calls `client.query()` with a
 * `Query` submittable object rather than always `(text, params)`, so
 * intercepting at the JS driver layer is fragile (it desynced a later,
 * unrelated query in early drafts of this test and hung the suite). A
 * `BEFORE INSERT` trigger scoped to a device-id prefix this test controls
 * gets a genuine wire-level error from the server, which is also a more
 * faithful stand-in for "the INSERT fails for some other reason" than a
 * client-side short-circuit.
 */
async function withForcedSuccessorInsertFailure(pool, run) {
  await pool.query(`
    CREATE OR REPLACE FUNCTION sec06_force_insert_failure() RETURNS trigger AS $fn$
    BEGIN
      IF NEW.device_id LIKE 'sec06-force-fail-%' THEN
        RAISE EXCEPTION 'SEC-06 test: forced successor insert failure';
      END IF;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql;
    DROP TRIGGER IF EXISTS sec06_force_insert_failure_trigger ON sessions;
    CREATE TRIGGER sec06_force_insert_failure_trigger
      BEFORE INSERT ON sessions
      FOR EACH ROW EXECUTE FUNCTION sec06_force_insert_failure();
  `);
  try {
    await run();
  } finally {
    await pool.query('DROP TRIGGER IF EXISTS sec06_force_insert_failure_trigger ON sessions');
    await pool.query('DROP FUNCTION IF EXISTS sec06_force_insert_failure()');
  }
}

integrationTest(
  'exactly one of two concurrent /auth/refresh calls for the same session wins (SEC-06)',
  async () => {
    await withApp(async (app) => {
      const { accountId, accessToken } = await createDeviceBoundSession(app.db);

      const releaseBarrier = barrierConnect(app.db, 2);
      let responses;
      try {
        responses = await Promise.all([
          app.inject({ method: 'POST', url: '/auth/refresh', headers: { authorization: `Bearer ${accessToken}` } }),
          app.inject({ method: 'POST', url: '/auth/refresh', headers: { authorization: `Bearer ${accessToken}` } })
        ]);
      } finally {
        releaseBarrier();
      }

      const statuses = responses.map((r) => r.statusCode).sort();
      assert.deepEqual(statuses, [200, 401]); // exactly one winner, the other generically unauthorized

      const winner = responses.find((r) => r.statusCode === 200);
      const winnerBody = winner.json();
      assert.ok(winnerBody.accessToken);
      assert.ok(winnerBody.expiresAt);

      const loser = responses.find((r) => r.statusCode === 401);
      assert.equal(loser.json().error, 'authentication_failed'); // generic, not a distinguishing race detail

      const { rows } = await app.db.query(
        'SELECT session_id, revoked_at, issued_via FROM sessions WHERE account_id = $1',
        [accountId]
      );
      assert.equal(rows.length, 2); // the original plus exactly one successor — never two successors

      const successors = rows.filter((row) => row.issued_via === 'refresh');
      assert.equal(successors.length, 1);

      const original = rows.find((row) => row.issued_via === 'opaque-login');
      assert.ok(original.revoked_at); // the original is consumed exactly once
    });
  }
);

integrationTest(
  'a refresh racing a concurrent logout/revoke never yields two successors, and logout always completes',
  async () => {
    await withApp(async (app) => {
      const { accountId, accessToken } = await createDeviceBoundSession(app.db);

      const [refreshResponse, logoutResponse] = await Promise.all([
        app.inject({ method: 'POST', url: '/auth/refresh', headers: { authorization: `Bearer ${accessToken}` } }),
        app.inject({ method: 'POST', url: '/auth/logout', headers: { authorization: `Bearer ${accessToken}` } })
      ]);

      // revokeSession's own UPDATE has no affected-row check (logout of an
      // already-revoked/rotated session is still treated as a successful
      // logout), but `requireSession`'s earlier liveness read can itself
      // observe the session as already revoked if refresh's transaction
      // committed first — in that case logout never reaches revokeSession
      // at all and gets the same generic 401 refresh's loser gets. Either
      // side can therefore be the one that's generically unauthorized;
      // what must never happen is two successors, or the original session
      // surviving the race un-revoked.
      assert.ok([204, 401].includes(logoutResponse.statusCode));
      assert.ok([200, 401].includes(refreshResponse.statusCode));

      const { rows } = await app.db.query(
        'SELECT session_id, revoked_at, issued_via FROM sessions WHERE account_id = $1',
        [accountId]
      );
      const successors = rows.filter((row) => row.issued_via === 'refresh');

      if (refreshResponse.statusCode === 200) {
        assert.equal(successors.length, 1);
        const newToken = refreshResponse.json().accessToken;
        assert.ok(newToken);
        // the successor from the winning refresh must itself be a live,
        // usable session — the race must not leave behind a token that
        // looks minted but doesn't actually authenticate.
        const probe = await app.inject({
          method: 'GET',
          url: '/devices',
          headers: { authorization: `Bearer ${newToken}` }
        });
        assert.equal(probe.statusCode, 200);
      } else {
        assert.equal(successors.length, 0); // logout won the race: no successor was ever minted
      }

      const original = rows.find((row) => row.issued_via === 'opaque-login');
      assert.ok(original.revoked_at); // the original session is revoked either way
    });
  }
);

integrationTest('rotateSession rolls back the revoke if the successor INSERT fails', async () => {
  await withApp(async (app) => {
    const deviceId = `sec06-force-fail-${randomUUID()}`;
    const { accountId, accessToken } = await createDeviceBoundSession(app.db, { deviceId });
    const session = await resolveSession(app.db, accessToken);
    assert.ok(session);

    await withForcedSuccessorInsertFailure(app.db, async () => {
      await assert.rejects(() => rotateSession(app.db, session, config.sessionTtlSeconds));
    });

    const { rows } = await app.db.query('SELECT revoked_at, issued_via FROM sessions WHERE account_id = $1', [
      accountId
    ]);
    assert.equal(rows.length, 1); // no successor row was left behind by the failed attempt
    assert.equal(rows[0].revoked_at, null); // the revoke was rolled back too — original session still live

    // A subsequent legitimate rotation (trigger removed) still works normally afterward.
    const retried = await rotateSession(app.db, session, config.sessionTtlSeconds);
    assert.ok(retried);
    assert.ok(retried.accessToken);

    const afterRetry = await app.db.query('SELECT revoked_at, issued_via FROM sessions WHERE account_id = $1', [
      accountId
    ]);
    assert.equal(afterRetry.rows.length, 2);
  });
});
