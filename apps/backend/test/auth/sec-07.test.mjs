// SEC-07: unauthenticated login/registration must not create unbounded
// `accounts`/`auth_rate_limits` rows before the request's accountId
// grammar and OPAQUE message shape are validated, and a coarse admission
// control must bound raw request volume ahead of any persistent write.
import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { buildApp } from '../../src/app.mjs';
import { createPool } from '../../src/db.mjs';
import { createAuthContext } from '../../src/auth/init.mjs';
import { encodeB64, decodeB64 } from '../../src/auth/codec.mjs';
import { cleanupStaleAuthState } from '../../src/auth/cleanup.mjs';
import init, { client_login_start, client_registration_start } from '../../../../packages/crypto-server/pkg/crypto_server.js';

const databaseUrl = process.env.TEST_DATABASE_URL;
const integrationTest = databaseUrl ? test : test.skip;
const PASSWORD = new TextEncoder().encode('CorrectHorseBatteryStaple');

function config(overrides = {}) {
  return Object.freeze({
    nodeEnv: 'test',
    logLevel: 'silent',
    requestIdHeader: 'x-request-id',
    opaqueServerSetup: null,
    sessionTtlSeconds: 2,
    authRateLimitMax: 1000,
    authRateLimitWindowSeconds: 300,
    ...overrides
  });
}

async function withApp(fn, configOverrides = {}) {
  await init();
  const pool = createPool({ databaseUrl, databaseSsl: false });
  const cfg = config(configOverrides);
  const authContext = createAuthContext(cfg, { logger: { warn() {} } });
  const app = buildApp(cfg, { pool, authContext });
  try {
    await fn(app, pool);
  } finally {
    await app.close();
  }
}

async function accountRowExists(pool, accountId) {
  const { rows } = await pool.query('SELECT 1 FROM accounts WHERE account_id = $1', [accountId]);
  return rows.length > 0;
}

async function rateLimitRowCount(pool, accountId) {
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM auth_rate_limits WHERE account_id = $1', [
    accountId
  ]);
  return rows[0].n;
}

integrationTest('a malformed login (bad clientMessage shape) creates no accounts row', async () => {
  const accountId = `acct-sec07-${randomUUID()}`;
  await withApp(async (app, pool) => {
    // Well-formed accountId grammar, but clientMessage is far shorter than
    // KE1_LEN -- exactly the flood primitive from GitHub issue #7.
    const response = await app.inject({
      method: 'POST',
      url: '/auth/opaque/login',
      payload: { accountId, clientMessage: encodeB64(Buffer.alloc(4)) }
    });
    assert.equal(response.statusCode, 401);
    assert.equal(await accountRowExists(pool, accountId), false);
    assert.equal(await rateLimitRowCount(pool, accountId), 0);
  });
});

integrationTest('a malformed accountId creates no accounts row, for either route', async () => {
  const badAccountId = 'not a valid account id! ***';
  await withApp(async (app, pool) => {
    const loginResponse = await app.inject({
      method: 'POST',
      url: '/auth/opaque/login',
      payload: { accountId: badAccountId, clientMessage: encodeB64(Buffer.alloc(96)) }
    });
    assert.equal(loginResponse.statusCode, 401);

    const registerResponse = await app.inject({
      method: 'POST',
      url: '/auth/opaque/register',
      payload: { accountId: badAccountId, clientMessage: encodeB64(Buffer.alloc(32)) }
    });
    assert.equal(registerResponse.statusCode, 400);

    assert.equal(await accountRowExists(pool, badAccountId), false);
  });
});

integrationTest('a malformed registration (bad clientMessage shape) creates no accounts row', async () => {
  const accountId = `acct-sec07-${randomUUID()}`;
  await withApp(async (app, pool) => {
    // Neither a valid 32-byte RegistrationRequest nor a well-formed
    // RegistrationUpload: registrationStep must reject this before any
    // write, exactly like a real client would never produce this shape.
    const response = await app.inject({
      method: 'POST',
      url: '/auth/opaque/register',
      payload: { accountId, clientMessage: encodeB64(Buffer.alloc(5)) }
    });
    assert.equal(response.statusCode, 400);
    assert.equal(await accountRowExists(pool, accountId), false);
  });
});

integrationTest(
  'a flood of distinct malformed/synthetic accountIds is bounded by admission control, not one row per accountId',
  async () => {
    const prefix = `acct-sec07-flood-${randomUUID()}`;
    const admissionMax = 5;
    const floodSize = 20;
    await withApp(
      async (app, pool) => {
        for (let i = 0; i < floodSize; i += 1) {
          // Each request uses a distinct, well-formed-grammar accountId and
          // a correctly-shaped (KE1_LEN) but otherwise garbage message --
          // i.e. exactly what a flood exploiting the pre-fix ordering would
          // send. Every one of these would previously get its own
          // `accounts` + `auth_rate_limits` row.
          // eslint-disable-next-line no-await-in-loop
          await app.inject({
            method: 'POST',
            url: '/auth/opaque/login',
            payload: { accountId: `${prefix}-${i}`, clientMessage: encodeB64(Buffer.alloc(96)) }
          });
        }

        const { rows } = await pool.query(
          "SELECT count(*)::int AS n FROM accounts WHERE account_id LIKE $1",
          [`${prefix}-%`]
        );
        assert.ok(
          rows[0].n <= admissionMax,
          `expected at most ${admissionMax} accounts rows from a ${floodSize}-request flood, got ${rows[0].n}`
        );
        assert.ok(rows[0].n < floodSize, 'admission control must actually bound volume below the flood size');
      },
      { authAdmissionRateLimitMax: admissionMax, authAdmissionRateLimitWindowSeconds: 300 }
    );
  }
);

integrationTest(
  'malformed, unknown-account, and known-account-wrong-password login responses are identically shaped',
  async () => {
    await withApp(async (app, pool) => {
      const malformedAccountId = `acct-sec07-shape-malformed-${randomUUID()}`;
      const malformed = await app.inject({
        method: 'POST',
        url: '/auth/opaque/login',
        payload: { accountId: malformedAccountId, clientMessage: encodeB64(Buffer.alloc(4)) }
      });

      const unknownAccountId = `acct-sec07-shape-unknown-${randomUUID()}`;
      const unknownStart = client_login_start(PASSWORD);
      const unknownKe2 = await app.inject({
        method: 'POST',
        url: '/auth/opaque/login',
        payload: { accountId: unknownAccountId, clientMessage: encodeB64(unknownStart.message) }
      });
      assert.equal(unknownKe2.statusCode, 200); // shaped like a continuation, per ADR-0006 §9
      const unknownFinish = await app.inject({
        method: 'POST',
        url: '/auth/opaque/login',
        payload: { accountId: unknownAccountId, clientMessage: encodeB64(Buffer.alloc(64)) }
      });

      // Both terminal rejections must carry the exact same generic shape:
      // no field lets a caller distinguish "malformed request" from
      // "unknown account, correctly-shaped attempt".
      assert.equal(malformed.statusCode, 401);
      assert.equal(unknownFinish.statusCode, 401);
      assert.deepEqual(Object.keys(malformed.json()).sort(), Object.keys(unknownFinish.json()).sort());
      assert.equal(malformed.json().error, unknownFinish.json().error);
      assert.equal(malformed.json().message, unknownFinish.json().message);

      // A malformed accountId (fails grammar) must be equally indistinguishable.
      const badGrammar = await app.inject({
        method: 'POST',
        url: '/auth/opaque/login',
        payload: { accountId: 'bad id with spaces', clientMessage: encodeB64(Buffer.alloc(96)) }
      });
      assert.equal(badGrammar.statusCode, 401);
      assert.equal(badGrammar.json().error, malformed.json().error);
      assert.equal(badGrammar.json().message, malformed.json().message);
    });
  }
);

integrationTest('cleanupStaleAuthState bounds the lifetime of rate-limit rows and incomplete-registration accounts', async () => {
  const pool = createPool({ databaseUrl, databaseSsl: false });
  try {
    const staleAccountId = `acct-sec07-cleanup-stale-${randomUUID()}`;
    const freshAccountId = `acct-sec07-cleanup-fresh-${randomUUID()}`;
    const completedAccountId = `acct-sec07-cleanup-completed-${randomUUID()}`;
    const longAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000); // 10 days ago

    // A stale, never-completed registration: old `accounts` row, no
    // `opaque_credentials`, and an old `auth_rate_limits` row.
    await pool.query('INSERT INTO accounts (account_id, created_at) VALUES ($1, $2)', [
      staleAccountId,
      longAgo
    ]);
    await pool.query(
      'INSERT INTO auth_rate_limits (account_id, scope, window_start, count) VALUES ($1, $2, $3, 1)',
      [staleAccountId, 'login', longAgo]
    );

    // A fresh, never-completed registration: must survive cleanup (not old
    // enough yet).
    await pool.query('INSERT INTO accounts (account_id) VALUES ($1)', [freshAccountId]);

    // A completed registration that is old: must survive cleanup because
    // it has a credential record (it's a real account, not an abandoned
    // attempt), even though it's old.
    await pool.query('INSERT INTO accounts (account_id, created_at) VALUES ($1, $2)', [
      completedAccountId,
      longAgo
    ]);
    await pool.query('INSERT INTO opaque_credentials (account_id, credential_record) VALUES ($1, $2)', [
      completedAccountId,
      Buffer.from('fake-record')
    ]);

    await cleanupStaleAuthState(pool, {
      rateLimitRetentionMs: 24 * 60 * 60 * 1000,
      staleAccountRetentionMs: 24 * 60 * 60 * 1000
    });

    assert.equal(await accountRowExists(pool, staleAccountId), false);
    assert.equal(await rateLimitRowCount(pool, staleAccountId), 0);
    assert.equal(await accountRowExists(pool, freshAccountId), true);
    assert.equal(await accountRowExists(pool, completedAccountId), true);
  } finally {
    await pool.end();
  }
});
