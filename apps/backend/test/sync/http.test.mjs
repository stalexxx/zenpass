import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { buildApp } from '../../src/app.mjs';
import { createPool } from '../../src/db.mjs';
import { issueSession } from '../../src/auth/sessions.mjs';
import { encodeB64 } from '../../src/auth/codec.mjs';

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
  // registerSyncRoutes is wired into buildApp() by apps/backend/src/app.mjs.
  const app = buildApp(config, { pool });
  try {
    await fn(app, pool);
  } finally {
    await app.close();
  }
}

/** Inserts a fresh account and issues a live session for it, bypassing the
 * OPAQUE dance (already covered by apps/backend/test/auth/http.test.mjs) so
 * these tests stay focused on sync behavior. */
async function createSession(pool) {
  const accountId = `acct-${randomUUID()}`;
  await pool.query('INSERT INTO accounts (account_id) VALUES ($1)', [accountId]);
  const session = await issueSession(pool, accountId, config.sessionTtlSeconds);
  return { accountId, accessToken: session.accessToken };
}

function mutation(overrides = {}) {
  return {
    mutationId: `mut-${randomUUID()}`,
    itemId: `item-${randomUUID()}`,
    vaultId: 'vault-placeholder',
    baseRevision: 0,
    ciphertext: encodeB64(Buffer.from('opaque-ciphertext')),
    envelopeVersion: 'crypto-envelope/v1',
    deleted: false,
    ...overrides
  };
}

async function mutate(app, accessToken, vaultId, body) {
  return app.inject({
    method: 'POST',
    url: `/vaults/${vaultId}/items`,
    headers: { authorization: `Bearer ${accessToken}` },
    payload: body
  });
}

async function changes(app, accessToken, vaultId, query = {}) {
  const search = new URLSearchParams(query).toString();
  return app.inject({
    method: 'GET',
    url: `/vaults/${vaultId}/changes${search ? `?${search}` : ''}`,
    headers: { authorization: `Bearer ${accessToken}` }
  });
}

integrationTest('the server never merges ciphertext: an opaque blob round-trips byte-for-byte', async () => {
  await withApp(async (app, pool) => {
    const { accessToken } = await createSession(pool);
    const vaultId = `vault-${randomUUID()}`;
    const secret = Buffer.from('super-secret-ciphertext-bytes');
    const response = await mutate(app, accessToken, vaultId, mutation({ vaultId, ciphertext: encodeB64(secret) }));
    assert.equal(response.statusCode, 201);
    const record = response.json();
    assert.equal(record.ciphertext, encodeB64(secret));
    assert.equal(record.revision, 1);
    assert.equal(record.deleted, false);
  });
});

integrationTest('a stale baseRevision returns a 409 with both opaque records, and does not corrupt the stored item (rollback)', async () => {
  await withApp(async (app, pool) => {
    const { accessToken } = await createSession(pool);
    const vaultId = `vault-${randomUUID()}`;
    const itemId = `item-${randomUUID()}`;

    const first = await mutate(app, accessToken, vaultId, mutation({ vaultId, itemId, baseRevision: 0 }));
    assert.equal(first.statusCode, 201);
    assert.equal(first.json().revision, 1);

    const staleAttempt = mutation({ vaultId, itemId, baseRevision: 0 });
    const conflict = await mutate(app, accessToken, vaultId, staleAttempt);
    assert.equal(conflict.statusCode, 409);
    const body = conflict.json();
    assert.equal(body.error, 'conflict');
    assert.equal(body.mutationId, staleAttempt.mutationId);
    assert.equal(body.current.revision, 1);
    assert.equal(body.current.itemId, itemId);
    assert.deepEqual(body.attempted, staleAttempt);

    // Rollback: the conflicting attempt must not have partially applied.
    const { rows } = await pool.query('SELECT revision FROM vault_items WHERE vault_id = $1 AND item_id = $2', [
      vaultId,
      itemId
    ]);
    assert.equal(rows.length, 1);
    assert.equal(Number(rows[0].revision), 1);

    // A correctly-based follow-up mutation still succeeds afterward.
    const retry = await mutate(app, accessToken, vaultId, mutation({ vaultId, itemId, baseRevision: 1 }));
    assert.equal(retry.statusCode, 201);
    assert.equal(retry.json().revision, 2);
  });
});

integrationTest('replaying the same mutationId returns the exact original result, not a fresh conflict', async () => {
  await withApp(async (app, pool) => {
    const { accessToken } = await createSession(pool);
    const vaultId = `vault-${randomUUID()}`;
    const body = mutation({ vaultId });

    const first = await mutate(app, accessToken, vaultId, body);
    assert.equal(first.statusCode, 201);
    const firstRecord = first.json();

    const replay = await mutate(app, accessToken, vaultId, body);
    assert.equal(replay.statusCode, 201);
    assert.deepEqual(replay.json(), firstRecord);

    // Only one revision was ever committed — the replay did not reapply.
    const { rows } = await pool.query('SELECT revision FROM vault_items WHERE vault_id = $1 AND item_id = $2', [
      vaultId,
      body.itemId
    ]);
    assert.equal(rows.length, 1);
    assert.equal(Number(rows[0].revision), 1);
  });
});

integrationTest('replaying a mutationId that resulted in a 409 returns the same 409, not a new conflict record', async () => {
  await withApp(async (app, pool) => {
    const { accessToken } = await createSession(pool);
    const vaultId = `vault-${randomUUID()}`;
    const itemId = `item-${randomUUID()}`;
    await mutate(app, accessToken, vaultId, mutation({ vaultId, itemId, baseRevision: 0 }));

    const staleAttempt = mutation({ vaultId, itemId, baseRevision: 0 });
    const conflict = await mutate(app, accessToken, vaultId, staleAttempt);
    assert.equal(conflict.statusCode, 409);

    const replayedConflict = await mutate(app, accessToken, vaultId, staleAttempt);
    assert.equal(replayedConflict.statusCode, 409);
    assert.deepEqual(replayedConflict.json(), conflict.json());
  });
});

integrationTest('deletes are tombstones that stay visible in the change feed', async () => {
  await withApp(async (app, pool) => {
    const { accessToken } = await createSession(pool);
    const vaultId = `vault-${randomUUID()}`;
    const itemId = `item-${randomUUID()}`;

    await mutate(app, accessToken, vaultId, mutation({ vaultId, itemId, baseRevision: 0 }));
    const del = await mutate(
      app,
      accessToken,
      vaultId,
      mutation({ vaultId, itemId, baseRevision: 1, deleted: true })
    );
    assert.equal(del.statusCode, 201);
    assert.equal(del.json().deleted, true);
    assert.equal(del.json().revision, 2);

    const feed = await changes(app, accessToken, vaultId);
    assert.equal(feed.statusCode, 200);
    const page = feed.json();
    const record = page.changes.find((c) => c.itemId === itemId);
    assert.ok(record, 'tombstone must remain in the feed');
    assert.equal(record.deleted, true);
    assert.equal(record.revision, 2);
  });
});

integrationTest('the change feed paginates and the same cursor replayed twice returns the same page (idempotent)', async () => {
  await withApp(async (app, pool) => {
    const { accessToken } = await createSession(pool);
    const vaultId = `vault-${randomUUID()}`;
    const itemIds = [1, 2, 3].map(() => `item-${randomUUID()}`);
    for (const itemId of itemIds) {
      const response = await mutate(app, accessToken, vaultId, mutation({ vaultId, itemId, baseRevision: 0 }));
      assert.equal(response.statusCode, 201);
    }

    const pageOne = await changes(app, accessToken, vaultId, { limit: '2' });
    assert.equal(pageOne.statusCode, 200);
    const firstBody = pageOne.json();
    assert.equal(firstBody.changes.length, 2);
    assert.ok(firstBody.nextCursor);

    const pageTwo = await changes(app, accessToken, vaultId, { cursor: firstBody.nextCursor, limit: '2' });
    const secondBody = pageTwo.json();
    assert.equal(secondBody.changes.length, 1);

    // Idempotent replay: requesting the very first cursor again returns
    // the identical page.
    const pageOneReplayed = await changes(app, accessToken, vaultId, { limit: '2' });
    assert.deepEqual(pageOneReplayed.json(), firstBody);

    // Requesting past the end returns no changes and a stable cursor.
    const pageThree = await changes(app, accessToken, vaultId, { cursor: secondBody.nextCursor, limit: '2' });
    const thirdBody = pageThree.json();
    assert.equal(thirdBody.changes.length, 0);
    const pageThreeReplayed = await changes(app, accessToken, vaultId, { cursor: secondBody.nextCursor, limit: '2' });
    assert.deepEqual(pageThreeReplayed.json(), thirdBody);

    const allIds = new Set([...firstBody.changes, ...secondBody.changes].map((c) => c.itemId));
    assert.deepEqual(allIds, new Set(itemIds));
  });
});

integrationTest('two devices sharing an account see each other\'s committed changes via the feed', async () => {
  await withApp(async (app, pool) => {
    const accountId = `acct-${randomUUID()}`;
    await pool.query('INSERT INTO accounts (account_id) VALUES ($1)', [accountId]);
    const deviceASession = await issueSession(pool, accountId, config.sessionTtlSeconds);
    const deviceBSession = await issueSession(pool, accountId, config.sessionTtlSeconds);

    const vaultId = `vault-${randomUUID()}`;
    const itemFromA = `item-${randomUUID()}`;
    const itemFromB = `item-${randomUUID()}`;

    const writeA = await mutate(
      app,
      deviceASession.accessToken,
      vaultId,
      mutation({ vaultId, itemId: itemFromA, baseRevision: 0 })
    );
    assert.equal(writeA.statusCode, 201);

    const writeB = await mutate(
      app,
      deviceBSession.accessToken,
      vaultId,
      mutation({ vaultId, itemId: itemFromB, baseRevision: 0 })
    );
    assert.equal(writeB.statusCode, 201);

    const feedForB = await changes(app, deviceBSession.accessToken, vaultId);
    const idsSeenByB = feedForB.json().changes.map((c) => c.itemId);
    assert.ok(idsSeenByB.includes(itemFromA), 'device B must see device A\'s committed change');
    assert.ok(idsSeenByB.includes(itemFromB));

    const feedForA = await changes(app, deviceASession.accessToken, vaultId);
    const idsSeenByA = feedForA.json().changes.map((c) => c.itemId);
    assert.ok(idsSeenByA.includes(itemFromB), 'device A must see device B\'s committed change');
  });
});

integrationTest('a vault is owned by whichever account first writes to it; other accounts get a generic 404', async () => {
  await withApp(async (app, pool) => {
    const owner = await createSession(pool);
    const stranger = await createSession(pool);
    const vaultId = `vault-${randomUUID()}`;

    const created = await mutate(app, owner.accessToken, vaultId, mutation({ vaultId, baseRevision: 0 }));
    assert.equal(created.statusCode, 201);

    const strangerMutate = await mutate(app, stranger.accessToken, vaultId, mutation({ vaultId, baseRevision: 0 }));
    assert.equal(strangerMutate.statusCode, 404);

    const strangerRead = await changes(app, stranger.accessToken, vaultId);
    assert.equal(strangerRead.statusCode, 404);

    // A vaultId a stranger has never touched at all is also a generic 404
    // on read (never auto-created by a GET).
    const neverTouched = await changes(app, stranger.accessToken, `vault-${randomUUID()}`);
    assert.equal(neverTouched.statusCode, 404);
  });
});

integrationTest('body/path vaultId mismatch and malformed mutations are rejected as bad requests', async () => {
  await withApp(async (app, pool) => {
    const { accessToken } = await createSession(pool);
    const vaultId = `vault-${randomUUID()}`;

    const mismatched = await mutate(app, accessToken, vaultId, mutation({ vaultId: `other-${randomUUID()}` }));
    assert.equal(mismatched.statusCode, 400);

    const badEnvelope = await mutate(app, accessToken, vaultId, mutation({ vaultId, envelopeVersion: 'v0' }));
    assert.equal(badEnvelope.statusCode, 400);

    const nonZeroBaseOnNewItem = await mutate(app, accessToken, vaultId, mutation({ vaultId, baseRevision: 5 }));
    assert.equal(nonZeroBaseOnNewItem.statusCode, 400);
  });
});

integrationTest('requests without a valid session are rejected', async () => {
  await withApp(async (app) => {
    const vaultId = `vault-${randomUUID()}`;
    const response = await app.inject({ method: 'GET', url: `/vaults/${vaultId}/changes` });
    assert.equal(response.statusCode, 401);
  });
});
