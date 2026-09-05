import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { buildApp } from '../../src/app.mjs';
import { createPool } from '../../src/db.mjs';
import { issueSession } from '../../src/auth/sessions.mjs';
import { encodeB64 } from '../../src/auth/codec.mjs';
import { ACCOUNT_BUNDLE_FIELDS, ACCOUNT_BUNDLE_FORMAT } from '../../src/account/bundle-codec.mjs';

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

/** Bypasses the OPAQUE dance (covered by apps/backend/test/auth/http.test.mjs)
 * so these tests stay focused on the key-bundle contract. */
async function createSession(pool, accountId = `acct-${randomUUID()}`) {
  await pool.query('INSERT INTO accounts (account_id) VALUES ($1)', [accountId]);
  const session = await issueSession(pool, accountId, config.sessionTtlSeconds);
  return { accountId, accessToken: session.accessToken };
}

function bundleWireValue(accountId, overrides = {}) {
  const fields = {
    format: ACCOUNT_BUNDLE_FORMAT,
    accountId,
    vaultId: 'vault-01',
    itemId: 'item-01',
    kdfParametersCbor: encodeB64(Buffer.from('kdf-params')),
    wrappedAccountKey: encodeB64(Buffer.from('wrapped-account-key')),
    wrappedVaultKey: encodeB64(Buffer.from('wrapped-vault-key')),
    wrappedItemKey: encodeB64(Buffer.from('wrapped-item-key')),
    wrappedRecoveryKey: encodeB64(Buffer.from('wrapped-recovery-key')),
    ...overrides
  };
  const ordered = {};
  for (const key of ACCOUNT_BUNDLE_FIELDS) ordered[key] = fields[key];
  return encodeB64(Buffer.from(JSON.stringify(ordered), 'utf8'));
}

integrationTest('GET before any publish returns 404, never a fabricated empty bundle', async () => {
  await withApp(async (app, pool) => {
    const { accessToken } = await createSession(pool);
    const response = await app.inject({
      method: 'GET',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.equal(response.statusCode, 404);
  });
});

integrationTest('first publish (version 1) creates the row; GET returns exact bytes and version', async () => {
  await withApp(async (app, pool) => {
    const { accountId, accessToken } = await createSession(pool);
    const bundle = bundleWireValue(accountId);
    const putResponse = await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle, version: 1 }
    });
    assert.equal(putResponse.statusCode, 204);

    const getResponse = await app.inject({
      method: 'GET',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.equal(getResponse.statusCode, 200);
    assert.deepEqual(getResponse.json(), { bundle, version: 1 });
  });
});

integrationTest('replacing with version = current + 1 commits', async () => {
  await withApp(async (app, pool) => {
    const { accountId, accessToken } = await createSession(pool);
    const v1 = bundleWireValue(accountId, { itemId: 'item-01' });
    await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle: v1, version: 1 }
    });
    const v2 = bundleWireValue(accountId, { itemId: 'item-02' });
    const replace = await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle: v2, version: 2 }
    });
    assert.equal(replace.statusCode, 204);
    const getResponse = await app.inject({
      method: 'GET',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.deepEqual(getResponse.json(), { bundle: v2, version: 2 });
  });
});

integrationTest('replaying the same bytes at the current version is an idempotent 204', async () => {
  await withApp(async (app, pool) => {
    const { accountId, accessToken } = await createSession(pool);
    const bundle = bundleWireValue(accountId);
    for (let i = 0; i < 2; i += 1) {
      const response = await app.inject({
        method: 'PUT',
        url: '/account/key-bundle',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { bundle, version: 1 }
      });
      assert.equal(response.statusCode, 204);
    }
  });
});

integrationTest('different bytes at the same version is a 409 KeyBundleConflict, not silently accepted', async () => {
  await withApp(async (app, pool) => {
    const { accountId, accessToken } = await createSession(pool);
    await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle: bundleWireValue(accountId, { itemId: 'item-01' }), version: 1 }
    });
    const conflicting = await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle: bundleWireValue(accountId, { itemId: 'item-99' }), version: 1 }
    });
    assert.equal(conflicting.statusCode, 409);
    assert.deepEqual(conflicting.json(), {
      error: 'key_bundle_conflict',
      currentVersion: 1,
      attemptedVersion: 1
    });
  });
});

integrationTest('an older retry after a revision has advanced conflicts rather than rewinding', async () => {
  await withApp(async (app, pool) => {
    const { accountId, accessToken } = await createSession(pool);
    await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle: bundleWireValue(accountId, { itemId: 'item-01' }), version: 1 }
    });
    await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle: bundleWireValue(accountId, { itemId: 'item-02' }), version: 2 }
    });
    const stale = await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle: bundleWireValue(accountId, { itemId: 'item-01' }), version: 1 }
    });
    assert.equal(stale.statusCode, 409);
    assert.equal(stale.json().currentVersion, 2);
  });
});

integrationTest('a first publish attempt at version other than 1 is a 409 with a null currentVersion', async () => {
  await withApp(async (app, pool) => {
    const { accountId, accessToken } = await createSession(pool);
    const response = await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle: bundleWireValue(accountId), version: 2 }
    });
    assert.equal(response.statusCode, 409);
    assert.deepEqual(response.json(), { error: 'key_bundle_conflict', currentVersion: null, attemptedVersion: 2 });
  });
});

integrationTest('a malformed (non-canonical) bundle is rejected as 400, never stored', async () => {
  await withApp(async (app, pool) => {
    const { accountId, accessToken } = await createSession(pool);
    const malformed = encodeB64(Buffer.from('{"format":"c04-account-bundle/1"}', 'utf8'));
    const response = await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle: malformed, version: 1 }
    });
    assert.equal(response.statusCode, 400);
    const getResponse = await app.inject({
      method: 'GET',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.equal(getResponse.statusCode, 404);
  });
});

integrationTest("a bundle whose accountId field doesn't match the session is rejected as 400", async () => {
  await withApp(async (app, pool) => {
    const { accessToken } = await createSession(pool);
    const response = await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle: bundleWireValue('some-other-account'), version: 1 }
    });
    assert.equal(response.statusCode, 400);
  });
});

integrationTest('an oversized wrapped-key field is rejected as 400', async () => {
  await withApp(async (app, pool) => {
    const { accountId, accessToken } = await createSession(pool);
    const oversized = bundleWireValue(accountId, { wrappedItemKey: encodeB64(Buffer.alloc(64 * 1024 + 1, 1)) });
    const response = await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle: oversized, version: 1 }
    });
    assert.equal(response.statusCode, 400);
  });
});

integrationTest('account isolation: one account can never read or overwrite another account\'s bundle', async () => {
  await withApp(async (app, pool) => {
    const a = await createSession(pool);
    const b = await createSession(pool);
    await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${a.accessToken}` },
      payload: { bundle: bundleWireValue(a.accountId), version: 1 }
    });

    const getAsB = await app.inject({
      method: 'GET',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${b.accessToken}` }
    });
    assert.equal(getAsB.statusCode, 404);

    // Even a bundle whose internal accountId field impersonates A is
    // rejected: publication ownership is derived from B's session, and B's
    // own bundle (accountId=B) doesn't match — a hostile client cannot get
    // this route to accept a foreign accountId either.
    const putAsB = await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${b.accessToken}` },
      payload: { bundle: bundleWireValue(a.accountId), version: 1 }
    });
    assert.equal(putAsB.statusCode, 400);
  });
});

integrationTest('no request or response ever carries key material outside the opaque b64 field', async () => {
  await withApp(async (app, pool) => {
    const { accountId, accessToken } = await createSession(pool);
    const bundle = bundleWireValue(accountId);
    const response = await app.inject({
      method: 'PUT',
      url: '/account/key-bundle',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { bundle, version: 1 }
    });
    assert.equal(response.statusCode, 204);
    assert.equal(response.body, ''); // empty body: no key material echoed back
  });
});
