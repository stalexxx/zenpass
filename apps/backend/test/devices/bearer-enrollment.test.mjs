// ADR-0011 G2: bearer-authenticated, revocable device enrollment without
// proof-of-possession. Legacy publicKey enrollment is already covered by
// apps/backend/test/auth/http.test.mjs; this file is scoped to the new
// disjoint `enrollmentMode:"bearer-session-v1"` branch and its interaction
// with the legacy branch.
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
  const app = buildApp(config, { pool });
  try {
    await fn(app, pool);
  } finally {
    await app.close();
  }
}

async function createSession(pool, ttlSeconds = config.sessionTtlSeconds) {
  const accountId = `acct-${randomUUID()}`;
  await pool.query('INSERT INTO accounts (account_id) VALUES ($1)', [accountId]);
  const session = await issueSession(pool, accountId, ttlSeconds);
  return { accountId, accessToken: session.accessToken };
}

integrationTest('a fresh device-unbound session can enroll via bearer-session-v1', async () => {
  await withApp(async (app) => {
    const { accessToken } = await createSession(app.db);
    const response = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { name: 'Extension', enrollmentMode: 'bearer-session-v1' }
    });
    assert.equal(response.statusCode, 201);
    const device = response.json();
    assert.equal(device.name, 'Extension');
    assert.ok(device.deviceId);
    assert.equal('publicKey' in device, false); // Device response never carries key material
  });
});

integrationTest('an already-bound session cannot rebind via bearer-session-v1', async () => {
  await withApp(async (app) => {
    const { accessToken } = await createSession(app.db);
    const first = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { name: 'Device A', enrollmentMode: 'bearer-session-v1' }
    });
    assert.equal(first.statusCode, 201);

    const second = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { name: 'Device B', enrollmentMode: 'bearer-session-v1' }
    });
    assert.equal(second.statusCode, 400); // generic 400, not a distinguishing "already bound" detail
  });
});

integrationTest('an already-bound session (via the legacy branch) also cannot enroll via bearer-session-v1', async () => {
  await withApp(async (app) => {
    const { accessToken } = await createSession(app.db);
    const legacy = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { name: 'Laptop', publicKey: encodeB64(Buffer.from('device-public-key')) }
    });
    assert.equal(legacy.statusCode, 201);

    const bearer = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { name: 'Extension', enrollmentMode: 'bearer-session-v1' }
    });
    assert.equal(bearer.statusCode, 400);
  });
});

integrationTest('concurrent bearer-session-v1 enrollment attempts on the same session: exactly one wins', async () => {
  await withApp(async (app) => {
    const { accessToken } = await createSession(app.db);
    const [a, b] = await Promise.all([
      app.inject({
        method: 'POST',
        url: '/devices',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'Race A', enrollmentMode: 'bearer-session-v1' }
      }),
      app.inject({
        method: 'POST',
        url: '/devices',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'Race B', enrollmentMode: 'bearer-session-v1' }
      })
    ]);
    const statuses = [a.statusCode, b.statusCode].sort();
    assert.deepEqual(statuses, [201, 400]);

    const list = await app.inject({
      method: 'GET',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.equal(list.json().devices.length, 1);
  });
});

integrationTest('an anonymous (missing bearer) enrollment attempt is 401', async () => {
  await withApp(async (app) => {
    const response = await app.inject({
      method: 'POST',
      url: '/devices',
      payload: { name: 'Extension', enrollmentMode: 'bearer-session-v1' }
    });
    assert.equal(response.statusCode, 401);
  });
});

integrationTest('a session issued via /auth/refresh is never eligible for bearer-session-v1, even if somehow device-unbound', async () => {
  await withApp(async (app) => {
    // ADR-0011 G2 requires "a valid, device-unbound, freshly OPAQUE-issued
    // session." Every session /auth/refresh can actually produce today is
    // already device-bound (ADR-0005 §2 refuses to refresh an unbound
    // session), so this scenario cannot occur through any current HTTP
    // path. This test exercises the durable `issued_via` provenance check
    // itself — inserting a row directly, as a future/buggy issuance path
    // might — to prove enrollment is rejected on provenance, not merely
    // reconstructing today's accidental invariant from device_id.
    const accountId = `acct-${randomUUID()}`;
    await app.db.query('INSERT INTO accounts (account_id) VALUES ($1)', [accountId]);
    const { issueSession } = await import('../../src/auth/sessions.mjs');
    const session = await issueSession(app.db, accountId, config.sessionTtlSeconds, 'refresh');

    const response = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${session.accessToken}` },
      payload: { name: 'Extension', enrollmentMode: 'bearer-session-v1' }
    });
    assert.equal(response.statusCode, 400); // generic 400, same as any other ineligible-session case

    const devices = await app.db.query('SELECT count(*)::int AS count FROM devices WHERE account_id = $1', [
      accountId
    ]);
    assert.equal(devices.rows[0].count, 0); // no device was created on the rejected attempt
  });
});

integrationTest('an expired session cannot enroll', async () => {
  await withApp(async (app) => {
    const { accessToken } = await createSession(app.db, -1);
    const response = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { name: 'Extension', enrollmentMode: 'bearer-session-v1' }
    });
    assert.equal(response.statusCode, 401); // resolveSession already rejects expired tokens
  });
});

integrationTest('a revoked device (bearer-session-v1) cascades to revoke its session, per existing ADR-0005 behavior', async () => {
  await withApp(async (app) => {
    const { accessToken } = await createSession(app.db);
    const enroll = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { name: 'Extension', enrollmentMode: 'bearer-session-v1' }
    });
    const device = enroll.json();

    const revoke = await app.inject({
      method: 'POST',
      url: `/devices/${device.deviceId}/revoke`,
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.equal(revoke.statusCode, 204);

    const useAfterRevoke = await app.inject({
      method: 'GET',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.equal(useAfterRevoke.statusCode, 401);
  });
});

integrationTest('a second, independent login can enroll a new device after the first was revoked', async () => {
  await withApp(async (app) => {
    const accountId = `acct-${randomUUID()}`;
    await app.db.query('INSERT INTO accounts (account_id) VALUES ($1)', [accountId]);
    const first = await issueSession(app.db, accountId, config.sessionTtlSeconds);
    const enroll = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${first.accessToken}` },
      payload: { name: 'Extension', enrollmentMode: 'bearer-session-v1' }
    });
    const device = enroll.json();
    await app.inject({
      method: 'POST',
      url: `/devices/${device.deviceId}/revoke`,
      headers: { authorization: `Bearer ${first.accessToken}` }
    });

    // A fresh, independent login (new device-unbound session) can enroll
    // again — revocation is not a permanent ban on the account.
    const second = await issueSession(app.db, accountId, config.sessionTtlSeconds);
    const reEnroll = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${second.accessToken}` },
      payload: { name: 'Extension (re-enrolled)', enrollmentMode: 'bearer-session-v1' }
    });
    assert.equal(reEnroll.statusCode, 201);
  });
});

integrationTest('mixed publicKey + enrollmentMode payload is rejected as 400', async () => {
  await withApp(async (app) => {
    const { accessToken } = await createSession(app.db);
    const response = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        name: 'Confused',
        publicKey: encodeB64(Buffer.from('key')),
        enrollmentMode: 'bearer-session-v1'
      }
    });
    assert.equal(response.statusCode, 400);
  });
});

integrationTest('an unknown enrollmentMode value is rejected as 400', async () => {
  await withApp(async (app) => {
    const { accessToken } = await createSession(app.db);
    const response = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { name: 'Extension', enrollmentMode: 'future-mode-v2' }
    });
    assert.equal(response.statusCode, 400);
  });
});

integrationTest('a payload with neither publicKey nor enrollmentMode is rejected as 400', async () => {
  await withApp(async (app) => {
    const { accessToken } = await createSession(app.db);
    const response = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { name: 'Extension' }
    });
    assert.equal(response.statusCode, 400);
  });
});
