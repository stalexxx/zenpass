import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { buildApp } from '../../src/app.mjs';
import { createPool } from '../../src/db.mjs';
import { createAuthContext } from '../../src/auth/init.mjs';
import { encodeB64, decodeB64 } from '../../src/auth/codec.mjs';
import init, {
  client_login_finish,
  client_login_start,
  client_registration_finish,
  client_registration_start
} from '../../../../packages/crypto-server/pkg/crypto_server.js';

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
    authRateLimitMax: 3,
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

async function register(app, accountId, password = PASSWORD) {
  const start = client_registration_start(password);
  const stepA = await app.inject({
    method: 'POST',
    url: '/auth/opaque/register',
    payload: { accountId, clientMessage: encodeB64(start.message) }
  });
  assert.equal(stepA.statusCode, 201);
  const responseMessage = decodeB64(stepA.json().message);
  const finish = client_registration_finish(start.state, password, responseMessage);
  const stepB = await app.inject({
    method: 'POST',
    url: '/auth/opaque/register',
    payload: { accountId, clientMessage: encodeB64(finish.message) }
  });
  assert.equal(stepB.statusCode, 201);
}

async function login(app, accountId, password = PASSWORD) {
  const start = client_login_start(password);
  const ke2Response = await app.inject({
    method: 'POST',
    url: '/auth/opaque/login',
    payload: { accountId, clientMessage: encodeB64(start.message) }
  });
  const ke2Message = decodeB64(ke2Response.json().message);
  const finish = client_login_finish(start.state, password, ke2Message, new TextEncoder().encode('zkpm-opaque-v1'));
  const sessionResponse = await app.inject({
    method: 'POST',
    url: '/auth/opaque/login',
    payload: { accountId, clientMessage: encodeB64(finish.message) }
  });
  return sessionResponse;
}

integrationTest('registration then login issues a Session per ADR-0005', async () => {
  const accountId = `acct-${randomUUID()}`;
  await withApp(async (app) => {
    await register(app, accountId);
    const sessionResponse = await login(app, accountId);
    assert.equal(sessionResponse.statusCode, 200);
    const body = sessionResponse.json();
    assert.ok(body.accessToken);
    assert.ok(body.expiresAt);
  });
});

integrationTest('wrong password never authenticates', async () => {
  const accountId = `acct-${randomUUID()}`;
  await withApp(async (app) => {
    await register(app, accountId);
    const start = client_login_start(new TextEncoder().encode('WrongHorseBatteryStaple'));
    const ke2Response = await app.inject({
      method: 'POST',
      url: '/auth/opaque/login',
      payload: { accountId, clientMessage: encodeB64(start.message) }
    });
    assert.equal(ke2Response.statusCode, 200); // still shaped like a continuation
    const ke2Message = decodeB64(ke2Response.json().message);
    assert.throws(() =>
      client_login_finish(
        start.state,
        new TextEncoder().encode('WrongHorseBatteryStaple'),
        ke2Message,
        new TextEncoder().encode('zkpm-opaque-v1')
      )
    );
  });
});

integrationTest('an unknown account gets a same-shaped decoy login continuation, then generic rejection', async () => {
  const accountId = `acct-unknown-${randomUUID()}`;
  await withApp(async (app) => {
    const start = client_login_start(PASSWORD);
    const ke2Response = await app.inject({
      method: 'POST',
      url: '/auth/opaque/login',
      payload: { accountId, clientMessage: encodeB64(start.message) }
    });
    assert.equal(ke2Response.statusCode, 200);
    assert.ok(decodeB64(ke2Response.json().message).length > 0);

    const finishResponse = await app.inject({
      method: 'POST',
      url: '/auth/opaque/login',
      payload: { accountId, clientMessage: encodeB64(Buffer.alloc(64)) }
    });
    assert.equal(finishResponse.statusCode, 401);
  });
});

integrationTest('device registration binds the session; refresh rotates a device-bound session', async () => {
  const accountId = `acct-${randomUUID()}`;
  await withApp(async (app) => {
    await register(app, accountId);
    const sessionResponse = await login(app, accountId);
    const { accessToken } = sessionResponse.json();

    const refreshBeforeDevice = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.equal(refreshBeforeDevice.statusCode, 401); // not yet device-bound (ADR-0005 §2)

    const deviceResponse = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { name: 'Test device', publicKey: encodeB64(Buffer.from('device-public-key')) }
    });
    assert.equal(deviceResponse.statusCode, 201);
    const device = deviceResponse.json();

    const refreshed = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.equal(refreshed.statusCode, 200);
    const newToken = refreshed.json().accessToken;
    assert.notEqual(newToken, accessToken);

    const oldTokenReuse = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.equal(oldTokenReuse.statusCode, 401); // rotation revokes the prior token

    const revokeResponse = await app.inject({
      method: 'POST',
      url: `/devices/${device.deviceId}/revoke`,
      headers: { authorization: `Bearer ${newToken}` }
    });
    assert.equal(revokeResponse.statusCode, 204);

    const useAfterRevoke = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { authorization: `Bearer ${newToken}` }
    });
    assert.equal(useAfterRevoke.statusCode, 401); // device revoke cascades to sessions
  });
});

integrationTest('logout revokes the session', async () => {
  const accountId = `acct-${randomUUID()}`;
  await withApp(async (app) => {
    await register(app, accountId);
    const { accessToken } = (await login(app, accountId)).json();
    const logoutResponse = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.equal(logoutResponse.statusCode, 204);

    const listAfterLogout = await app.inject({
      method: 'GET',
      url: '/devices',
      headers: { authorization: `Bearer ${accessToken}` }
    });
    assert.equal(listAfterLogout.statusCode, 401);
  });
});

integrationTest('login is durably rate limited per account', async () => {
  const accountId = `acct-${randomUUID()}`;
  await withApp(
    async (app) => {
      for (let i = 0; i < 3; i += 1) {
        const response = await app.inject({
          method: 'POST',
          url: '/auth/opaque/login',
          payload: { accountId, clientMessage: encodeB64(Buffer.alloc(96)) }
        });
        assert.notEqual(response.statusCode, 500);
      }
      const throttled = await app.inject({
        method: 'POST',
        url: '/auth/opaque/login',
        payload: { accountId, clientMessage: encodeB64(Buffer.alloc(96)) }
      });
      assert.equal(throttled.statusCode, 401);
    },
    { authRateLimitMax: 3 }
  );
});
