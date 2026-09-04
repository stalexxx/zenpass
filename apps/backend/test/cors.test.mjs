import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { buildApp } from '../src/app.mjs';

const localOrigin = 'http://127.0.0.1:4173';
const localhostOrigin = 'http://localhost:4173';
const tauriOrigin = 'tauri://localhost';
const config = Object.freeze({
  nodeEnv: 'development', logLevel: 'silent', requestIdHeader: 'x-request-id', webOrigins: [localOrigin, localhostOrigin, tauriOrigin],
  opaqueServerSetup: null, sessionTtlSeconds: 900, authRateLimitMax: 10, authRateLimitWindowSeconds: 300,
});

function app() {
  return buildApp(config, { pool: { query: async () => ({ rows: [{ '?column?': 1 }] }), end: async () => {} } });
}

test('local web origin receives a narrow CORS response and preflight', async () => {
  const server = app();
  try {
    const response = await server.inject({ method: 'GET', url: '/health/live', headers: { origin: localOrigin } });
    assert.equal(response.headers['access-control-allow-origin'], localOrigin);
    assert.equal(response.headers.vary, 'Origin');
    assert.equal(response.headers['access-control-allow-credentials'], undefined);
    const preflight = await server.inject({ method: 'OPTIONS', url: '/auth/opaque/login', headers: { origin: localOrigin } });
    assert.equal(preflight.statusCode, 204);
    assert.equal(preflight.headers['access-control-allow-headers'], 'Authorization, Content-Type');
  } finally { await server.close(); }
});

test('untrusted origins do not receive CORS permission', async () => {
  const server = app();
  try {
    const response = await server.inject({ method: 'GET', url: '/health/live', headers: { origin: 'https://attacker.invalid' } });
    assert.equal(response.headers['access-control-allow-origin'], undefined);
  } finally { await server.close(); }
});

test('localhost development alias is allowed without opening any other origin', async () => {
  const server = app();
  try {
    const response = await server.inject({ method: 'GET', url: '/health/live', headers: { origin: localhostOrigin } });
    assert.equal(response.headers['access-control-allow-origin'], localhostOrigin);
  } finally { await server.close(); }
});

test('Tauri local WebView receives the same narrow CORS permission', async () => {
  const server = app();
  try {
    const response = await server.inject({ method: 'GET', url: '/health/live', headers: { origin: tauriOrigin } });
    assert.equal(response.headers['access-control-allow-origin'], tauriOrigin);
  } finally { await server.close(); }
});
