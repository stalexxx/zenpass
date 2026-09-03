import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { buildApp } from '../src/app.mjs';

const config = Object.freeze({
  logLevel: 'silent',
  requestIdHeader: 'x-request-id'
});

test('liveness is independent of the database and readiness verifies it', async () => {
  const healthyPool = {
    query: async (sql) => {
      assert.equal(sql, 'SELECT 1');
      return { rows: [{ '?column?': 1 }] };
    },
    end: async () => {}
  };
  const readyApp = buildApp(config, { pool: healthyPool });
  try {
    const live = await readyApp.inject({ method: 'GET', url: '/health/live' });
    assert.equal(live.statusCode, 200);
    assert.deepEqual(live.json(), { status: 'ok' });

    const ready = await readyApp.inject({ method: 'GET', url: '/health/ready' });
    assert.equal(ready.statusCode, 200);
    assert.deepEqual(ready.json(), { status: 'ok' });

    const unavailablePool = {
      query: async () => { throw new Error('database unavailable'); },
      end: async () => {}
    };
    const unavailableApp = buildApp(config, { pool: unavailablePool });
    try {
      const unavailable = await unavailableApp.inject({ method: 'GET', url: '/health/ready' });
      assert.equal(unavailable.statusCode, 503);
      assert.deepEqual(unavailable.json(), { status: 'not_ready' });
    } finally {
      await unavailableApp.close();
    }
  } finally {
    await readyApp.close();
  }
});
