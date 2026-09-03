import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.mjs';
import { loggerOptions, redactedPaths } from '../src/logger.mjs';

test('config validates and applies safe defaults', () => {
  const cfg = loadConfig({ NODE_ENV: 'test', PORT: '3100', LOG_LEVEL: 'warn' });
  assert.equal(cfg.port, 3100); assert.equal(cfg.databaseUrl, null); assert.equal(cfg.logLevel, 'warn');
});
test('config rejects invalid values', () => {
  assert.throws(() => loadConfig({ NODE_ENV: 'bad' }), /NODE_ENV/);
  assert.throws(() => loadConfig({ NODE_ENV: 'test', PORT: '0' }), /PORT/);
  assert.throws(() => loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'nope' }), /LOG_LEVEL/);
});
test('logger redacts bodies and secret fields', () => {
  const options = loggerOptions();
  assert.ok(options.redact.paths.includes('req.body'));
  assert.ok(redactedPaths.includes('*.ciphertext'));
  assert.ok(redactedPaths.includes('*.masterPassword'));
});
