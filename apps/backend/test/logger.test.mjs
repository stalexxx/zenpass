import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import pino from 'pino';
import { loggerOptions } from '../src/logger.mjs';

test('structured request logs exclude headers, bodies, and opaque values', () => {
  let output = '';
  const sink = new Writable({
    write(chunk, _encoding, callback) {
      output += chunk.toString();
      callback();
    }
  });
  const logger = pino(loggerOptions(), sink);
  logger.info({
    req: {
      id: 'request-id',
      method: 'POST',
      url: '/v1/vaults/example/items',
      headers: { authorization: 'AUTH_HEADER_SENTINEL' },
      body: {
        ciphertext: 'OPAQUE_PAYLOAD_SENTINEL',
        password: 'FORM_FIELD_SENTINEL'
      }
    }
  }, 'request completed');

  assert.match(output, /request-id/);
  assert.match(output, /\/v1\/vaults\/example\/items/);
  assert.doesNotMatch(output, /AUTH_HEADER_SENTINEL/);
  assert.doesNotMatch(output, /OPAQUE_PAYLOAD_SENTINEL/);
  assert.doesNotMatch(output, /FORM_FIELD_SENTINEL/);
});
