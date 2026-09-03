import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { decodeB64, encodeB64 } from '../../src/auth/codec.mjs';

test('encodeB64/decodeB64 round-trip arbitrary bytes', () => {
  const original = Buffer.from([0, 1, 2, 253, 254, 255, 42]);
  const encoded = encodeB64(original);
  assert.match(encoded, /^b64:[A-Za-z0-9+/]+=*$/);
  assert.ok(Buffer.from(decodeB64(encoded)).equals(original));
});

test('decodeB64 rejects values without the b64: prefix', () => {
  assert.equal(decodeB64('aGVsbG8='), null);
  assert.equal(decodeB64(''), null);
  assert.equal(decodeB64(undefined), null);
  assert.equal(decodeB64(42), null);
});

test('decodeB64 rejects an invalid base64 alphabet or length', () => {
  assert.equal(decodeB64('b64:not base64!!'), null);
  assert.equal(decodeB64('b64:abc'), null); // not a multiple of 4
});

test('decodeB64 accepts an empty payload', () => {
  assert.ok(Buffer.from(decodeB64('b64:')).equals(Buffer.alloc(0)));
});
