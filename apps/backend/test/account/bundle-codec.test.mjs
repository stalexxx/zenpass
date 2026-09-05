import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { encodeB64 } from '../../src/auth/codec.mjs';
import {
  ACCOUNT_BUNDLE_FIELDS,
  ACCOUNT_BUNDLE_FORMAT,
  MAX_KDF_PARAMS_BYTES,
  MAX_OUTER_BYTES,
  MAX_WRAPPER_BYTES,
  validateAccountBundleBytes
} from '../../src/account/bundle-codec.mjs';

function validFields(overrides = {}) {
  return {
    format: ACCOUNT_BUNDLE_FORMAT,
    accountId: 'acct-01',
    vaultId: 'vault-01',
    itemId: 'item-01',
    kdfParametersCbor: encodeB64(Buffer.from('kdf-params')),
    wrappedAccountKey: encodeB64(Buffer.from('wrapped-account-key')),
    wrappedVaultKey: encodeB64(Buffer.from('wrapped-vault-key')),
    wrappedItemKey: encodeB64(Buffer.from('wrapped-item-key')),
    wrappedRecoveryKey: encodeB64(Buffer.from('wrapped-recovery-key')),
    ...overrides
  };
}

/** Canonical bytes: field order fixed, ordinary JSON.stringify. */
function canonicalBytes(fields = validFields()) {
  const ordered = {};
  for (const key of ACCOUNT_BUNDLE_FIELDS) ordered[key] = fields[key];
  return Buffer.from(JSON.stringify(ordered), 'utf8');
}

test('accepts a canonical valid bundle and returns its ids', () => {
  const result = validateAccountBundleBytes(canonicalBytes());
  assert.deepEqual(result, { accountId: 'acct-01', vaultId: 'vault-01', itemId: 'item-01' });
});

test('rejects an unrecognized format', () => {
  assert.equal(validateAccountBundleBytes(canonicalBytes(validFields({ format: 'other/1' }))), null);
});

test('rejects reordered keys (non-canonical serialization)', () => {
  const fields = validFields();
  const reordered = { ...fields };
  const bytes = Buffer.from(
    JSON.stringify({ accountId: reordered.accountId, format: reordered.format, ...reordered }),
    'utf8'
  );
  assert.equal(validateAccountBundleBytes(bytes), null);
});

test('rejects duplicate keys even though JSON.parse would silently collapse them', () => {
  const fields = validFields();
  // Hand-construct raw JSON text with a duplicated "format" key: valid
  // JSON syntax, but its canonical reproduction (one "format" key) can
  // never byte-match this input.
  const raw =
    `{"format":"${fields.format}","format":"${fields.format}","accountId":"${fields.accountId}",` +
    `"vaultId":"${fields.vaultId}","itemId":"${fields.itemId}",` +
    `"kdfParametersCbor":"${fields.kdfParametersCbor}",` +
    `"wrappedAccountKey":"${fields.wrappedAccountKey}","wrappedVaultKey":"${fields.wrappedVaultKey}",` +
    `"wrappedItemKey":"${fields.wrappedItemKey}","wrappedRecoveryKey":"${fields.wrappedRecoveryKey}"}`;
  assert.equal(validateAccountBundleBytes(Buffer.from(raw, 'utf8')), null);
});

test('rejects an unknown extra field', () => {
  const bytes = Buffer.from(JSON.stringify({ ...validFields(), extra: 'nope' }), 'utf8');
  assert.equal(validateAccountBundleBytes(bytes), null);
});

test('rejects a missing field', () => {
  const fields = validFields();
  delete fields.wrappedRecoveryKey;
  const bytes = Buffer.from(JSON.stringify(fields), 'utf8');
  assert.equal(validateAccountBundleBytes(bytes), null);
});

test('rejects malformed IDs', () => {
  assert.equal(validateAccountBundleBytes(canonicalBytes(validFields({ accountId: '' }))), null);
  assert.equal(validateAccountBundleBytes(canonicalBytes(validFields({ vaultId: 'has a space' }))), null);
});

test('rejects a non-b64-prefixed wrapper', () => {
  assert.equal(
    validateAccountBundleBytes(canonicalBytes(validFields({ wrappedItemKey: 'not-b64-prefixed' }))),
    null
  );
});

test('rejects an empty (zero-length) wrapper', () => {
  assert.equal(validateAccountBundleBytes(canonicalBytes(validFields({ wrappedItemKey: 'b64:' }))), null);
});

test('rejects a wrapper exceeding the 64 KiB cap', () => {
  const oversized = encodeB64(Buffer.alloc(MAX_WRAPPER_BYTES + 1, 1));
  assert.equal(validateAccountBundleBytes(canonicalBytes(validFields({ wrappedItemKey: oversized }))), null);
});

test('accepts a wrapper at exactly the 64 KiB cap', () => {
  const atCap = encodeB64(Buffer.alloc(MAX_WRAPPER_BYTES, 1));
  const result = validateAccountBundleBytes(canonicalBytes(validFields({ wrappedItemKey: atCap })));
  assert.notEqual(result, null);
});

test('rejects KDF params exceeding the 512-byte cap', () => {
  const oversized = encodeB64(Buffer.alloc(MAX_KDF_PARAMS_BYTES + 1, 1));
  assert.equal(validateAccountBundleBytes(canonicalBytes(validFields({ kdfParametersCbor: oversized }))), null);
});

test('rejects an outer record exceeding the 512 KiB cap', () => {
  const oversized = encodeB64(Buffer.alloc(MAX_OUTER_BYTES, 1));
  assert.equal(validateAccountBundleBytes(canonicalBytes(validFields({ wrappedItemKey: oversized }))), null);
});

test('rejects non-string field values', () => {
  const fields = validFields();
  fields.itemId = 123;
  assert.equal(validateAccountBundleBytes(Buffer.from(JSON.stringify(fields), 'utf8')), null);
});

test('rejects malformed JSON', () => {
  assert.equal(validateAccountBundleBytes(Buffer.from('{not json', 'utf8')), null);
});

test('rejects an empty buffer', () => {
  assert.equal(validateAccountBundleBytes(Buffer.alloc(0)), null);
});

test('never throws on adversarial input', () => {
  const adversarial = [
    Buffer.from('null', 'utf8'),
    Buffer.from('[]', 'utf8'),
    Buffer.from('"a string"', 'utf8'),
    Buffer.from('42', 'utf8'),
    Buffer.alloc(10, 0xff)
  ];
  for (const input of adversarial) {
    assert.doesNotThrow(() => validateAccountBundleBytes(input));
  }
});
