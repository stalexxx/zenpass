// ADR-0011 G1: canonical validation for the `AccountBundle` JSON object
// carried opaquely inside `KeyBundle.bundle` (a `b64:`-prefixed transport
// framing around C01's existing AEAD-wrapped bytes — never a new crypto
// envelope, never plaintext). This module only checks shape, size, and
// exact canonical byte reproduction; it never inspects or decrypts wrapper
// contents.
import { decodeB64 } from '../auth/codec.mjs';

export const ACCOUNT_BUNDLE_FORMAT = 'c04-account-bundle/1';

// Fixed key order per ADR-0011 G1. Canonical serialization reproduces
// exactly this order with ordinary `JSON.stringify` string encoding, then
// the caller byte-compares the result against the received record —
// rejecting duplicate/reordered/unknown keys, non-canonical escapes, and
// non-canonical base64 without a separate normalization step.
export const ACCOUNT_BUNDLE_FIELDS = Object.freeze([
  'format',
  'accountId',
  'vaultId',
  'itemId',
  'kdfParametersCbor',
  'wrappedAccountKey',
  'wrappedVaultKey',
  'wrappedItemKey',
  'wrappedRecoveryKey'
]);

const WRAPPER_FIELDS = Object.freeze([
  'wrappedAccountKey',
  'wrappedVaultKey',
  'wrappedItemKey',
  'wrappedRecoveryKey'
]);

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const B64_PATTERN = /^b64:[A-Za-z0-9+/]+={0,2}$/;

export const MAX_OUTER_BYTES = 512 * 1024;
export const MAX_WRAPPER_BYTES = 64 * 1024;
export const MAX_KDF_PARAMS_BYTES = 512;

/**
 * Validates `outerBytes` (the raw bytes obtained by decoding a
 * `KeyBundle.bundle` string's `b64:` prefix) as a canonical
 * `c04-account-bundle/1` record.
 *
 * Returns `{ accountId, vaultId, itemId }` on success, or `null` for any
 * malformed, oversized, non-canonical, or unrecognized-format input. Never
 * throws on attacker-controlled input.
 */
export function validateAccountBundleBytes(outerBytes) {
  if (!Buffer.isBuffer(outerBytes) || outerBytes.length === 0 || outerBytes.length > MAX_OUTER_BYTES) return null;

  let text;
  try {
    text = outerBytes.toString('utf8');
  } catch {
    return null;
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;

  const keys = Object.keys(parsed);
  if (keys.length !== ACCOUNT_BUNDLE_FIELDS.length) return null;
  for (const field of ACCOUNT_BUNDLE_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(parsed, field)) return null;
    if (typeof parsed[field] !== 'string') return null;
  }

  if (parsed.format !== ACCOUNT_BUNDLE_FORMAT) return null;
  if (!ID_PATTERN.test(parsed.accountId)) return null;
  if (!ID_PATTERN.test(parsed.vaultId)) return null;
  if (!ID_PATTERN.test(parsed.itemId)) return null;

  if (!B64_PATTERN.test(parsed.kdfParametersCbor)) return null;
  const kdfBytes = decodeB64(parsed.kdfParametersCbor);
  if (!kdfBytes || kdfBytes.length === 0 || kdfBytes.length > MAX_KDF_PARAMS_BYTES) return null;

  for (const field of WRAPPER_FIELDS) {
    if (!B64_PATTERN.test(parsed[field])) return null;
    const bytes = decodeB64(parsed[field]);
    if (!bytes || bytes.length === 0 || bytes.length > MAX_WRAPPER_BYTES) return null;
  }

  // Canonical reproduction: build a plain object in the fixed field order
  // (object insertion order controls `JSON.stringify` key order for
  // string keys) and require an exact byte match against what was
  // received. This single check rejects reordered/duplicate keys (a
  // duplicate collapses to one value under `JSON.parse`, which then fails
  // to reproduce the original bytes), non-canonical base64 padding
  // variants, and stray whitespace, without a bespoke check for each.
  const canonical = {};
  for (const field of ACCOUNT_BUNDLE_FIELDS) canonical[field] = parsed[field];
  const canonicalBytes = Buffer.from(JSON.stringify(canonical), 'utf8');
  if (Buffer.compare(canonicalBytes, outerBytes) !== 0) return null;

  return { accountId: parsed.accountId, vaultId: parsed.vaultId, itemId: parsed.itemId };
}
