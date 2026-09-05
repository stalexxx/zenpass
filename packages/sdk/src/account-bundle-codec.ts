// ADR-0011 G1: client-side canonical codec for the `AccountBundle` JSON
// object carried opaquely inside `KeyBundle.bundle`. Mirrors
// apps/backend/src/account/bundle-codec.mjs field-for-field; any
// divergence between the two is itself a bug this file's tests + the
// backend's own tests are meant to catch via matching fixtures, not a
// shared implementation (the two run in different languages/runtimes by
// design — the server never runs this "client" codec).
import { decodeB64, encodeB64 } from "./b64.ts";

export const ACCOUNT_BUNDLE_FORMAT = "c04-account-bundle/1";

export const ACCOUNT_BUNDLE_FIELDS = [
  "format",
  "accountId",
  "vaultId",
  "itemId",
  "kdfParametersCbor",
  "wrappedAccountKey",
  "wrappedVaultKey",
  "wrappedItemKey",
  "wrappedRecoveryKey",
] as const;

export interface AccountBundleFields {
  format: string;
  accountId: string;
  vaultId: string;
  itemId: string;
  kdfParametersCbor: string;
  wrappedAccountKey: string;
  wrappedVaultKey: string;
  wrappedItemKey: string;
  wrappedRecoveryKey: string;
}

/** The decrypted-shape inputs a caller actually has: raw bytes, not
 * pre-encoded `b64:` strings. `buildAccountBundle` does the encoding. */
export interface AccountBundleBytes {
  accountId: string;
  vaultId: string;
  itemId: string;
  kdfParametersCbor: Uint8Array;
  wrappedAccountKey: Uint8Array;
  wrappedVaultKey: Uint8Array;
  wrappedItemKey: Uint8Array;
  wrappedRecoveryKey: Uint8Array;
}

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const B64_PATTERN = /^b64:[A-Za-z0-9+/]+={0,2}$/;

export const MAX_OUTER_BYTES = 512 * 1024;
export const MAX_WRAPPER_BYTES = 64 * 1024;
export const MAX_KDF_PARAMS_BYTES = 512;

/** Builds the canonical `KeyBundle.bundle` wire value (a `b64:`-prefixed
 * string) from raw wrapped bytes, in the fixed ADR-0011 G1 field order. */
export function buildAccountBundle(fields: AccountBundleBytes): string {
  const ordered: AccountBundleFields = {
    format: ACCOUNT_BUNDLE_FORMAT,
    accountId: fields.accountId,
    vaultId: fields.vaultId,
    itemId: fields.itemId,
    kdfParametersCbor: encodeB64(fields.kdfParametersCbor),
    wrappedAccountKey: encodeB64(fields.wrappedAccountKey),
    wrappedVaultKey: encodeB64(fields.wrappedVaultKey),
    wrappedItemKey: encodeB64(fields.wrappedItemKey),
    wrappedRecoveryKey: encodeB64(fields.wrappedRecoveryKey),
  };
  const json = JSON.stringify(ordered);
  const bytes = new TextEncoder().encode(json);
  return encodeB64(bytes);
}

/**
 * Parses and validates a `KeyBundle.bundle` wire value. Returns the
 * decoded fields (still `b64:`-encoded byte-strings; callers unwrap them
 * with the existing Rust/WASM wrapper-opening calls) on success, or `null`
 * for anything malformed, oversized, or non-canonical. Never throws on
 * attacker- or server-controlled input.
 */
export function parseAccountBundle(bundleWireValue: string): AccountBundleFields | null {
  if (typeof bundleWireValue !== "string" || !B64_PATTERN.test(bundleWireValue)) return null;

  let outerBytes: Uint8Array;
  try {
    outerBytes = decodeB64(bundleWireValue);
  } catch {
    return null;
  }
  if (outerBytes.length === 0 || outerBytes.length > MAX_OUTER_BYTES) return null;

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(outerBytes);
  } catch {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const record = parsed as Record<string, unknown>;

  const keys = Object.keys(record);
  if (keys.length !== ACCOUNT_BUNDLE_FIELDS.length) return null;
  for (const field of ACCOUNT_BUNDLE_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(record, field)) return null;
    if (typeof record[field] !== "string") return null;
  }

  if (record.format !== ACCOUNT_BUNDLE_FORMAT) return null;
  if (!ID_PATTERN.test(record.accountId as string)) return null;
  if (!ID_PATTERN.test(record.vaultId as string)) return null;
  if (!ID_PATTERN.test(record.itemId as string)) return null;

  const kdf = record.kdfParametersCbor as string;
  if (!B64_PATTERN.test(kdf)) return null;
  const kdfBytes = safeDecode(kdf);
  if (!kdfBytes || kdfBytes.length === 0 || kdfBytes.length > MAX_KDF_PARAMS_BYTES) return null;

  for (const field of ["wrappedAccountKey", "wrappedVaultKey", "wrappedItemKey", "wrappedRecoveryKey"] as const) {
    const value = record[field] as string;
    if (!B64_PATTERN.test(value)) return null;
    const bytes = safeDecode(value);
    if (!bytes || bytes.length === 0 || bytes.length > MAX_WRAPPER_BYTES) return null;
  }

  // Canonical reproduction: reject reordered/duplicate/unknown keys and
  // non-canonical escapes/whitespace by requiring an exact byte match
  // against a freshly serialized fixed-order copy, rather than trusting
  // any "normalized" reading of hostile input.
  const canonical: Record<string, string> = {};
  for (const field of ACCOUNT_BUNDLE_FIELDS) canonical[field] = record[field] as string;
  const canonicalBytes = new TextEncoder().encode(JSON.stringify(canonical));
  if (!bytesEqual(canonicalBytes, outerBytes)) return null;

  return record as unknown as AccountBundleFields;
}

function safeDecode(value: string): Uint8Array | null {
  try {
    return decodeB64(value);
  } catch {
    return null;
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}
