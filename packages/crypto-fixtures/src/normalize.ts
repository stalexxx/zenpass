import { createHash } from "node:crypto";

/**
 * Normalized fixture records and digests.
 *
 * A fixture's *normalized record* is the full parsed JSON document with every
 * `provenance.normalizedRecordSha256` field removed (wherever it appears),
 * serialized with recursively sorted object keys and no insignificant
 * whitespace. The provenance digest embedded in the fixture and recorded in
 * the manifest is the lowercase hex SHA-256 of the UTF-8 encoding of that
 * string.
 */

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`).join(",")}}`;
}

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export function cloneWithoutDigest(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(cloneWithoutDigest);
  if (value !== null && typeof value === "object") {
    const out: { [key: string]: JsonValue } = {};
    for (const [key, child] of Object.entries(value)) out[key] = cloneWithoutDigest(child);
    if (
      (value as { [key: string]: JsonValue }).provenance !== null &&
      typeof (value as { [key: string]: JsonValue }).provenance === "object" &&
      !Array.isArray((value as { [key: string]: JsonValue }).provenance)
    ) {
      delete (out as { [key: string]: JsonValue }).provenance.normalizedRecordSha256;
    }
    return out;
  }
  return value;
}

export function normalizedRecordString(fixture: JsonValue): string {
  return stableStringify(cloneWithoutDigest(fixture));
}

export function sha256Hex(input: string | Uint8Array): string {
  const hash = createHash("sha256");
  hash.update(input);
  return hash.digest("hex");
}

export function normalizedRecordDigest(fixture: JsonValue): string {
  return sha256Hex(normalizedRecordString(fixture));
}

const DIGEST_RE = /^sha256:([0-9a-f]{64})$/;

export function parseDigestField(s: unknown): { ok: true; hex: string } | { ok: false; error: string } {
  if (typeof s !== "string") return { ok: false, error: "digest must be a string" };
  const match = DIGEST_RE.exec(s);
  if (!match) {
    return { ok: false, error: "digest must match 'sha256:<64 lowercase hex chars>'" };
  }
  return { ok: true, hex: match[1] };
}
