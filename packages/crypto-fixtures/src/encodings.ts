/**
 * Byte-field encodings for crypto fixtures.
 *
 * Byte-carrying string fields use the fixture conventions from the contract:
 *   "hex:<lowercase-hex>"  — raw bytes as even-length lowercase hexadecimal
 *   "b64:<standard-base64>" — transport encoding, RFC 4648 with padding
 *
 * Any other `scheme:`-shaped prefix is an unknown encoding and must be
 * rejected. This module only parses and validates encodings; it never
 * interprets or prints byte material.
 */

const SCHEME_RE = /^[A-Za-z][A-Za-z0-9+.\-]*:/;
const HEX_BODY_RE = /^hex:([0-9a-f]*)$/;
const B64_BODY_RE = /^b64:([A-Za-z0-9+/]*={0,2})$/;

export type ByteField =
  | { ok: true; encoding: "hex" | "b64"; bytes: Uint8Array }
  | { ok: false; error: string };

export type SchemeScanResult =
  | { ok: true; fields: { path: string; encoding: "hex" | "b64"; byteLength: number }[] }
  | { ok: false; path: string; error: string };

export function looksLikeScheme(s: string): boolean {
  return SCHEME_RE.test(s);
}

export function parseByteField(s: string): ByteField {
  if (HEX_BODY_RE.test(s)) {
    const body = s.slice(4);
    if (body.length % 2 !== 0) {
      return { ok: false, error: "hex: body must have an even number of digits" };
    }
    const bytes = new Uint8Array(body.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16);
    }
    return { ok: true, encoding: "hex", bytes };
  }
  if (B64_BODY_RE.test(s)) {
    const body = s.slice(4);
    if (body.length % 4 !== 0) {
      return { ok: false, error: "b64: body length must be a multiple of 4 (padded RFC 4648)" };
    }
    const bytes = Buffer.from(body, "base64");
    const reencoded = bytes.toString("base64");
    if (body !== reencoded) {
      return { ok: false, error: "b64: body is not canonical padded standard base64" };
    }
    return { ok: true, encoding: "b64", bytes };
  }
  if (looksLikeScheme(s)) {
    const scheme = s.slice(0, s.indexOf(":"));
    return { ok: false, error: `unknown byte-field encoding prefix '${scheme}:' (expected hex: or b64:)` };
  }
  return { ok: false, error: "value is not a byte field (expected hex: or b64: prefix)" };
}

/** Parse a field that must be a byte field; returns byte length or an error. */
export function byteFieldLength(s: unknown): { ok: true; byteLength: number } | { ok: false; error: string } {
  if (typeof s !== "string") return { ok: false, error: "expected a byte-field string" };
  const parsed = parseByteField(s);
  if (!parsed.ok) return parsed;
  return { ok: true, byteLength: parsed.bytes.length };
}

/**
 * Walk every string in a parsed JSON document. All `scheme:`-shaped strings
 * must be valid `hex:`/`b64:` byte fields; any other scheme prefix is an
 * unknown encoding and fails.
 */
export function scanByteFields(root: unknown): SchemeScanResult {
  const fields: { path: string; encoding: "hex" | "b64"; byteLength: number }[] = [];
  const stack: { path: string; value: unknown }[] = [{ path: "$", value: root }];
  while (stack.length > 0) {
    const { path, value } = stack.pop()!;
    if (typeof value === "string") {
      if (!looksLikeScheme(value)) continue;
      const parsed = parseByteField(value);
      if (!parsed.ok) return { ok: false, path, error: parsed.error };
      fields.push({ path, encoding: parsed.encoding, byteLength: parsed.bytes.length });
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) stack.push({ path: `${path}[${i}]`, value: value[i] });
    } else if (value !== null && typeof value === "object") {
      for (const [key, child] of Object.entries(value)) {
        stack.push({ path: `${path}.${key}`, value: child });
      }
    }
  }
  fields.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { ok: true, fields };
}
