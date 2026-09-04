// Recovery-key display encoding. ADR-0008 §2 / G-10 is deliberately
// unresolved: this is explicitly a provisional, plain hex rendering, not a
// final display format (no grouping/checksum/word-list scheme of this
// task's own invention — those are reserved for the human H01 reviewer).
// The underlying key bytes are unaffected by whatever display format is
// eventually chosen.
export const PROVISIONAL_LABEL =
  "Provisional format — pending final display-encoding decision (G-10); the underlying key is unaffected.";

export function toProvisionalHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Parses back a provisional-hex string the user typed/pasted for the
 * confirm step. Whitespace-tolerant; throws on anything else invalid so
 * confirmation fails closed rather than silently accepting garbage. */
export function fromProvisionalHex(input: string): Uint8Array {
  const cleaned = input.trim().toLowerCase().replace(/\s+/g, "");
  if (!/^[0-9a-f]+$/.test(cleaned) || cleaned.length % 2 !== 0) {
    throw new Error("recovery key must be hex-encoded");
  }
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
