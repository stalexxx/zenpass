/**
 * Bounded JSON-compatible integer-byte-array encoding for password/edit
 * buffers crossing Chrome's JSON-serialized runtime messaging (ADR-0011:
 * "Chrome runtime messaging uses JSON serialization, unlike structured
 * clone in other browsers. Specify a bounded JSON-compatible
 * integer-byte-array encoding [...]; reconstruct Uint8Array inside
 * background and clear both caller/receiver arrays after use").
 *
 * A `Uint8Array` survives Firefox's structured-clone messaging directly,
 * but Chrome serializes runtime messages as JSON, which has no typed-array
 * representation — an array of 0-255 integers is the bounded, explicit
 * wire shape used on both browsers for consistency. Neither browser's copy
 * can be proven erased from every engine-internal buffer; `clearNumberArray`
 * below is best-effort defense in depth, not a memory-safety guarantee.
 */

export const MAX_SECRET_BYTES = 4096;

/** True only for a plain array of integers in [0, 255], bounded in length.
 * Used to validate an incoming message field before reconstruction. */
export function isByteArray(value: unknown, maxLength: number = MAX_SECRET_BYTES): value is number[] {
  if (!Array.isArray(value) || value.length > maxLength) return false;
  for (const entry of value) {
    if (!Number.isInteger(entry) || entry < 0 || entry > 255) return false;
  }
  return true;
}

/** Encodes bytes as a plain JSON-compatible number array for sending
 * across runtime messaging. Does not mutate `bytes`. */
export function toByteArray(bytes: Uint8Array): number[] {
  return Array.from(bytes);
}

/** Reconstructs a Uint8Array from a validated number array. Caller must
 * validate with `isByteArray` first if the source is untrusted. */
export function fromByteArray(value: readonly number[]): Uint8Array {
  return Uint8Array.from(value);
}

/** Best-effort in-place zeroing of a plain number array (the caller's own
 * copy) after use — mirrors zeroing a Uint8Array, for the JSON-array wire
 * representation which has no typed-array semantics of its own. */
export function clearNumberArray(value: number[]): void {
  value.fill(0);
}

/** UTF-8 encodes a string into a byte array ready for the wire, without
 * retaining the intermediate Uint8Array beyond this call. */
export function stringToByteArray(value: string): number[] {
  return toByteArray(new TextEncoder().encode(value));
}

/** Decodes a validated byte array back to a UTF-8 string. */
export function byteArrayToString(value: readonly number[]): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(fromByteArray(value));
}
