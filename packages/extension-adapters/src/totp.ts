// RFC 6238 (TOTP) code generation, display/fill only (ADR-0011 D6: "extend
// ADR-0008's native Web Crypto TOTP permission to extension background
// display/fill only"). This mirrors apps/web/src/crypto/totp.ts's approved
// algorithm (native `crypto.subtle` HMAC, never a hand-rolled HMAC/hash) as
// its own small pure module inside this task's Allowed paths — the two
// copies run in different app runtimes by design, matching the existing
// account-bundle-codec.ts precedent of mirroring rather than sharing a
// module across a forbidden path boundary. No new cryptographic primitive.
// The TOTP seed only ever reaches this module already decrypted, in memory,
// from the trusted background; it is never itself persisted, logged, or
// transmitted.

export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface TotpOptions {
  algorithm?: TotpAlgorithm;
  digits?: number;
  periodSeconds?: number;
}

const DEFAULTS: Required<TotpOptions> = { algorithm: "SHA1", digits: 6, periodSeconds: 30 };

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Decodes an RFC 4648 base32 secret (case-insensitive, padding/whitespace
 * tolerated) into raw bytes. Throws on characters outside the base32
 * alphabet — a malformed secret must fail closed. */
export function base32Decode(input: string): Uint8Array {
  const cleaned = input.trim().toUpperCase().replace(/[\s-]+/g, "").replace(/=+$/, "");
  if (cleaned.length === 0) return new Uint8Array(0);
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error("invalid base32 TOTP secret");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

function counterBytes(counter: number): Uint8Array {
  const bytes = new Uint8Array(8);
  let remaining = counter;
  for (let i = 7; i >= 0; i -= 1) {
    bytes[i] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  return bytes;
}

const SUBTLE_ALGORITHM: Record<TotpAlgorithm, string> = {
  SHA1: "SHA-1",
  SHA256: "SHA-256",
  SHA512: "SHA-512",
};

async function hmac(secret: Uint8Array, message: Uint8Array, algorithm: TotpAlgorithm): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    secret as BufferSource,
    { name: "HMAC", hash: SUBTLE_ALGORITHM[algorithm] },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, message as BufferSource);
  return new Uint8Array(signature);
}

function dynamicTruncate(hmacResult: Uint8Array, digits: number): string {
  const offset = hmacResult[hmacResult.length - 1] & 0x0f;
  const binary =
    ((hmacResult[offset] & 0x7f) << 24) |
    ((hmacResult[offset + 1] & 0xff) << 16) |
    ((hmacResult[offset + 2] & 0xff) << 8) |
    (hmacResult[offset + 3] & 0xff);
  const code = binary % 10 ** digits;
  return code.toString().padStart(digits, "0");
}

/** Computes the TOTP code for `secretBase32` at `atEpochMs` (defaults to
 * now). `secretBase32` is caller-owned already-decrypted plaintext; this
 * function does not retain a copy beyond the synchronous decode step. */
export async function computeTotp(secretBase32: string, options: TotpOptions = {}, atEpochMs: number = Date.now()): Promise<string> {
  const { algorithm, digits, periodSeconds } = { ...DEFAULTS, ...options };
  const secret = base32Decode(secretBase32);
  if (secret.length === 0) throw new Error("empty TOTP secret");
  const counter = Math.floor(atEpochMs / 1000 / periodSeconds);
  const digest = await hmac(secret, counterBytes(counter), algorithm);
  return dynamicTruncate(digest, digits);
}

/** Seconds remaining in the current TOTP period at `atEpochMs`, for a
 * countdown display. */
export function secondsRemaining(periodSeconds: number = DEFAULTS.periodSeconds, atEpochMs: number = Date.now()): number {
  const elapsed = Math.floor(atEpochMs / 1000) % periodSeconds;
  return periodSeconds - elapsed;
}
