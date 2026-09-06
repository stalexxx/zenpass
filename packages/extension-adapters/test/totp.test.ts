import { describe, expect, test } from "bun:test";
import { base32Decode, computeTotp, secondsRemaining } from "../src/totp.ts";

// RFC 6238 Appendix B known-answer test vectors, using the well-known
// 20-byte ASCII seed "12345678901234567890" (SHA1), base32-encoded. These
// are published test vectors, not a real user secret.
const SEED_SHA1_ASCII = "12345678901234567890";

function toBase32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

describe("base32Decode", () => {
  test("round-trips a known ASCII seed", () => {
    const seedBytes = new TextEncoder().encode(SEED_SHA1_ASCII);
    const encoded = toBase32(seedBytes);
    expect(base32Decode(encoded)).toEqual(seedBytes);
  });

  test("rejects invalid characters", () => {
    expect(() => base32Decode("not-valid-base32!!!")).toThrow();
  });

  test("tolerates whitespace, dashes, and lowercase", () => {
    const seedBytes = new TextEncoder().encode(SEED_SHA1_ASCII);
    const encoded = toBase32(seedBytes);
    const spaced = encoded.toLowerCase().replace(/(.{4})/g, "$1 ").trim();
    expect(base32Decode(spaced)).toEqual(seedBytes);
  });
});

describe("computeTotp (RFC 6238 Appendix B known-answer vectors)", () => {
  const secret = toBase32(new TextEncoder().encode(SEED_SHA1_ASCII));

  test("T=59s -> 94287082 (8-digit SHA1)", async () => {
    const code = await computeTotp(secret, { digits: 8 }, 59_000);
    expect(code).toBe("94287082");
  });

  test("T=1111111109s -> 07081804 (8-digit SHA1)", async () => {
    const code = await computeTotp(secret, { digits: 8 }, 1_111_111_109_000);
    expect(code).toBe("07081804");
  });

  test("T=1111111111s -> 14050471 (8-digit SHA1)", async () => {
    const code = await computeTotp(secret, { digits: 8 }, 1_111_111_111_000);
    expect(code).toBe("14050471");
  });

  test("default options give a zero-padded 6-digit code", async () => {
    const code = await computeTotp(secret, {}, 59_000);
    expect(code).toMatch(/^\d{6}$/);
  });

  test("rejects an empty secret", async () => {
    await expect(computeTotp("")).rejects.toThrow();
  });
});

describe("secondsRemaining", () => {
  test("counts down within a 30s period", () => {
    expect(secondsRemaining(30, 0)).toBe(30);
    expect(secondsRemaining(30, 1_000)).toBe(29);
    expect(secondsRemaining(30, 29_000)).toBe(1);
    expect(secondsRemaining(30, 30_000)).toBe(30);
  });
});
