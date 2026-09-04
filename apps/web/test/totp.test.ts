import { describe, expect, test } from "bun:test";
import { base32Decode, computeTotp, secondsRemaining } from "../src/crypto/totp.ts";

describe("totp", () => {
  test("base32Decode matches the RFC 4648 test vectors", () => {
    const toStr = (b: Uint8Array) => new TextDecoder().decode(b);
    expect(toStr(base32Decode("MY======"))).toBe("f");
    expect(toStr(base32Decode("MZXQ===="))).toBe("fo");
    expect(toStr(base32Decode("MZXW6==="))).toBe("foo");
    expect(toStr(base32Decode("MZXW6YQ="))).toBe("foob");
    expect(toStr(base32Decode("MZXW6YTBOI======"))).toBe("foobar");
  });

  test("base32Decode is case-insensitive and tolerates whitespace/hyphens", () => {
    expect(base32Decode("mzxw 6yq=")).toEqual(base32Decode("MZXW6YQ="));
    expect(base32Decode("mzxw-6yq=")).toEqual(base32Decode("MZXW6YQ="));
  });

  test("base32Decode rejects invalid characters", () => {
    expect(() => base32Decode("this is not base32!!!")).toThrow();
  });

  // RFC 6238 Appendix B test vectors for the 20-byte SHA1 secret
  // "12345678901234567890" (ASCII), 8-digit codes, 30s step.
  const SECRET_SHA1_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // base32("12345678901234567890")

  test("computeTotp matches RFC 6238 Appendix B SHA1 test vectors", async () => {
    expect(await computeTotp(SECRET_SHA1_B32, { algorithm: "SHA1", digits: 8 }, 59_000)).toBe("94287082");
    expect(await computeTotp(SECRET_SHA1_B32, { algorithm: "SHA1", digits: 8 }, 1_111_111_109_000)).toBe("07081804");
    expect(await computeTotp(SECRET_SHA1_B32, { algorithm: "SHA1", digits: 8 }, 1_111_111_111_000)).toBe("14050471");
    expect(await computeTotp(SECRET_SHA1_B32, { algorithm: "SHA1", digits: 8 }, 1_234_567_890_000)).toBe("89005924");
    expect(await computeTotp(SECRET_SHA1_B32, { algorithm: "SHA1", digits: 8 }, 2_000_000_000_000)).toBe("69279037");
  });

  test("computeTotp defaults to 6 digits and rejects an empty secret", async () => {
    const code = await computeTotp(SECRET_SHA1_B32);
    expect(code).toMatch(/^\d{6}$/);
    await expect(computeTotp("")).rejects.toThrow();
  });

  test("secondsRemaining counts down within one period and wraps", () => {
    expect(secondsRemaining(30, 0)).toBe(30);
    expect(secondsRemaining(30, 29_000)).toBe(1);
    expect(secondsRemaining(30, 30_000)).toBe(30);
    expect(secondsRemaining(30, 59_000)).toBe(1);
  });
});
