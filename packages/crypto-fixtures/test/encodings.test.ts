import { describe, expect, test } from "bun:test";
import { byteFieldLength, looksLikeScheme, parseByteField, scanByteFields } from "../src/encodings.ts";

describe("hex: byte fields", () => {
  test("accepts even lowercase hex", () => {
    const parsed = parseByteField("hex:0a0b0c");
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.encoding).toBe("hex");
      expect(Array.from(parsed.bytes)).toEqual([0x0a, 0x0b, 0x0c]);
    }
  });

  test("accepts empty byte string", () => {
    const parsed = parseByteField("hex:");
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.bytes.length).toBe(0);
  });

  test("rejects odd length", () => {
    expect(parseByteField("hex:0a0").ok).toBe(false);
  });

  test("rejects uppercase hex", () => {
    expect(parseByteField("hex:0A0B").ok).toBe(false);
  });

  test("rejects non-hex characters", () => {
    expect(parseByteField("hex:zz").ok).toBe(false);
  });
});

describe("b64: byte fields", () => {
  test("accepts padded standard base64", () => {
    const parsed = parseByteField("b64:QUJD");
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.encoding).toBe("b64");
      expect(Buffer.from(parsed.bytes).toString("utf8")).toBe("ABC");
    }
  });

  test("accepts empty byte string", () => {
    expect(parseByteField("b64:").ok).toBe(true);
  });

  test("rejects missing padding", () => {
    expect(parseByteField("b64:QUJDRA").ok).toBe(false); // 6 chars, not multiple of 4
  });

  test("rejects url-safe alphabet", () => {
    expect(parseByteField("b64:QUJD-_==").ok).toBe(false);
  });

  test("rejects non-canonical trailing bits", () => {
    expect(parseByteField("b64:QUJDQQ==").ok).toBe(true); // "ABCA" canonical
    expect(parseByteField("b64:QUJDQR==").ok).toBe(false); // non-zero trailing bits
  });
});

describe("unknown encodings", () => {
  test("rejects base32-style prefix", () => {
    expect(parseByteField("base32:GEZDGNBV").ok).toBe(false);
  });

  test("rejects base58-style prefix", () => {
    expect(parseByteField("b58:2NEpo7TZRhUtV3Kjyxcc").ok).toBe(false);
  });

  test("scheme detection", () => {
    expect(looksLikeScheme("hex:00")).toBe(true);
    expect(looksLikeScheme("base32:GEZD")).toBe(true);
    expect(looksLikeScheme("crypto-envelope/v1")).toBe(false);
    expect(looksLikeScheme("account_01")).toBe(false);
  });
});

describe("scanByteFields", () => {
  test("collects nested byte fields and reports lengths", () => {
    const doc = {
      nonce: "hex:000102030405060708090a0b0c0d0e0f1011121314151617",
      nested: { key: "hex:000102", list: ["b64:QUJD", "plain-text"] },
    };
    const result = scanByteFields(doc);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.fields.map((f) => f.path).sort()).toEqual(["$.nested.key", "$.nested.list[0]", "$.nonce"]);
      const nonce = result.fields.find((f) => f.path === "$.nonce");
      expect(nonce?.byteLength).toBe(24);
    }
  });

  test("fails on unknown scheme anywhere in the document", () => {
    const result = scanByteFields({ a: "hex:00", b: { c: ["base32:GEZD"] } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.path).toBe("$.b.c[0]");
  });

  test("fails on malformed hex nested deep", () => {
    expect(scanByteFields({ x: [{ y: { z: "hex:0A" } }] }).ok).toBe(false);
  });
});

describe("byteFieldLength", () => {
  test("measures hex bytes", () => {
    const result = byteFieldLength("hex:000102");
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.byteLength).toBe(3);
  });
  test("rejects non-string", () => {
    expect(byteFieldLength(42).ok).toBe(false);
  });
});
