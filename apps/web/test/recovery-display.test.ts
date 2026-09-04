import { describe, expect, test } from "bun:test";
import { fromProvisionalHex, toProvisionalHex } from "../src/crypto/recovery-display.ts";

describe("recovery-display", () => {
  test("round-trips arbitrary bytes", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    expect(fromProvisionalHex(toProvisionalHex(bytes))).toEqual(bytes);
  });

  test("tolerates whitespace and mixed case on input", () => {
    expect(fromProvisionalHex(" AaBb 0011 ")).toEqual(new Uint8Array([0xaa, 0xbb, 0x00, 0x11]));
  });

  test("rejects non-hex or odd-length input", () => {
    expect(() => fromProvisionalHex("not hex")).toThrow();
    expect(() => fromProvisionalHex("abc")).toThrow();
  });
});
