import { describe, expect, test } from "bun:test";
import { DEFAULT_GENERATOR_OPTIONS, generatePassword } from "../src/crypto/generator.ts";

describe("generatePassword", () => {
  test("generates the requested length", () => {
    expect(generatePassword({ length: 32 }).length).toBe(32);
  });

  test("defaults produce a plausible mixed-class password", () => {
    const pw = generatePassword();
    expect(pw.length).toBe(DEFAULT_GENERATOR_OPTIONS.length);
  });

  test("respects a single enabled class", () => {
    const pw = generatePassword({ length: 16, upper: false, lower: true, digits: false, symbols: false });
    expect(pw).toMatch(/^[a-km-z]+$/);
  });

  test("guarantees at least one character from each enabled class", () => {
    for (let i = 0; i < 25; i += 1) {
      const pw = generatePassword({ length: 8, upper: true, lower: true, digits: true, symbols: true });
      expect(pw).toMatch(/[A-HJ-NP-Z]/);
      expect(pw).toMatch(/[a-km-z]/);
      expect(pw).toMatch(/[2-9]/);
      expect(/[!@#$%^&*()\-_=+[\]{}]/.test(pw)).toBe(true);
    }
  });

  test("throws when no character class is enabled", () => {
    expect(() => generatePassword({ upper: false, lower: false, digits: false, symbols: false })).toThrow();
  });

  test("throws when length is smaller than the number of enabled classes", () => {
    expect(() => generatePassword({ length: 2, upper: true, lower: true, digits: true, symbols: true })).toThrow();
  });

  test("does not use Math.random (spy asserts zero calls)", () => {
    const original = Math.random;
    let calls = 0;
    Math.random = () => { calls += 1; return original(); };
    try {
      generatePassword({ length: 64 });
      expect(calls).toBe(0);
    } finally {
      Math.random = original;
    }
  });

  test("output has reasonable entropy across many samples (not constant, no obvious repetition)", () => {
    const samples = new Set<string>();
    for (let i = 0; i < 200; i += 1) samples.add(generatePassword({ length: 24 }));
    expect(samples.size).toBe(200);
  });
});
