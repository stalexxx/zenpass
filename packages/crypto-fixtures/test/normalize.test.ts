import { describe, expect, test } from "bun:test";
import {
  cloneWithoutDigest,
  normalizedRecordDigest,
  normalizedRecordString,
  parseDigestField,
  sha256Hex,
  stableStringify,
} from "../src/normalize.ts";

describe("stableStringify", () => {
  test("sorts object keys recursively", () => {
    expect(stableStringify({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
  });

  test("preserves array order", () => {
    expect(stableStringify(["b", "a"])).toBe('["b","a"]');
  });

  test("handles scalars and null", () => {
    expect(stableStringify(null)).toBe("null");
    expect(stableStringify("x")).toBe('"x"');
    expect(stableStringify(3)).toBe("3");
    expect(stableStringify(true)).toBe("true");
  });

  test("is order-insensitive for equal objects", () => {
    expect(stableStringify({ a: 1, b: 2 })).toBe(stableStringify({ b: 2, a: 1 }));
  });
});

describe("cloneWithoutDigest", () => {
  test("removes provenance.normalizedRecordSha256 at any depth, keeps siblings", () => {
    const doc = {
      id: "x",
      provenance: { source: "RFC", normalizedRecordSha256: "sha256:" + "0".repeat(64) },
      nested: { provenance: { normalizedRecordSha256: "sha256:" + "0".repeat(64) } },
    };
    const cloned = cloneWithoutDigest(doc) as typeof doc;
    expect(cloned.provenance.source).toBe("RFC");
    expect((cloned.provenance as Record<string, unknown>).normalizedRecordSha256).toBeUndefined();
    expect(
      (cloned.nested.provenance as Record<string, unknown>).normalizedRecordSha256,
    ).toBeUndefined();
    // original is not mutated
    expect(doc.provenance.normalizedRecordSha256).toBe("sha256:" + "0".repeat(64));
    expect(
      doc.nested.provenance.normalizedRecordSha256,
    ).toBe("sha256:" + "0".repeat(64));
  });
});

describe("digests", () => {
  test("sha256Hex of empty string matches known value", () => {
    expect(sha256Hex("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  test("normalizedRecordDigest is deterministic and digest-insensitive", () => {
    const base = { id: "v1", bytes: "hex:00ff", provenance: { source: "test" } };
    const withDigest = {
      ...base,
      provenance: { ...base.provenance, normalizedRecordSha256: "sha256:" + "a".repeat(64) },
    };
    const d1 = normalizedRecordDigest(base as never);
    const d2 = normalizedRecordDigest(withDigest as never);
    expect(d1).toBe(d2);
    expect(d1).toMatch(/^[0-9a-f]{64}$/);
    // and changes when vector data changes
    const changed = { ...base, bytes: "hex:00fe" };
    expect(normalizedRecordDigest(changed as never)).not.toBe(d1);
  });

  test("normalizedRecordString has no whitespace and sorted keys", () => {
    const s = normalizedRecordString({ b: "hex:01", a: 2 } as never);
    expect(s).toBe('{"a":2,"b":"hex:01"}');
  });
});

describe("parseDigestField", () => {
  test("accepts well-formed digest", () => {
    const r = parseDigestField("sha256:" + "ab".repeat(32));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.hex).toBe("ab".repeat(32));
  });
  test("rejects malformed digests", () => {
    expect(parseDigestField("sha256:xyz").ok).toBe(false);
    expect(parseDigestField("0".repeat(64)).ok).toBe(false);
    expect(parseDigestField("sha256:" + "A".repeat(64)).ok).toBe(false);
    expect(parseDigestField(42).ok).toBe(false);
  });
});
