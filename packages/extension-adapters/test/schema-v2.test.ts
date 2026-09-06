import { describe, expect, test } from "bun:test";
import { parsePopupMessage } from "../src/schema.ts";
import { isByteArray, toByteArray } from "../src/bytes.ts";

const pw = toByteArray(new TextEncoder().encode("hunter2"));

describe("parsePopupMessage: C04-EXT2 additions", () => {
  test("accepts unlock with a bounded byte-array password", () => {
    expect(parsePopupMessage({ type: "unlock", accountId: "acct_1", apiOrigin: "https://api.example.test", password: pw }))
      .toEqual({ type: "unlock", accountId: "acct_1", apiOrigin: "https://api.example.test", password: pw });
  });

  test("rejects unlock with unknown fields, a non-byte-array password, or an empty password", () => {
    expect(parsePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://x.test", password: pw, extra: 1 })).toBeNull();
    expect(parsePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://x.test", password: "hunter2" })).toBeNull();
    expect(parsePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://x.test", password: [] })).toBeNull();
    expect(parsePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://x.test", password: [1, 2, 256] })).toBeNull();
    expect(parsePopupMessage({ type: "unlock", accountId: "", apiOrigin: "https://x.test", password: pw })).toBeNull();
  });

  test("accepts logout/list-items/get-totp", () => {
    expect(parsePopupMessage({ type: "logout" })).toEqual({ type: "logout" });
    expect(parsePopupMessage({ type: "list-items" })).toEqual({ type: "list-items" });
    expect(parsePopupMessage({ type: "get-totp", itemId: "item_1" })).toEqual({ type: "get-totp", itemId: "item_1" });
    expect(parsePopupMessage({ type: "get-totp" })).toBeNull();
    expect(parsePopupMessage({ type: "logout", extra: true })).toBeNull();
  });

  test("accepts a minimal save-item (note, no secrets) and a full login save-item", () => {
    expect(parsePopupMessage({ type: "save-item", title: "My note", itemType: "note" }))
      .toEqual({ type: "save-item", title: "My note", itemType: "note" });
    const full = {
      type: "save-item", title: "Example", itemType: "login", itemId: "item_1",
      username: "alice", password: pw, url: "https://example.test", notes: toByteArray(new TextEncoder().encode("n")),
    };
    expect(parsePopupMessage(full)).toEqual(full);
  });

  test("rejects save-item with unknown fields, a bad itemType, or a non-byte-array secret", () => {
    expect(parsePopupMessage({ type: "save-item", title: "x", itemType: "login", extra: 1 })).toBeNull();
    expect(parsePopupMessage({ type: "save-item", title: "x", itemType: "not-a-type" })).toBeNull();
    expect(parsePopupMessage({ type: "save-item", title: "x", itemType: "login", password: "plain" })).toBeNull();
    expect(parsePopupMessage({ type: "save-item", title: "", itemType: "note" })).toBeNull();
    expect(parsePopupMessage({ type: "save-item", itemType: "note" })).toBeNull();
  });
});

describe("isByteArray", () => {
  test("accepts a bounded array of byte values only", () => {
    expect(isByteArray([0, 1, 255])).toBe(true);
    expect(isByteArray([])).toBe(true);
    expect(isByteArray([1.5])).toBe(false);
    expect(isByteArray([-1])).toBe(false);
    expect(isByteArray([256])).toBe(false);
    expect(isByteArray("not-an-array")).toBe(false);
    expect(isByteArray(new Array(5000).fill(0))).toBe(false);
  });
});
