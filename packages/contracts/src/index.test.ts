import test from "node:test";
import assert from "node:assert/strict";
import type { ItemRecord } from "./index.ts";

test("ItemRecord exposes only opaque item content", () => {
  const record: ItemRecord = { itemId: "item_01", vaultId: "vault_01", ciphertext: "b64:opaque", envelopeVersion: "crypto-envelope/v1", revision: 1, deleted: false, createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z" };
  assert.equal(record.ciphertext, "b64:opaque");
  assert.equal("title" in record, false);
});
