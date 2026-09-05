import test from "node:test";
import assert from "node:assert/strict";
import type { ItemRecord, KeyBundleConflict, DeviceCreate } from "./index.ts";

test("ItemRecord exposes only opaque item content", () => {
  const record: ItemRecord = { itemId: "item_01", vaultId: "vault_01", ciphertext: "b64:opaque", envelopeVersion: "crypto-envelope/v1", revision: 1, deleted: false, createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z" };
  assert.equal(record.ciphertext, "b64:opaque");
  assert.equal("title" in record, false);
});

test("KeyBundleConflict (ADR-0011 G1) is distinct from sync's Conflict shape", () => {
  const conflict: KeyBundleConflict = { error: "key_bundle_conflict", currentVersion: 3, attemptedVersion: 3 };
  assert.equal(conflict.error, "key_bundle_conflict");
  assert.equal("current" in conflict, false);
  assert.equal("mutationId" in conflict, false);
});

test("DeviceCreate (ADR-0011 G2) accepts the legacy and bearer-session-v1 branches, never mixed", () => {
  const legacy: DeviceCreate = { name: "Laptop", publicKey: "b64:AA==" };
  const bearer: DeviceCreate = { name: "Extension", enrollmentMode: "bearer-session-v1" };
  assert.equal("publicKey" in legacy, true);
  assert.equal("enrollmentMode" in bearer, true);
});
