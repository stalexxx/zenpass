import { expect, test } from "bun:test";
import { InMemoryLocalRepository, RecordConflictError, assertMonotonicPut } from "../src/repository.ts";
import type { ItemRecord, Mutation } from "../src/types.ts";

const item: ItemRecord = {
  itemId: "i1",
  vaultId: "v1",
  ciphertext: "b64:c29tZS1jaXBoZXJ0ZXh0",
  envelopeVersion: "crypto-envelope/v1",
  revision: 3,
  deleted: false,
  createdAt: "2030-01-01T00:00:00Z",
  updatedAt: "2030-01-02T00:00:00Z",
};

const mutation: Mutation = {
  mutationId: "m1",
  itemId: "i1",
  vaultId: "v1",
  baseRevision: 2,
  ciphertext: "b64:YW5vdGhlci1jaXBoZXJ0ZXh0",
  envelopeVersion: "crypto-envelope/v1",
  deleted: false,
};

test("putItem/getItem round-trips an ItemRecord exactly, byte for byte on ciphertext", async () => {
  const repo = new InMemoryLocalRepository();
  await repo.putItem(item);
  expect(await repo.getItem("v1", "i1")).toEqual(item);
});

test("listItems is scoped to one vault", async () => {
  const repo = new InMemoryLocalRepository();
  await repo.putItem(item);
  await repo.putItem({ ...item, itemId: "i2", vaultId: "v2" });
  expect(await repo.listItems("v1")).toEqual([item]);
});

test("cursor persistence round-trips exactly and starts null for an unpulled vault", async () => {
  const repo = new InMemoryLocalRepository();
  expect(await repo.getCursor("v1")).toBeNull();
  await repo.setCursor("v1", "opaque-cursor-value");
  expect(await repo.getCursor("v1")).toBe("opaque-cursor-value");
});

test("queued mutation round-trips including its sync-state metadata", async () => {
  const repo = new InMemoryLocalRepository();
  await repo.enqueueMutation({ mutation, state: "LOCAL_DIRTY", attempts: 0 });
  const entry = await repo.getQueuedMutation("m1");
  expect(entry).toEqual({ mutation, state: "LOCAL_DIRTY", attempts: 0 });
  await repo.dequeueMutation("m1");
  expect(await repo.getQueuedMutation("m1")).toBeNull();
});

test("re-enqueuing the same mutationId replaces the entry in place rather than duplicating it", async () => {
  const repo = new InMemoryLocalRepository();
  await repo.enqueueMutation({ mutation, state: "LOCAL_DIRTY", attempts: 0 });
  await repo.enqueueMutation({ mutation, state: "SYNCING", attempts: 1 });
  const all = await repo.listQueuedMutations();
  expect(all).toHaveLength(1);
  expect(all[0].state).toBe("SYNCING");
});

test("every persisted field is ciphertext/metadata shaped: no key named plaintext/password/notes ever appears on a stored value", async () => {
  const repo = new InMemoryLocalRepository();
  await repo.putItem(item);
  await repo.enqueueMutation({ mutation, state: "LOCAL_DIRTY", attempts: 0 });
  const serialized = JSON.stringify({ items: await repo.listItems("v1"), queue: await repo.listQueuedMutations() });
  // ItemRecord/Mutation's TypeScript shape already excludes any plaintext
  // field, but this asserts it holds for what's actually stored too:
  // ciphertext values here are recognizably base64 (the b64: convention),
  // not any structured plaintext object leaking through.
  expect(serialized).not.toMatch(/"password"|"plaintext"|"notes"/);
  expect(serialized).toContain("b64:");
});

// SEC-04: InMemoryLocalRepository.putItem must not unconditionally replace
// an already-stored record — see docs/tasks/SEC-04.md.

test("putItem rejects a revision rollback: an older-revision record must not replace a newer one", async () => {
  const repo = new InMemoryLocalRepository();
  await repo.putItem(item); // revision 3
  const rollback: ItemRecord = { ...item, revision: 2, ciphertext: "b64:cm9sbGJhY2s" };
  await expect(repo.putItem(rollback)).rejects.toThrow(RecordConflictError);
  // Fail closed: the newer record already stored is untouched.
  expect(await repo.getItem("v1", "i1")).toEqual(item);
});

test("putItem rejects a revival: a rollback with deleted:false reviving a tombstoned record is still a rollback", async () => {
  const repo = new InMemoryLocalRepository();
  const tombstoned: ItemRecord = { ...item, revision: 4, deleted: true };
  await repo.putItem(tombstoned);
  const revived: ItemRecord = { ...item, revision: 3, deleted: false }; // old, pre-tombstone revision
  await expect(repo.putItem(revived)).rejects.toThrow(RecordConflictError);
  expect(await repo.getItem("v1", "i1")).toEqual(tombstoned);
});

test("putItem rejects a same-revision record whose bytes differ from what is already stored", async () => {
  const repo = new InMemoryLocalRepository();
  await repo.putItem(item);
  const tampered: ItemRecord = { ...item, ciphertext: "b64:dGFtcGVyZWQ" }; // same revision, different ciphertext
  await expect(repo.putItem(tampered)).rejects.toThrow(RecordConflictError);
  expect(await repo.getItem("v1", "i1")).toEqual(item);
});

test("putItem rejects a same-revision record with a tampered deleted flag", async () => {
  const repo = new InMemoryLocalRepository();
  await repo.putItem(item); // deleted: false
  const tamperedDeleted: ItemRecord = { ...item, deleted: true }; // same revision, flipped tombstone
  await expect(repo.putItem(tamperedDeleted)).rejects.toThrow(RecordConflictError);
  expect(await repo.getItem("v1", "i1")).toEqual(item);
});

test("putItem accepts a genuine same-revision re-write (identical bytes) as a no-op", async () => {
  const repo = new InMemoryLocalRepository();
  await repo.putItem(item);
  await repo.putItem({ ...item }); // identical copy at the same revision
  expect(await repo.getItem("v1", "i1")).toEqual(item);
});

test("putItem accepts a genuine revision advance", async () => {
  const repo = new InMemoryLocalRepository();
  await repo.putItem(item);
  const next: ItemRecord = { ...item, revision: 4, ciphertext: "b64:bmV3", updatedAt: "2030-01-03T00:00:00Z" };
  await repo.putItem(next);
  expect(await repo.getItem("v1", "i1")).toEqual(next);
});

test("assertMonotonicPut is a no-op when there is no existing record", () => {
  expect(() => assertMonotonicPut(null, item)).not.toThrow();
});

test("assertMonotonicPut: RecordConflictError carries a machine-readable reason", () => {
  try {
    assertMonotonicPut(item, { ...item, revision: 1 });
    throw new Error("expected assertMonotonicPut to throw");
  } catch (e) {
    expect(e).toBeInstanceOf(RecordConflictError);
    expect((e as RecordConflictError).reason).toBe("revision-regression");
  }
  try {
    assertMonotonicPut(item, { ...item, ciphertext: "b64:eA" });
    throw new Error("expected assertMonotonicPut to throw");
  } catch (e) {
    expect(e).toBeInstanceOf(RecordConflictError);
    expect((e as RecordConflictError).reason).toBe("revision-mismatch");
  }
});

// Residual risk (see SEC-04's completion report / docstring on
// assertMonotonicPut): a *higher*-numbered revision carrying a genuinely
// valid but stale ciphertext cannot be told apart from a legitimate new
// write without an AAD change binding `revision` — that gap is out of
// scope for this task and is documented, not silently left unaddressed.
test("residual gap: a stale-but-valid ciphertext relabeled at a fabricated higher revision is NOT detected by assertMonotonicPut alone", () => {
  const staleRelabeled: ItemRecord = { ...item, revision: 99 }; // same old ciphertext, fake higher revision
  expect(() => assertMonotonicPut(item, staleRelabeled)).not.toThrow();
});
