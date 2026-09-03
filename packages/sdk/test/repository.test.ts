import { expect, test } from "bun:test";
import { InMemoryLocalRepository } from "../src/repository.ts";
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
