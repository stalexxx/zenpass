import { beforeEach, describe, expect, test } from "bun:test";
import "fake-indexeddb/auto";
import { IndexedDBLocalRepository, deleteVaultDatabase } from "../src/db/indexeddb-repository.ts";
import type { ItemRecord, Mutation } from "@zkpm/sdk";

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

let ns = 0;
function freshNamespace(): string {
  ns += 1;
  return `test-${ns}-${Date.now()}`;
}

describe("IndexedDBLocalRepository — LocalRepository contract (mirrors packages/sdk/test/repository.test.ts)", () => {
  test("putItem/getItem round-trips an ItemRecord exactly, byte for byte on ciphertext", async () => {
    const repo = new IndexedDBLocalRepository(freshNamespace());
    await repo.putItem(item);
    expect(await repo.getItem("v1", "i1")).toEqual(item);
  });

  test("listItems is scoped to one vault", async () => {
    const repo = new IndexedDBLocalRepository(freshNamespace());
    await repo.putItem(item);
    await repo.putItem({ ...item, itemId: "i2", vaultId: "v2" });
    expect(await repo.listItems("v1")).toEqual([item]);
  });

  test("cursor persistence round-trips exactly and starts null for an unpulled vault", async () => {
    const repo = new IndexedDBLocalRepository(freshNamespace());
    expect(await repo.getCursor("v1")).toBeNull();
    await repo.setCursor("v1", "opaque-cursor-value");
    expect(await repo.getCursor("v1")).toBe("opaque-cursor-value");
  });

  test("queued mutation round-trips including its sync-state metadata", async () => {
    const repo = new IndexedDBLocalRepository(freshNamespace());
    await repo.enqueueMutation({ mutation, state: "LOCAL_DIRTY", attempts: 0 });
    const entry = await repo.getQueuedMutation("m1");
    expect(entry).toEqual({ mutation, state: "LOCAL_DIRTY", attempts: 0 });
    await repo.dequeueMutation("m1");
    expect(await repo.getQueuedMutation("m1")).toBeNull();
  });

  test("re-enqueuing the same mutationId replaces the entry in place rather than duplicating it", async () => {
    const repo = new IndexedDBLocalRepository(freshNamespace());
    await repo.enqueueMutation({ mutation, state: "LOCAL_DIRTY", attempts: 0 });
    await repo.enqueueMutation({ mutation, state: "SYNCING", attempts: 1 });
    const all = await repo.listQueuedMutations();
    expect(all).toHaveLength(1);
    expect(all[0].state).toBe("SYNCING");
  });

  test("every persisted field is ciphertext/metadata shaped: no key named plaintext/password/notes ever appears on a stored value", async () => {
    const repo = new IndexedDBLocalRepository(freshNamespace());
    await repo.putItem(item);
    await repo.enqueueMutation({ mutation, state: "LOCAL_DIRTY", attempts: 0 });
    const serialized = JSON.stringify({ items: await repo.listItems("v1"), queue: await repo.listQueuedMutations() });
    expect(serialized).not.toMatch(/"password"|"plaintext"|"notes"/);
    expect(serialized).toContain("b64:");
  });
});

describe("IndexedDBLocalRepository — durability across connection close/reopen", () => {
  test("items, cursor, and queued mutations all survive closing and reopening the database", async () => {
    const namespace = freshNamespace();
    const first = new IndexedDBLocalRepository(namespace);
    await first.putItem(item);
    await first.setCursor("v1", "cursor-1");
    await first.enqueueMutation({ mutation, state: "RETRYABLE", attempts: 2, nextRetryAt: 12345, lastError: "network" });
    first.close();

    const second = new IndexedDBLocalRepository(namespace);
    expect(await second.getItem("v1", "i1")).toEqual(item);
    expect(await second.getCursor("v1")).toBe("cursor-1");
    expect(await second.getQueuedMutation("m1")).toEqual({
      mutation, state: "RETRYABLE", attempts: 2, nextRetryAt: 12345, lastError: "network",
    });
    second.close();
    await deleteVaultDatabase(namespace);
  });

  test("different namespaces do not share data", async () => {
    const a = new IndexedDBLocalRepository(freshNamespace());
    const b = new IndexedDBLocalRepository(freshNamespace());
    await a.putItem(item);
    expect(await b.getItem("v1", "i1")).toBeNull();
  });
});

beforeEach(() => {
  // Nothing to reset globally — every test uses a fresh namespace so
  // databases never collide across tests.
});
