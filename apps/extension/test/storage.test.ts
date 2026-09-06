import { describe, expect, test } from "bun:test";
import { createAssociationStorage, createInMemoryAssociationStorage, type BrowserLocalStorageArea } from "../src/storage.ts";

function fakeArea(): BrowserLocalStorageArea & { data: Record<string, unknown> } {
  const data: Record<string, unknown> = {};
  return {
    data,
    async get(keys) {
      const out: Record<string, unknown> = {};
      for (const key of keys) if (key in data) out[key] = data[key];
      return out;
    },
    async set(items) {
      Object.assign(data, items);
    },
    async remove(keys) {
      for (const key of keys) delete data[key];
    },
  };
}

describe("createAssociationStorage", () => {
  test("round-trips only the non-secret accountId/apiOrigin association", async () => {
    const area = fakeArea();
    const storage = createAssociationStorage(area);
    expect(await storage.get()).toBeNull();
    await storage.set({ accountId: "acct_1", apiOrigin: "https://api.example.test" });
    expect(await storage.get()).toEqual({ accountId: "acct_1", apiOrigin: "https://api.example.test" });
    await storage.clear();
    expect(await storage.get()).toBeNull();
  });

  test("stores nothing beyond the two association fields", async () => {
    const area = fakeArea();
    const storage = createAssociationStorage(area);
    await storage.set({ accountId: "acct_1", apiOrigin: "https://api.example.test" });
    const keys = Object.keys(area.data);
    expect(keys).toHaveLength(1);
    const stored = area.data[keys[0]!] as Record<string, unknown>;
    expect(Object.keys(stored).sort()).toEqual(["accountId", "apiOrigin"]);
  });

  test("rejects a malformed stored value rather than surfacing it", async () => {
    const area = fakeArea();
    const storage = createAssociationStorage(area);
    await area.set({ "zkpm.extension.account-association.v1": { accountId: 5 } });
    expect(await storage.get()).toBeNull();
  });

  test("rejects setting an invalid association", async () => {
    const area = fakeArea();
    const storage = createAssociationStorage(area);
    await expect(storage.set({ accountId: "", apiOrigin: "https://x.test" })).rejects.toThrow();
  });
});

describe("createInMemoryAssociationStorage", () => {
  test("round-trips in memory", async () => {
    const storage = createInMemoryAssociationStorage();
    expect(await storage.get()).toBeNull();
    await storage.set({ accountId: "acct_1", apiOrigin: "https://api.example.test" });
    expect(await storage.get()).toEqual({ accountId: "acct_1", apiOrigin: "https://api.example.test" });
    await storage.clear();
    expect(await storage.get()).toBeNull();
  });
});
