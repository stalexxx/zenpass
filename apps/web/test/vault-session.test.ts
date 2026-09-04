import { describe, expect, test } from "bun:test";
import init from "crypto-wasm";
import { CryptoWorkerHost, type CryptoBackend } from "../../../packages/crypto-worker/src/index.ts";
import { createWasmBackend } from "../../../packages/crypto-worker/src/wasm-adapter.ts";
import { ApiClient, InMemoryLocalRepository, SyncEngine } from "@zkpm/sdk";
import { CryptoWorkerClient } from "../src/crypto/worker-client.ts";
import { VaultSession, CLIPBOARD_CLEAR_MS } from "../src/vault/vault-session.ts";
import type { AccountBundle } from "../src/vault/account-bundle.ts";

class FakeWorker {
  private host: CryptoWorkerHost;
  private listeners = new Map<string, ((event: unknown) => void)[]>();
  constructor(backend: CryptoBackend) { this.host = new CryptoWorkerHost(backend); }
  addEventListener(type: string, listener: (event: unknown) => void): void {
    const list = this.listeners.get(type) ?? []; list.push(listener); this.listeners.set(type, list);
  }
  postMessage(message: unknown): void {
    // Real postMessage structured-clones the message, so the Worker never
    // sees (and cannot zero) the caller's own buffer — mimic that here, or
    // this fake would zero the test's own password array in place.
    const cloned = structuredClone(message);
    queueMicrotask(() => {
      const response = this.host.handle(cloned);
      for (const listener of this.listeners.get("message") ?? []) listener({ data: response });
    });
  }
  terminate(): void {}
}

async function setup(): Promise<{ client: CryptoWorkerClient; bundle: AccountBundle; session: VaultSession }> {
  await init();
  const client = new CryptoWorkerClient(new FakeWorker(await createWasmBackend()) as unknown as Worker);
  const password = new Uint8Array([1, 2, 3, 4]);
  const setupResult = await client.createAccountSetup({
    password, reportedPhysicalMemoryKiB: 262_144n, accountId: "acct_test", vaultId: "vault_test", itemId: "vault-key",
  });
  const bundle: AccountBundle = {
    accountId: setupResult.accountId, vaultId: setupResult.vaultId, itemId: setupResult.itemId,
    kdfParametersCbor: setupResult.kdfParametersCbor, wrappedAccountKey: setupResult.wrappedAccountKey,
    wrappedVaultKey: setupResult.wrappedVaultKey, wrappedItemKey: setupResult.wrappedItemKey,
    wrappedRecoveryKey: setupResult.wrappedRecoveryKey,
  };
  const repo = new InMemoryLocalRepository();
  const api = new ApiClient({ baseUrl: "http://vault.test.invalid", fetchImpl: (() => { throw new Error("network unused in this test"); }) as unknown as typeof fetch });
  const sync = new SyncEngine(api, repo);
  const session = new VaultSession(client, repo, sync);
  await session.unlockWithPassword(bundle, password.slice());
  return { client, bundle, session };
}

describe("VaultSession lock lifecycle", () => {
  test("unlock loads nothing yet (empty vault), save adds a visible item, and it decrypts back exactly", async () => {
    const { session } = await setup();
    expect(session.isUnlocked).toBe(true);
    expect(session.list()).toEqual([]);
    const id = await session.saveItem({ type: "login", title: "Example", username: "alice", password: "hunter2" });
    expect(session.list()).toHaveLength(1);
    expect(session.getItemData(id)).toEqual({ type: "login", title: "Example", username: "alice", password: "hunter2" });
  });

  test("lock clears the key handle, item cache, search results, and selected item", async () => {
    const { session } = await setup();
    const id = await session.saveItem({ type: "note", title: "Secret note", notes: "shh" });
    session.selectedItemId = id;
    expect(session.debugMemoryState()).toMatchObject({ itemCacheSize: 1, searchEntries: 1, unlocked: true });

    await session.lock();

    const state = session.debugMemoryState();
    expect(state).toEqual({ itemCacheSize: 0, searchEntries: 0, selectedItemId: null, unlocked: false });
    expect(session.list()).toEqual([]);
    expect(session.search("Secret")).toEqual([]);
    expect(session.getItemData(id)).toBeNull();
  });

  test("operations on a locked session are rejected rather than silently no-op", async () => {
    const { session } = await setup();
    await session.lock();
    await expect(session.saveItem({ type: "note", title: "x" })).rejects.toThrow(/locked/);
  });

  test("save validates required fields locally before ever calling the Worker", async () => {
    const { session } = await setup();
    await expect(session.saveItem({ type: "login", title: "" })).rejects.toThrow(/title/i);
    await expect(session.saveItem({ type: "login", title: "No creds" })).rejects.toThrow(/username or a password/i);
  });

  test("delete creates a tombstone and hides the item; undo while still local restores it", async () => {
    const { session } = await setup();
    const id = await session.saveItem({ type: "login", title: "ToDelete", username: "bob" });
    const mutationId = await session.deleteItem(id);
    expect(session.list()).toEqual([]);
    expect(session.getItemData(id)).toBeNull();

    const restored = await session.undoDeleteIfLocal(mutationId, id);
    expect(restored).toBe(true);
    expect(session.list()).toHaveLength(1);
    expect(session.getItemData(id)?.title).toBe("ToDelete");
  });

  test("an item saved but never pushed to the server is still visible after a fresh unlock (e.g. app relaunch)", async () => {
    // Regression test: saveItem() durably queues the mutation
    // (LocalRepository.enqueueMutation) but only writes the confirmed
    // `items` store once SyncEngine actually pushes it successfully — sync
    // itself only runs opportunistically (apps/web/src/App.tsx's `online`
    // handler), so a device that is never observed transitioning
    // offline->online never pushes at all. Without VaultSession overlaying
    // still-queued mutations on unlock, a freshly created item would look
    // silently lost on the next unlock/relaunch even though its ciphertext
    // was safely persisted in the queue the whole time.
    await init();
    const client = new CryptoWorkerClient(new FakeWorker(await createWasmBackend()) as unknown as Worker);
    const password = new Uint8Array([1, 2, 3, 4]);
    const setupResult = await client.createAccountSetup({
      password, reportedPhysicalMemoryKiB: 262_144n, accountId: "acct_relaunch", vaultId: "vault_relaunch", itemId: "vault-key",
    });
    const bundle: AccountBundle = {
      accountId: setupResult.accountId, vaultId: setupResult.vaultId, itemId: setupResult.itemId,
      kdfParametersCbor: setupResult.kdfParametersCbor, wrappedAccountKey: setupResult.wrappedAccountKey,
      wrappedVaultKey: setupResult.wrappedVaultKey, wrappedItemKey: setupResult.wrappedItemKey,
      wrappedRecoveryKey: setupResult.wrappedRecoveryKey,
    };
    const repo = new InMemoryLocalRepository(); // shared across both "app runs" below, like a real persistent IndexedDB would be
    const api = new ApiClient({ baseUrl: "http://vault.test.invalid", fetchImpl: (() => { throw new Error("network unused in this test"); }) as unknown as typeof fetch });

    const firstRun = new VaultSession(client, repo, new SyncEngine(api, repo));
    await firstRun.unlockWithPassword(bundle, password.slice());
    const id = await firstRun.saveItem({ type: "note", title: "Never synced", notes: "still here?" });
    expect(firstRun.list().map((e) => e.title)).toEqual(["Never synced"]); // visible in-session, optimistically
    await firstRun.lock(); // simulates the app closing with the mutation still only in the queue

    const secondRun = new VaultSession(client, repo, new SyncEngine(api, repo));
    await secondRun.unlockWithPassword(bundle, password.slice());
    expect(secondRun.list().map((e) => e.title)).toEqual(["Never synced"]);
    expect(secondRun.getItemData(id)?.notes).toBe("still here?");
  });

  test("search matches title, username, and url case-insensitively", async () => {
    const { session } = await setup();
    await session.saveItem({ type: "login", title: "GitHub", username: "octocat", url: "https://github.com" });
    await session.saveItem({ type: "note", title: "Wifi password" });
    expect(session.search("github").map((e) => e.title)).toEqual(["GitHub"]);
    expect(session.search("octo").map((e) => e.title)).toEqual(["GitHub"]);
    expect(session.search("wifi").map((e) => e.title)).toEqual(["Wifi password"]);
    expect(session.search("nomatch")).toEqual([]);
  });
});

describe("VaultSession clipboard hygiene (T15)", () => {
  test("copying schedules a clear, and lock clears the timer and the clipboard immediately", async () => {
    const writes: string[] = [];
    const original = (globalThis as any).navigator?.clipboard;
    Object.defineProperty(globalThis.navigator, "clipboard", {
      value: { writeText: async (text: string) => { writes.push(text); } },
      configurable: true,
    });
    try {
      const { session } = await setup();
      await session.copyToClipboard("hunter2");
      expect(writes).toEqual(["hunter2"]);
      await session.lock(); // must clear the clipboard immediately, not wait CLIPBOARD_CLEAR_MS
      expect(writes[writes.length - 1]).toBe("");
    } finally {
      if (original) Object.defineProperty(globalThis.navigator, "clipboard", { value: original, configurable: true });
    }
  });
});

void CLIPBOARD_CLEAR_MS;
