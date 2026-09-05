import { describe, expect, test } from "bun:test";
import init from "crypto-wasm";
import { CryptoWorkerHost, type CryptoBackend } from "../../../packages/crypto-worker/src/index.ts";
import { createWasmBackend } from "../../../packages/crypto-worker/src/wasm-adapter.ts";
import { ApiClient, InMemoryLocalRepository, SyncEngine } from "@zkpm/sdk";
import { CryptoWorkerClient } from "../src/crypto/worker-client.ts";
import { VaultSession, CLIPBOARD_CLEAR_MS } from "../src/vault/vault-session.ts";
import type { AccountBundle } from "../src/vault/account-bundle.ts";
import { encodeItemData } from "../src/vault/item-codec.ts";

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

/** A controllable promise: lets a test suspend a crypto/sync double
 * mid-call, drive `lock()` (or a second unlock) while the original
 * operation is still "in flight", then resume it deterministically —
 * the repro shape for SEC-05 (GitHub issue #5). */
function createDeferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => { resolve = res; });
  return { promise, resolve };
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

describe("VaultSession generation-guarded plaintext cache (SEC-05 / GitHub issue #5)", () => {
  test("lock() completing before an in-flight saveItem resolves leaves the plaintext cache empty, but still durably enqueues the ciphertext mutation", async () => {
    const { client, session } = await setup();
    const gate = createDeferred<Uint8Array>();
    let sealArgs: Parameters<typeof client.sealItemPayload> | null = null;
    // Fakes the encrypt result rather than delaying-then-replaying the
    // real crypto call: the real Worker's `lock()` (which this test
    // exercises mid-flight) invalidates every open session host-side, so
    // re-invoking the real sealItemPayload with the now-stale session
    // number after `session.lock()` would just throw "Locked" — a fact
    // about the crypto worker's own session bookkeeping, not about the
    // generation guard this test is actually verifying.
    client.sealItemPayload = (async (...args: Parameters<typeof client.sealItemPayload>) => {
      sealArgs = args;
      return gate.promise;
    }) as typeof client.sealItemPayload;

    const savePromise = session.saveItem({ type: "login", title: "Slow save", username: "alice", password: "hunter2" });
    // Let saveItem run up to (and suspend on) its await of sealItemPayload.
    await Promise.resolve();
    await Promise.resolve();
    expect(sealArgs).not.toBeNull();

    // lock() must win the race: it does not wait for the in-flight save.
    await session.lock();
    expect(session.debugMemoryState()).toEqual({ itemCacheSize: 0, searchEntries: 0, selectedItemId: null, unlocked: false });

    // Now let the slow crypto call resolve (as if it finished just after
    // lock()) and let saveItem run to completion.
    gate.resolve(new Uint8Array([1, 2, 3, 4]));
    const id = await savePromise;

    // The plaintext cache must still be empty — saveItem must not have
    // repopulated it after noticing the session generation moved on.
    expect(session.debugMemoryState()).toEqual({ itemCacheSize: 0, searchEntries: 0, selectedItemId: null, unlocked: false });

    // But the encrypted mutation itself must not have been silently
    // dropped: it was durably enqueued before the generation even could
    // have been checked, so it must still be sitting in the local queue
    // (ciphertext only) ready to sync whenever a session unlocks again.
    const repo = (session as unknown as { repo: InMemoryLocalRepository }).repo;
    const queued = await repo.listQueuedMutations();
    expect(queued.some((q) => q.mutation.itemId === id)).toBe(true);
  });

  test("lock() completing before an in-flight resolveConflict resolves leaves the plaintext cache empty", async () => {
    const { client, bundle, session } = await setup();
    const itemId = crypto.randomUUID();
    const conflict = {
      mutationId: crypto.randomUUID(),
      current: {
        itemId, vaultId: bundle.vaultId, ciphertext: "", envelopeVersion: "crypto-envelope/v1",
        revision: 1, deleted: false, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
      },
      attempted: {
        mutationId: crypto.randomUUID(), itemId, vaultId: bundle.vaultId, baseRevision: 0,
        ciphertext: "", envelopeVersion: "crypto-envelope/v1", deleted: false,
      },
    } as Parameters<VaultSession["resolveConflict"]>[0];

    const gate = createDeferred<Uint8Array>();
    let sealArgs: Parameters<typeof client.sealItemPayload> | null = null;
    client.sealItemPayload = (async (...args: Parameters<typeof client.sealItemPayload>) => {
      sealArgs = args;
      return gate.promise;
    }) as typeof client.sealItemPayload;

    const resolvePromise = session.resolveConflict(conflict, { type: "note", title: "Resolved", notes: "x" });
    await Promise.resolve();
    await Promise.resolve();
    expect(sealArgs).not.toBeNull();

    await session.lock();
    expect(session.debugMemoryState().itemCacheSize).toBe(0);

    gate.resolve(new Uint8Array([5, 6, 7, 8]));
    await resolvePromise;

    expect(session.debugMemoryState()).toEqual({ itemCacheSize: 0, searchEntries: 0, selectedItemId: null, unlocked: false });
    expect(session.getItemData(itemId)).toBeNull();
  });

  test("a stale unlock's in-flight loadAllItemsIntoMemory never surfaces its account's data into a later, different session", async () => {
    await init();
    const client = new CryptoWorkerClient(new FakeWorker(await createWasmBackend()) as unknown as Worker);
    const passwordA = new Uint8Array([1, 1, 1, 1]);
    const setupA = await client.createAccountSetup({
      password: passwordA, reportedPhysicalMemoryKiB: 262_144n, accountId: "acct_A", vaultId: "vault_A", itemId: "vault-key",
    });
    const bundleA: AccountBundle = {
      accountId: setupA.accountId, vaultId: setupA.vaultId, itemId: setupA.itemId,
      kdfParametersCbor: setupA.kdfParametersCbor, wrappedAccountKey: setupA.wrappedAccountKey,
      wrappedVaultKey: setupA.wrappedVaultKey, wrappedItemKey: setupA.wrappedItemKey,
      wrappedRecoveryKey: setupA.wrappedRecoveryKey,
    };
    const passwordB = new Uint8Array([2, 2, 2, 2]);
    const setupB = await client.createAccountSetup({
      password: passwordB, reportedPhysicalMemoryKiB: 262_144n, accountId: "acct_B", vaultId: "vault_B", itemId: "vault-key",
    });
    const bundleB: AccountBundle = {
      accountId: setupB.accountId, vaultId: setupB.vaultId, itemId: setupB.itemId,
      kdfParametersCbor: setupB.kdfParametersCbor, wrappedAccountKey: setupB.wrappedAccountKey,
      wrappedVaultKey: setupB.wrappedVaultKey, wrappedItemKey: setupB.wrappedItemKey,
      wrappedRecoveryKey: setupB.wrappedRecoveryKey,
    };

    const repo = new InMemoryLocalRepository();
    const api = new ApiClient({ baseUrl: "http://vault.test.invalid", fetchImpl: (() => { throw new Error("network unused in this test"); }) as unknown as typeof fetch });

    // First establish account A has a real (durably queued) item, by
    // unlocking normally, saving, and locking again.
    const seedSession = new VaultSession(client, repo, new SyncEngine(api, repo));
    await seedSession.unlockWithPassword(bundleA, passwordA.slice());
    await seedSession.saveItem({ type: "note", title: "Account A secret", notes: "should never reach B" });
    await seedSession.lock();

    // Reuse a single VaultSession across the "stale unlock" and the
    // account switch, since the generation token lives on the instance.
    const session = new VaultSession(client, repo, new SyncEngine(api, repo));

    // Hook the decrypt call itself (not a fixed number of microtask
    // ticks) so this test is deterministic regardless of how many
    // internal awaits sit between unlockWithPassword() and the point
    // where account A's queued mutation gets decrypted: `invoked`
    // resolves exactly when that decrypt starts, and `resume` is what
    // lets it (deterministically) finish afterward. This replaces the
    // real crypto call entirely (rather than delaying then re-invoking
    // it) because the real Worker's `lock()` invalidates every open
    // session host-side — calling it again with A's now-stale session
    // number after the test's own `session.lock()` would just throw a
    // CryptoError, which loadAllItemsIntoMemory's existing catch already
    // swallows unconditionally either way. Faking the decrypt result
    // isolates what this test is actually about: the generation guard,
    // not the crypto worker's independent session invalidation.
    const invoked = createDeferred<void>();
    const resume = createDeferred<Uint8Array>();
    let hooked = true;
    client.openItemPayload = ((..._args: Parameters<typeof client.openItemPayload>) => {
      if (hooked) {
        hooked = false;
        invoked.resolve();
        return resume.promise;
      }
      throw new Error("unexpected second openItemPayload call in this test");
    }) as typeof client.openItemPayload;

    // Start re-unlocking account A; its loadAllItemsIntoMemory will reach
    // and suspend inside the hooked openItemPayload call while decrypting
    // "Account A secret" from the queued-mutations overlay.
    const staleUnlock = session.unlockWithPassword(bundleA, passwordA.slice());
    await invoked.promise;

    // Before the stale load resumes, lock and switch to a different
    // account entirely.
    await session.lock();
    await session.unlockWithPassword(bundleB, passwordB.slice());
    expect(session.list()).toEqual([]); // account B has no items

    // Now let account A's stale, suspended decrypt resume and finish —
    // as if it had actually succeeded, right after the switch to B.
    resume.resolve(encodeItemData({ type: "note", title: "Account A secret", notes: "should never reach B" }));
    await staleUnlock;

    // Account A's data must not have leaked into the now-current
    // account-B session.
    expect(session.accountBundle?.accountId).toBe(bundleB.accountId);
    expect(session.list()).toEqual([]);
    expect(session.debugMemoryState().itemCacheSize).toBe(0);
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
