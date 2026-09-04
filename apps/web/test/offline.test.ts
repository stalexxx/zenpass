import { describe, expect, test } from "bun:test";
import { ApiClient, AuthClient } from "@zkpm/sdk";
import { CryptoWorkerClient } from "../src/crypto/worker-client.ts";
import { IndexedDBLocalRepository } from "../src/db/indexeddb-repository.ts";
import { Announcer } from "../src/lib/announcer.ts";
import { createContext } from "../src/lib/context.ts";
import { createFakeFetch, createFakeCryptoWorker, fakeOpaqueClient } from "./helpers/fake-backend.ts";
import { generateTestBundle } from "./helpers/bundle.ts";
import init from "crypto-wasm";

async function buildOfflineCapableContext(offline: boolean) {
  await init();
  const announcer = new Announcer(document.body);
  const api = new ApiClient({ baseUrl: "http://vault.test.invalid", fetchImpl: createFakeFetch({ offline }) });
  const auth = new AuthClient(api, fakeOpaqueClient);
  const cryptoClient = new CryptoWorkerClient(await createFakeCryptoWorker());
  const repo = new IndexedDBLocalRepository(`offline-test-${crypto.randomUUID()}`);
  const ctx = createContext({ api, auth, crypto: cryptoClient, repo, announcer, navigate: () => {}, resetInactivityTimer: () => {} });
  return ctx;
}

describe("offline behavior", () => {
  test("saving while offline queues the mutation locally and keeps the item visible; pushAll reports RETRYABLE", async () => {
    const ctx = await buildOfflineCapableContext(true);
    const { bundle, password } = await generateTestBundle(ctx);
    await ctx.auth.login(bundle.accountId, password).catch(() => {}); // login itself is not gated by the offline sync routes in the fake

    const id = await ctx.vault.saveItem({ type: "note", title: "Offline note", notes: "hi" });
    expect(ctx.vault.getItemData(id)?.title).toBe("Offline note"); // still visible locally, optimistic

    const queued = await ctx.repo.listQueuedMutations();
    expect(queued).toHaveLength(1);
    expect(queued[0].state).toBe("LOCAL_DIRTY");

    const outcomes = await ctx.sync.pushAll();
    const [outcome] = [...outcomes.values()];
    expect(outcome.kind).toBe("retryable");

    const stillQueued = await ctx.repo.listQueuedMutations();
    expect(stillQueued[0].state).toBe("RETRYABLE");
    // The item is unaffected in the UI-facing view even though sync failed.
    expect(ctx.vault.getItemData(id)?.title).toBe("Offline note");
  });

  test("reconnecting and re-running pushAll applies the queued mutation and clears the queue", async () => {
    const ctx = await buildOfflineCapableContext(true);
    const { bundle, password } = await generateTestBundle(ctx);
    await ctx.auth.login(bundle.accountId, password).catch(() => {});
    const id = await ctx.vault.saveItem({ type: "note", title: "Will sync later" });
    await ctx.sync.pushAll(); // fails while offline, queued as RETRYABLE

    // Simulate "coming back online": swap the ApiClient's underlying fetch
    // to the online fake and re-run pushAll on the same SyncEngine — this
    // exercises exactly the RETRYABLE -> applied transition that apps/web's
    // `online` event handler (app.ts) drives in the real app.
    Object.defineProperty(ctx.api, "fetchImpl", { value: createFakeFetch({ offline: false }), writable: true });

    // Past the RETRYABLE entry's backoff window, so pushAll actually
    // retries it instead of skipping it.
    const outcomes = await ctx.sync.pushAll(Date.now() + 60_000);
    const [outcome] = [...outcomes.values()];
    expect(outcome.kind).toBe("applied");
    expect(await ctx.repo.listQueuedMutations()).toEqual([]);
    expect(ctx.vault.getItemData(id)?.title).toBe("Will sync later");
  });
});
