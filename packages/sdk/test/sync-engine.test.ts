import { expect, test } from "bun:test";
import { ApiClient } from "../src/http-client.ts";
import { InMemoryLocalRepository } from "../src/repository.ts";
import { SyncEngine, retryDelayMs } from "../src/sync-state-machine.ts";
import type { ItemRecord, Mutation } from "../src/types.ts";

function mutation(overrides: Partial<Mutation> = {}): Mutation {
  return {
    mutationId: "m1",
    itemId: "i1",
    vaultId: "v1",
    baseRevision: 0,
    ciphertext: "b64:AAAA",
    envelopeVersion: "crypto-envelope/v1",
    deleted: false,
    ...overrides,
  };
}

function itemRecord(overrides: Partial<ItemRecord> = {}): ItemRecord {
  return {
    itemId: "i1",
    vaultId: "v1",
    ciphertext: "b64:AAAA",
    envelopeVersion: "crypto-envelope/v1",
    revision: 1,
    deleted: false,
    createdAt: "2030-01-01T00:00:00Z",
    updatedAt: "2030-01-01T00:00:00Z",
    ...overrides,
  };
}

/** Scripted fetch: `responses` is consumed in order, one per call; a
 * `"network-error"` entry rejects the way a real offline fetch would. */
function scriptedFetch(responses: Array<{ status: number; body: unknown } | "network-error">): typeof fetch {
  let i = 0;
  return (async () => {
    const next = responses[Math.min(i, responses.length - 1)];
    i += 1;
    if (next === "network-error") throw new Error("simulated offline");
    return new Response(JSON.stringify(next.body), { status: next.status });
  }) as typeof fetch;
}

test("LOCAL_DIRTY --mutate--> SYNCING --201--> LOCAL_CLEAN: applies the item and dequeues the mutation", async () => {
  const repo = new InMemoryLocalRepository();
  const api = new ApiClient({ baseUrl: "https://x", fetchImpl: scriptedFetch([{ status: 201, body: itemRecord() }]) });
  api.setAccessToken("t");
  const engine = new SyncEngine(api, repo);

  await engine.enqueueEdit(mutation());
  const outcomes = await engine.pushAll();
  expect(outcomes.get("m1")?.kind).toBe("applied");
  expect(await repo.getQueuedMutation("m1")).toBeNull();
  expect(await repo.getItem("v1", "i1")).toEqual(itemRecord());
});

test("offline queue: a mutation made while offline survives and is not dropped", async () => {
  const repo = new InMemoryLocalRepository();
  const api = new ApiClient({ baseUrl: "https://x", fetchImpl: scriptedFetch(["network-error"]) });
  api.setAccessToken("t");
  const engine = new SyncEngine(api, repo);

  await engine.enqueueEdit(mutation());
  const outcomes = await engine.pushAll();
  expect(outcomes.get("m1")?.kind).toBe("retryable");
  const queued = await repo.getQueuedMutation("m1");
  expect(queued?.state).toBe("RETRYABLE");
  expect(queued?.mutation.mutationId).toBe("m1"); // survived, not dropped
});

test("SYNCING --network error--> RETRYABLE --retry--> SYNCING: replaying reuses the same mutationId and eventually succeeds", async () => {
  const repo = new InMemoryLocalRepository();
  const api = new ApiClient({
    baseUrl: "https://x",
    fetchImpl: scriptedFetch(["network-error", { status: 201, body: itemRecord() }]),
  });
  api.setAccessToken("t");
  const engine = new SyncEngine(api, repo, { baseMs: 1, maxMs: 5 });

  await engine.enqueueEdit(mutation());
  const first = await engine.pushAll();
  expect(first.get("m1")?.kind).toBe("retryable");

  // Reconnect: retry past the (tiny, test-configured) backoff window.
  const queued = await repo.getQueuedMutation("m1");
  const second = await engine.pushAll((queued!.nextRetryAt ?? 0) + 1);
  expect(second.get("m1")?.kind).toBe("applied");
  expect(await repo.getQueuedMutation("m1")).toBeNull();
});

test("pushAll skips a RETRYABLE mutation still inside its backoff window", async () => {
  const repo = new InMemoryLocalRepository();
  const api = new ApiClient({ baseUrl: "https://x", fetchImpl: scriptedFetch(["network-error"]) });
  api.setAccessToken("t");
  const engine = new SyncEngine(api, repo, { baseMs: 60_000, maxMs: 600_000 });

  await engine.enqueueEdit(mutation());
  await engine.pushAll();
  // Immediately retrying (same "now") must not re-attempt yet.
  const second = await engine.pushAll();
  expect(second.size).toBe(0);
});

test("retryDelayMs grows exponentially and is capped at maxMs", () => {
  const opts = { baseMs: 100, maxMs: 1000 };
  expect(retryDelayMs(1, opts)).toBe(100);
  expect(retryDelayMs(2, opts)).toBe(200);
  expect(retryDelayMs(3, opts)).toBe(400);
  expect(retryDelayMs(10, opts)).toBe(1000); // capped
});

test("SYNCING --409--> CONFLICT: produces a Conflict object rather than silently overwriting local state", async () => {
  const repo = new InMemoryLocalRepository();
  const conflictBody = {
    error: "conflict" as const,
    mutationId: "m1",
    current: itemRecord({ revision: 5, ciphertext: "b64:ZZZZ" }),
    attempted: mutation(),
  };
  const api = new ApiClient({ baseUrl: "https://x", fetchImpl: scriptedFetch([{ status: 409, body: conflictBody }]) });
  api.setAccessToken("t");
  const engine = new SyncEngine(api, repo);

  await engine.enqueueEdit(mutation());
  const outcomes = await engine.pushAll();
  const outcome = outcomes.get("m1");
  expect(outcome?.kind).toBe("conflict");
  if (outcome?.kind === "conflict") {
    expect(outcome.conflict.current.revision).toBe(5);
    expect(outcome.conflict.attempted.mutationId).toBe("m1");
  }
  // The local item store is untouched: no silent overwrite happened.
  expect(await repo.getItem("v1", "i1")).toBeNull();
  const queued = await repo.getQueuedMutation("m1");
  expect(queued?.state).toBe("CONFLICT");
});

test("pushAll does not re-attempt a mutation already parked in CONFLICT", async () => {
  const repo = new InMemoryLocalRepository();
  let calls = 0;
  const api = new ApiClient({
    baseUrl: "https://x",
    fetchImpl: (async () => {
      calls += 1;
      return new Response(
        JSON.stringify({ error: "conflict", mutationId: "m1", current: itemRecord(), attempted: mutation() }),
        { status: 409 },
      );
    }) as typeof fetch,
  });
  api.setAccessToken("t");
  const engine = new SyncEngine(api, repo);
  await engine.enqueueEdit(mutation());
  await engine.pushAll();
  expect(calls).toBe(1);
  await engine.pushAll();
  expect(calls).toBe(1); // still parked, no second network call
});

test("resolveConflict: CONFLICT --client decrypt+resolve--> LOCAL_DIRTY as a new mutation", async () => {
  const repo = new InMemoryLocalRepository();
  await repo.enqueueMutation({ mutation: mutation(), state: "CONFLICT", attempts: 1 });
  const engine = new SyncEngine(new ApiClient({ baseUrl: "https://x" }), repo);

  const resolved = mutation({ mutationId: "m2", baseRevision: 5 });
  await engine.resolveConflict("m1", resolved);

  expect(await repo.getQueuedMutation("m1")).toBeNull();
  const entry = await repo.getQueuedMutation("m2");
  expect(entry?.state).toBe("LOCAL_DIRTY");
  expect(entry?.mutation.baseRevision).toBe(5);
});

test("LOCAL_CLEAN --pull--> APPLYING --page valid--> LOCAL_CLEAN: applies items and advances the cursor only after", async () => {
  const repo = new InMemoryLocalRepository();
  const api = new ApiClient({
    baseUrl: "https://x",
    fetchImpl: scriptedFetch([{ status: 200, body: { changes: [itemRecord()], nextCursor: "cursor-1" } }]),
  });
  api.setAccessToken("t");
  const engine = new SyncEngine(api, repo);

  expect(await repo.getCursor("v1")).toBeNull();
  const outcome = await engine.pull("v1");
  expect(outcome.kind).toBe("applied");
  expect(await repo.getItem("v1", "i1")).toEqual(itemRecord());
  expect(await repo.getCursor("v1")).toBe("cursor-1");
});

test("pull stops once the server repeats the same cursor with no new changes", async () => {
  const repo = new InMemoryLocalRepository();
  const api = new ApiClient({
    baseUrl: "https://x",
    fetchImpl: scriptedFetch([
      { status: 200, body: { changes: [itemRecord()], nextCursor: "c1" } },
      { status: 200, body: { changes: [], nextCursor: "c1" } },
    ]),
  });
  api.setAccessToken("t");
  const engine = new SyncEngine(api, repo);
  const outcome = await engine.pull("v1");
  expect(outcome.kind).toBe("applied");
  // Two fetches happen: the page with the real change, then the trailing
  // page confirming there's nothing further (nextCursor repeats "c1").
  if (outcome.kind === "applied") expect(outcome.pagesApplied).toBe(2);
});

test("APPLYING --page invalid--> ERROR: a failing page never advances the cursor past it", async () => {
  const repo = new InMemoryLocalRepository();
  const failingRepo: typeof repo = Object.assign(Object.create(Object.getPrototypeOf(repo)), repo, {
    async putItem() {
      throw new Error("simulated durable-write failure");
    },
  });
  const api = new ApiClient({
    baseUrl: "https://x",
    fetchImpl: scriptedFetch([{ status: 200, body: { changes: [itemRecord()], nextCursor: "c1" } }]),
  });
  api.setAccessToken("t");
  const engine = new SyncEngine(api, failingRepo);
  const outcome = await engine.pull("v1");
  expect(outcome.kind).toBe("error");
  expect(await repo.getCursor("v1")).toBeNull(); // untouched
});
