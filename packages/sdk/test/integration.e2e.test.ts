import { expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { buildApp } from "../../../apps/backend/src/app.mjs";
import { createPool } from "../../../apps/backend/src/db.mjs";
import { ApiClient } from "../src/http-client.ts";
import { AuthClient } from "../src/auth-client.ts";
import { createWasmOpaqueClient } from "../src/opaque-client.ts";
import { InMemoryLocalRepository } from "../src/repository.ts";
import { SyncEngine } from "../src/sync-state-machine.ts";

// End-to-end: this is the one test in the SDK's suite that drives a real
// backend (apps/backend, per B05) with a real WASM OPAQUE client
// (packages/crypto-wasm, ADR-0007) over real HTTP, rather than a fake
// OpaqueClient/fetch. Everything else in this package's test suite is
// unit-level by design (fast, deterministic); this test is the contract
// test proving the whole stack actually agrees on wire shapes.
//
// Skipped (not failed) without a database, matching every other
// integration test in this repo (see apps/backend/test/*).
const databaseUrl = process.env.TEST_DATABASE_URL;
const integrationTest = databaseUrl ? test : test.skip;

const config = Object.freeze({
  nodeEnv: "test",
  logLevel: "silent",
  requestIdHeader: "x-request-id",
  opaqueServerSetup: null,
  sessionTtlSeconds: 900,
  authRateLimitMax: 1000,
  authRateLimitWindowSeconds: 300,
});

async function withServer(fn: (baseUrl: string, pool: unknown) => Promise<void>) {
  const pool = createPool({ databaseUrl, databaseSsl: false });
  const app = buildApp(config, { pool });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  const baseUrl = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
  try {
    await fn(baseUrl, pool);
  } finally {
    await app.close();
  }
}

integrationTest(
  "SDK end-to-end: register, login, register device, mutate an item, and pull it back through the sync engine",
  async () => {
    await withServer(async (baseUrl) => {
      const accountId = `acct-${randomUUID()}`;
      const password = new TextEncoder().encode("CorrectHorseBatteryStaple");

      const api = new ApiClient({ baseUrl });
      const opaque = await createWasmOpaqueClient();
      const auth = new AuthClient(api, opaque);

      await auth.register(accountId, password);
      const session = await auth.login(accountId, password);
      expect(session.accessToken.length).toBeGreaterThan(0);
      expect(api.getAccessToken()).toBe(session.accessToken);

      const device = await api.registerDevice("Test device", new Uint8Array([1, 2, 3, 4]));
      expect(device.deviceId.length).toBeGreaterThan(0);

      const devices = await api.listDevices();
      expect(devices.some((d) => d.deviceId === device.deviceId)).toBe(true);

      // The SDK-level SyncEngine drives the actual mutate + pull, proving
      // the offline queue / cursor-advance machinery works against a real
      // server, not just a scripted fake.
      const repo = new InMemoryLocalRepository();
      const engine = new SyncEngine(api, repo);
      const vaultId = `vault-${randomUUID()}`;
      const itemId = `item-${randomUUID()}`;
      const ciphertext = "b64:" + Buffer.from("real-ciphertext-bytes").toString("base64");

      await engine.enqueueEdit({
        mutationId: `mut-${randomUUID()}`,
        itemId,
        vaultId,
        baseRevision: 0,
        ciphertext,
        envelopeVersion: "crypto-envelope/v1",
        deleted: false,
      });
      const pushOutcomes = await engine.pushAll();
      expect(pushOutcomes.size).toBe(1);
      const [outcome] = [...pushOutcomes.values()];
      expect(outcome.kind).toBe("applied");

      const pullOutcome = await engine.pull(vaultId);
      expect(pullOutcome.kind).toBe("applied");
      const stored = await repo.getItem(vaultId, itemId);
      expect(stored?.ciphertext).toBe(ciphertext);
      expect(stored?.revision).toBe(1);
    });
  },
);

integrationTest("a stale baseRevision mutation surfaces as a Conflict object, not a thrown error or silent overwrite", async () => {
  await withServer(async (baseUrl) => {
    const accountId = `acct-${randomUUID()}`;
    const password = new TextEncoder().encode("CorrectHorseBatteryStaple");
    const api = new ApiClient({ baseUrl });
    const auth = new AuthClient(api, await createWasmOpaqueClient());
    await auth.register(accountId, password);
    await auth.login(accountId, password);

    const repo = new InMemoryLocalRepository();
    const engine = new SyncEngine(api, repo);
    const vaultId = `vault-${randomUUID()}`;
    const itemId = `item-${randomUUID()}`;

    await engine.enqueueEdit({
      mutationId: `mut-${randomUUID()}`,
      itemId,
      vaultId,
      baseRevision: 0,
      ciphertext: "b64:AAAA",
      envelopeVersion: "crypto-envelope/v1",
      deleted: false,
    });
    await engine.pushAll();

    // Second mutation against the same item, still claiming baseRevision 0
    // (stale — the first mutation already advanced it to 1).
    await engine.enqueueEdit({
      mutationId: `mut-${randomUUID()}`,
      itemId,
      vaultId,
      baseRevision: 0,
      ciphertext: "b64:AAAB",
      envelopeVersion: "crypto-envelope/v1",
      deleted: false,
    });
    const outcomes = await engine.pushAll();
    const conflictOutcome = [...outcomes.values()].find((o) => o.kind === "conflict");
    expect(conflictOutcome).toBeDefined();
    if (conflictOutcome?.kind === "conflict") {
      expect(conflictOutcome.conflict.current.revision).toBe(1);
    }
  });
});
