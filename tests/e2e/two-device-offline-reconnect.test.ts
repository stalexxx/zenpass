import { expect, test } from "bun:test";
import { randomBytes, randomUUID } from "node:crypto";
import { buildApp } from "../../apps/backend/src/app.mjs";
import { createPool } from "../../apps/backend/src/db.mjs";
import { ApiClient } from "../../packages/sdk/src/http-client.ts";
import { AuthClient } from "../../packages/sdk/src/auth-client.ts";
import { createWasmOpaqueClient } from "../../packages/sdk/src/opaque-client.ts";
import { InMemoryLocalRepository } from "../../packages/sdk/src/repository.ts";
import { SyncEngine } from "../../packages/sdk/src/sync-state-machine.ts";

const databaseUrl = process.env.TEST_DATABASE_URL;
const enabled = process.env.Q01_E2E === "1";
const e2eTest = enabled && databaseUrl ? test : test.skip;

const config = Object.freeze({
  nodeEnv: "test",
  logLevel: "silent",
  requestIdHeader: "x-request-id",
  opaqueServerSetup: null,
  sessionTtlSeconds: 900,
  authRateLimitMax: 1000,
  authRateLimitWindowSeconds: 300,
});

async function withServer(fn: (baseUrl: string) => Promise<void>) {
  const pool = createPool({ databaseUrl, databaseSsl: false });
  const app = buildApp(config, { pool });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await app.close();
  }
}

if (enabled && !databaseUrl) {
  test("Q01 E2E configuration requires TEST_DATABASE_URL", () => {
    throw new Error("Q01_E2E=1 requires TEST_DATABASE_URL; start PostgreSQL or remove the explicit Q01_E2E gate.");
  });
}

e2eTest("two devices retain offline edits, reconnect without loss, and replay tombstones", async () => {
  await withServer(async (baseUrl) => {
    const accountId = `q01-${randomUUID()}`;
    const password = randomBytes(32);
    const firstApi = new ApiClient({ baseUrl });
    const firstAuth = new AuthClient(firstApi, await createWasmOpaqueClient());
    await firstAuth.register(accountId, password);
    await firstAuth.login(accountId, password);
    await firstApi.registerDevice("Q01 device one", new Uint8Array([1, 2, 3]));

    const secondApi = new ApiClient({ baseUrl });
    const secondAuth = new AuthClient(secondApi, await createWasmOpaqueClient());
    await secondAuth.login(accountId, password);
    await secondApi.registerDevice("Q01 device two", new Uint8Array([4, 5, 6]));

    const firstRepo = new InMemoryLocalRepository();
    const secondRepo = new InMemoryLocalRepository();
    const first = new SyncEngine(firstApi, firstRepo);
    const second = new SyncEngine(secondApi, secondRepo);
    const vaultId = `vault-${randomUUID()}`;
    const firstItem = `item-${randomUUID()}`;
    const secondItem = `item-${randomUUID()}`;

    await first.enqueueEdit({
      mutationId: `mutation-${randomUUID()}`,
      itemId: firstItem,
      vaultId,
      baseRevision: 0,
      ciphertext: "b64:AAECAwQ=",
      envelopeVersion: "crypto-envelope/v1",
      deleted: false,
    });

    // The durable queue exists before a network attempt. Simulate the
    // transport being offline by replacing only this test client's fetch.
    Object.defineProperty(firstApi, "fetchImpl", {
      value: () => Promise.reject(new TypeError("Q01 simulated offline transport")),
      writable: true,
    });
    const offline = await first.pushAll();
    expect([...offline.values()][0]?.kind).toBe("retryable");
    expect((await firstRepo.listQueuedMutations()).length).toBe(1);

    Object.defineProperty(firstApi, "fetchImpl", { value: fetch, writable: true });
    const reconnected = await first.pushAll(Number.MAX_SAFE_INTEGER);
    expect([...reconnected.values()][0]?.kind).toBe("applied");
    expect((await firstRepo.listQueuedMutations()).length).toBe(0);

    await second.pull(vaultId);
    expect((await secondRepo.getItem(vaultId, firstItem))?.ciphertext).toBe("b64:AAECAwQ=");

    await second.enqueueEdit({
      mutationId: `mutation-${randomUUID()}`,
      itemId: secondItem,
      vaultId,
      baseRevision: 0,
      ciphertext: "b64:BQYHCAk=",
      envelopeVersion: "crypto-envelope/v1",
      deleted: false,
    });
    expect([...((await second.pushAll()).values())][0]?.kind).toBe("applied");
    await first.pull(vaultId);
    expect((await firstRepo.getItem(vaultId, secondItem))?.ciphertext).toBe("b64:BQYHCAk=");

    await first.enqueueEdit({
      mutationId: `mutation-${randomUUID()}`,
      itemId: firstItem,
      vaultId,
      baseRevision: 1,
      ciphertext: "b64:CgsMDQ4=",
      envelopeVersion: "crypto-envelope/v1",
      deleted: true,
    });
    expect([...((await first.pushAll()).values())][0]?.kind).toBe("applied");
    await second.pull(vaultId);
    expect((await secondRepo.getItem(vaultId, firstItem))?.deleted).toBe(true);
  });
}, 30_000);
