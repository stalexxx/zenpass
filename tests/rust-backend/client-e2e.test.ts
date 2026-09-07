// RUST-04: real-client compatibility E2E against the actual compiled Rust
// backend binary (apps/backend-rust), not an in-process router call.
//
// This drives the exact SDK (packages/sdk) and exact WASM crypto module
// (packages/crypto-wasm) that apps/web, apps/extension and apps/desktop
// ship, over real HTTP, against a real spawned `zkpm-backend serve`
// process and a real disposable PostgreSQL database. It closes the gap
// RUST-03's report explicitly flagged: that task only proved native
// Rust-client-vs-Rust-server OPAQUE round trips; this proves the actual
// WASM-client-vs-Rust-server path a real browser/extension/desktop client
// would use.
//
// Covers: registration+login, device enrollment, key-bundle CAS, and the
// same two-device offline/reconnect/tombstone scenario as
// tests/e2e/two-device-offline-reconnect.test.ts (mirrored here against
// Rust instead of Bun) — i.e. "the existing web/extension/desktop-relevant
// user flows... as E2E against the Rust backend instead of Bun" from
// docs/tasks/RUST-04.md.
//
// Gated behind RUST04_E2E=1 + RUST04_TEST_DATABASE_URL so it never runs
// against a database by accident; requires apps/backend-rust to already be
// built (`cargo build --locked` from apps/backend-rust — see README).

import { expect, test } from "bun:test";
import { randomBytes, randomUUID } from "node:crypto";
import { ApiClient } from "../../packages/sdk/src/http-client.ts";
import { AuthClient } from "../../packages/sdk/src/auth-client.ts";
import { createWasmOpaqueClient } from "../../packages/sdk/src/opaque-client.ts";
import { InMemoryLocalRepository } from "../../packages/sdk/src/repository.ts";
import { SyncEngine } from "../../packages/sdk/src/sync-state-machine.ts";
import { buildAccountBundle } from "../../packages/sdk/src/account-bundle-codec.ts";
import { RUST04_E2E, TEST_DATABASE_URL, createScratchDatabase, freePort, migrate, spawnBackend } from "./helpers.ts";

const enabled = RUST04_E2E && !!TEST_DATABASE_URL;
const e2eTest = enabled ? test : test.skip;

if (RUST04_E2E && !TEST_DATABASE_URL) {
  test("RUST-04 client E2E configuration requires RUST04_TEST_DATABASE_URL", () => {
    throw new Error("RUST04_E2E=1 requires RUST04_TEST_DATABASE_URL; start a disposable PostgreSQL 16 container.");
  });
}

async function withRustBackend(fn: (baseUrl: string) => Promise<void>) {
  const db = await createScratchDatabase("clientE2E");
  await migrate(db.url);
  const port = await freePort();
  const backend = await spawnBackend(db.url, { port });
  try {
    await fn(backend.baseUrl);
  } finally {
    await backend.stop();
    await db.drop();
  }
}

e2eTest(
  "real WASM SDK client: register, login, device enrollment and key-bundle CAS against the real Rust binary",
  async () => {
    await withRustBackend(async (baseUrl) => {
      const accountId = `rust04-${randomUUID()}`;
      const password = randomBytes(32);
      const api = new ApiClient({ baseUrl });
      const auth = new AuthClient(api, await createWasmOpaqueClient());

      await auth.register(accountId, password);
      const session = await auth.login(accountId, password);
      expect(session.accessToken).toBeTruthy();

      const device = await api.registerDevice("RUST-04 device", new Uint8Array([9, 9, 9]));
      expect(device.deviceId).toBeTruthy();
      const devices = await api.listDevices();
      expect(devices.some((d) => d.deviceId === device.deviceId)).toBe(true);

      const before = await api.getKeyBundle();
      expect(before.status).toBe(404);

      const bundle = buildAccountBundle({
        accountId,
        vaultId: "vault-01",
        itemId: "item-01",
        kdfParametersCbor: new TextEncoder().encode("kdf-params"),
        wrappedAccountKey: new TextEncoder().encode("wrapped-account-key"),
        wrappedVaultKey: new TextEncoder().encode("wrapped-vault-key"),
        wrappedItemKey: new TextEncoder().encode("wrapped-item-key"),
        wrappedRecoveryKey: new TextEncoder().encode("wrapped-recovery-key"),
      });
      const created = await api.putKeyBundle({ bundle, version: 1 });
      expect(created.status).toBe(204);
      const fetched = await api.getKeyBundle();
      expect(fetched.status).toBe(200);
      if (fetched.status === 200) expect(fetched.keyBundle.bundle).toBe(bundle);
    });
  },
  30_000,
);

e2eTest(
  "two devices retain offline edits, reconnect without loss, and replay tombstones — against the real Rust binary",
  async () => {
    await withRustBackend(async (baseUrl) => {
      const accountId = `rust04-${randomUUID()}`;
      const password = randomBytes(32);

      const firstApi = new ApiClient({ baseUrl });
      const firstAuth = new AuthClient(firstApi, await createWasmOpaqueClient());
      await firstAuth.register(accountId, password);
      await firstAuth.login(accountId, password);
      await firstApi.registerDevice("RUST-04 device one", new Uint8Array([1, 2, 3]));

      const secondApi = new ApiClient({ baseUrl });
      const secondAuth = new AuthClient(secondApi, await createWasmOpaqueClient());
      await secondAuth.login(accountId, password);
      await secondApi.registerDevice("RUST-04 device two", new Uint8Array([4, 5, 6]));

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

      // Simulate offline transport, then reconnect and push.
      Object.defineProperty(firstApi, "fetchImpl", {
        value: () => Promise.reject(new TypeError("RUST-04 simulated offline transport")),
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
      expect([...(await second.pushAll()).values()][0]?.kind).toBe("applied");
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
      expect([...(await first.pushAll()).values()][0]?.kind).toBe("applied");
      await second.pull(vaultId);
      expect((await secondRepo.getItem(vaultId, firstItem))?.deleted).toBe(true);
    });
  },
  30_000,
);
