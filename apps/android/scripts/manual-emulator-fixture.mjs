#!/usr/bin/env bun
// D02-MVP manual on-emulator evidence run helper: starts one real backend +
// real HTTPS fixture + one provisioned test account (same machinery as
// integration-fixture.mjs), prints the details needed to drive the actual
// Android app UI against it, and then stays alive until killed (Ctrl+C).
import { randomUUID } from "node:crypto";
import { ApiClient, AuthClient, buildAccountBundle, createWasmOpaqueClient } from "../../../packages/sdk/src/index.ts";
import { CryptoWorkerHost } from "../../../packages/crypto-worker/src/index.ts";
import { createWasmBackend } from "../../../packages/crypto-worker/src/wasm-adapter.ts";
import { startHttpsFixture } from "../../../tests/browser/https-fixture.mjs";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

async function main() {
  const databaseUrl = process.env.TEST_DATABASE_URL;
  if (!databaseUrl) throw new Error("TEST_DATABASE_URL is required");

  const fixture = await startHttpsFixture({ databaseUrl });
  const accountId = `acct-manual-${randomUUID()}`;
  const vaultId = `vault-manual-${randomUUID()}`;
  const wrapItemId = `wrap-manual-${randomUUID()}`;
  const password = "CorrectHorseBatteryStaple1!";
  const passwordBytes = new TextEncoder().encode(password);

  const provisioningApi = new ApiClient({ baseUrl: fixture.url });
  const auth = new AuthClient(provisioningApi, await createWasmOpaqueClient());
  await auth.register(accountId, passwordBytes.slice());

  const backend = await createWasmBackend();
  const host = new CryptoWorkerHost(backend);
  const setupResponse = host.handle({
    id: "setup",
    type: "create-account-setup",
    password: passwordBytes.slice(),
    reportedPhysicalMemoryKiB: 262_144n,
    accountId,
    vaultId,
    itemId: wrapItemId,
  });
  if (!setupResponse.ok || setupResponse.type !== "account-setup") throw new Error("account setup failed");
  const setup = setupResponse.result;
  host.dispose();

  const bundleWire = buildAccountBundle({
    accountId: setup.accountId,
    vaultId: setup.vaultId,
    itemId: setup.itemId,
    kdfParametersCbor: setup.kdfParametersCbor,
    wrappedAccountKey: setup.wrappedAccountKey,
    wrappedVaultKey: setup.wrappedVaultKey,
    wrappedItemKey: setup.wrappedItemKey,
    wrappedRecoveryKey: setup.wrappedRecoveryKey,
  });

  const publishApi = new ApiClient({ baseUrl: fixture.url });
  const publishAuth = new AuthClient(publishApi, await createWasmOpaqueClient());
  await publishAuth.login(accountId, passwordBytes.slice());
  const published = await publishApi.putKeyBundle({ bundle: bundleWire, version: 1 });
  if (published.status !== 204) throw new Error(`key-bundle publish failed: ${JSON.stringify(published)}`);

  console.log(JSON.stringify({ accountId, vaultId, password, baseUrl: fixture.url, certPath: fixture.certPath }, null, 2));
  console.log("Fixture is running. Press Ctrl+C to stop.");

  process.on("SIGINT", async () => {
    await fixture.close();
    process.exit(0);
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
