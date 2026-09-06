#!/usr/bin/env bun
// D02-MVP real-backend integration fixture: a long-lived Bun subprocess
// that Kotlin's `VaultManagerRealBackendIntegrationTest` (JVM, run via
// `./gradlew :app:test`) drives, exactly the way
// `apps/extension/test/vault-manager.integration.test.ts` drives the same
// real backend/real PostgreSQL/real HTTPS fixture in-process from Bun.
// Kotlin cannot import `packages/sdk`/`packages/crypto-worker` directly, so
// this script performs the two things this task's Android crypto-ffi
// deliberately does *not* implement (OPAQUE *registration* and hierarchy
// *creation* — onboarding is out of scope for this MVP, see
// docs/tasks/D02-MVP.md) using only already-approved, already-used-by-C04
// primitives (`packages/sdk`, `packages/crypto-worker`'s WASM adapter,
// `tests/browser/https-fixture.mjs`, and `pg` for the direct
// ciphertext-only database check) — never `apps/web` or any other
// forbidden path. Every actual *unlock/list/save/TOTP* assertion happens
// in Kotlin, against the real crypto-ffi JNI build; this script only sets
// up and tears down the fixture and performs the plaintext-leak DB check
// and the second-client device revoke, which Kotlin has no other way to
// drive without a Postgres JDBC driver or a Node dependency of its own
// (neither of which this task adds).
//
// Protocol: reads one JSON array from argv[2] (`{id, password}` account
// requests) at startup. For each, registers + creates a hierarchy +
// publishes a key bundle, then prints one JSON line
// {"accountId","vaultId","itemId","password","baseUrl"} per account, then a
// final {"controlUrl": "http://127.0.0.1:PORT"} line. Kotlin then talks to
// that loopback HTTP control server with POST / bodies:
//   {"cmd":"verify_no_plaintext","vaultId":..,"markers":[...]}
//     -> {"ok":true|false,"reason"?:string}
//   {"cmd":"revoke_device","accountId":..,"password":..,"deviceName":..}
//     -> {"ok":true|false,"reason"?:string}
// Teardown is just the JVM forcibly destroying this process (see
// IntegrationFixtureProcess.kt's close() doc comment) — no explicit "exit"
// command. A plain loopback HTTP server replaces an earlier stdin/stdout
// line-protocol design: reading Node's `process.stdin` via `readline`
// proved unreliable once a real external client (OkHttp/the JVM) also had
// live traffic in flight against this same process's HTTPS fixture —
// commands sent over stdin would stall indefinitely for no reason visible
// at the Postgres or OS level. A dedicated loopback HTTP socket is a
// completely standard, unambiguous IPC channel with none of that risk.
import { randomUUID } from "node:crypto";
import http from "node:http";
import { ApiClient, AuthClient, buildAccountBundle, createWasmOpaqueClient } from "../../../packages/sdk/src/index.ts";
import { CryptoWorkerHost } from "../../../packages/crypto-worker/src/index.ts";
import { createWasmBackend } from "../../../packages/crypto-worker/src/wasm-adapter.ts";
import { startHttpsFixture } from "../../../tests/browser/https-fixture.mjs";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // see https-fixture.mjs's self-signed cert note

async function provisionAccount(baseUrl, id, password) {
  const accountId = `acct-${id}-${randomUUID()}`;
  const vaultId = `vault-${id}-${randomUUID()}`;
  const wrapItemId = `wrap-${id}-${randomUUID()}`;
  const passwordBytes = new TextEncoder().encode(password);

  const provisioningApi = new ApiClient({ baseUrl });
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

  const publishApi = new ApiClient({ baseUrl });
  const publishAuth = new AuthClient(publishApi, await createWasmOpaqueClient());
  await publishAuth.login(accountId, passwordBytes.slice());
  const published = await publishApi.putKeyBundle({ bundle: bundleWire, version: 1 });
  if (published.status !== 204) throw new Error(`key-bundle publish failed: ${JSON.stringify(published)}`);

  return { accountId, vaultId, itemId: setup.itemId, password, baseUrl };
}

async function handleCommand(cmd, { databaseUrl, fixture }) {
  if (cmd.cmd === "verify_no_plaintext") {
    const { Client } = await import("pg");
    const client = new Client({ connectionString: databaseUrl });
    await client.connect();
    try {
      const { rows } = await client.query("SELECT ciphertext FROM vault_items WHERE vault_id = $1", [cmd.vaultId]);
      if (rows.length === 0) return { ok: false, reason: "no rows found for vaultId" };
      let leaked = null;
      for (const row of rows) {
        for (const marker of cmd.markers ?? []) {
          if (String(row.ciphertext).includes(marker)) leaked = marker;
        }
      }
      return leaked ? { ok: false, reason: `plaintext marker leaked: ${leaked}` } : { ok: true };
    } finally {
      await client.end();
    }
  }
  if (cmd.cmd === "revoke_device") {
    const api = new ApiClient({ baseUrl: fixture.url });
    const auth = new AuthClient(api, await createWasmOpaqueClient());
    await auth.login(cmd.accountId, new TextEncoder().encode(cmd.password));
    const devices = await api.listDevices();
    const target = devices.find((d) => d.name === cmd.deviceName);
    if (!target) return { ok: false, reason: "device not found" };
    await api.revokeDevice(target.deviceId);
    return { ok: true };
  }
  return { ok: false, reason: `unknown cmd ${cmd.cmd}` };
}

async function main() {
  const databaseUrl = process.env.TEST_DATABASE_URL;
  if (!databaseUrl) {
    console.error("TEST_DATABASE_URL is required");
    process.exit(2);
  }
  const requests = JSON.parse(process.argv[2] ?? "[]");
  const fixture = await startHttpsFixture({ databaseUrl });

  for (const { id, password } of requests) {
    const provisioned = await provisionAccount(fixture.url, id, password);
    console.log(JSON.stringify(provisioned));
  }

  const controlServer = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", async () => {
      let cmd;
      try {
        cmd = JSON.parse(Buffer.concat(chunks).toString("utf-8"));
      } catch {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, reason: "invalid command JSON" }));
        return;
      }
      let result;
      try {
        result = await handleCommand(cmd, { databaseUrl, fixture });
      } catch (error) {
        result = { ok: false, reason: String(error && error.message ? error.message : error) };
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(result));
    });
  });
  await new Promise((resolve, reject) => {
    controlServer.once("error", reject);
    controlServer.listen(0, "127.0.0.1", resolve);
  });
  const controlPort = controlServer.address().port;
  console.log(JSON.stringify({ controlUrl: `http://127.0.0.1:${controlPort}` }));
  console.log("READY");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
