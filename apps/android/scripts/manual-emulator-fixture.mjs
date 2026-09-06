#!/usr/bin/env bun
// D02-MVP manual on-emulator evidence run helper: starts one real backend +
// real HTTPS front + one provisioned test account, prints the details
// needed to drive the actual Android app UI against it, and stays alive
// until killed (Ctrl+C).
//
// Unlike apps/android/scripts/integration-fixture.mjs (which reuses
// tests/browser/https-fixture.mjs's freshly-generated-per-run self-signed
// certificate — fine for a JVM test that also controls its own HTTP
// client's trust store), this script fronts the same real backend
// (apps/backend/src/app.mjs's buildApp, real PostgreSQL) with a FIXED,
// checked-in self-signed certificate
// (apps/android/demo-fixture/demo-cert.pem/-key.pem, 127.0.0.1-only,
// throwaway, private key never shipped in the app). The Android app
// itself cannot be told to trust an arbitrary freshly-generated cert at
// runtime; its debug-only network security config
// (app/src/main/res/xml/network_security_config.xml) instead pins this
// one fixed certificate via `@raw/demo_ca`, so a real on-device TLS
// handshake succeeds without any on-device "install a CA certificate"
// step (which requires a device credential and, on this API level's
// scoped storage, could not even read a pushed file — see this task's
// completion report for what was tried).
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import https from "node:https";
import http from "node:http";
import { ApiClient, AuthClient, buildAccountBundle, createWasmOpaqueClient } from "../../../packages/sdk/src/index.ts";
import { CryptoWorkerHost } from "../../../packages/crypto-worker/src/index.ts";
import { createWasmBackend } from "../../../packages/crypto-worker/src/wasm-adapter.ts";
import { buildApp } from "../../backend/src/app.mjs";
import { createPool } from "../../backend/src/db.mjs";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // this script's own provisioning calls also hit the fixed self-signed cert below

const scriptDir = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(scriptDir, "..", "demo-fixture");

async function startFixedCertHttpsFixture({ databaseUrl }) {
  const key = readFileSync(join(fixtureDir, "demo-key.pem"));
  const cert = readFileSync(join(fixtureDir, "demo-cert.pem"));

  const pool = createPool({ databaseUrl, databaseSsl: false });
  const config = Object.freeze({
    nodeEnv: "test",
    logLevel: "silent",
    requestIdHeader: "x-request-id",
    opaqueServerSetup: null,
    sessionTtlSeconds: 900,
    authRateLimitMax: 1000,
    authRateLimitWindowSeconds: 300,
  });
  const app = buildApp(config, { pool });
  // Fixed port (not 0/ephemeral): the Android app's `adb reverse` mapping
  // and the operator's typed-in API origin both need a stable, predictable
  // port across runs of this manual/demo script.
  const httpPort = 8443 + 1000; // 9443, arbitrary fixed loopback port for the plain-HTTP backend
  const httpsPort = 8443;
  await app.listen({ port: httpPort, host: "127.0.0.1" });

  const proxy = https.createServer({ key, cert }, (req, res) => {
    const upstream = http.request(
      { host: "127.0.0.1", port: httpPort, path: req.url, method: req.method, headers: req.headers },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
        upstreamRes.pipe(res);
      },
    );
    upstream.on("error", () => {
      res.writeHead(502);
      res.end();
    });
    req.pipe(upstream);
  });
  await new Promise((resolve, reject) => {
    proxy.once("error", reject);
    proxy.listen(httpsPort, "127.0.0.1", resolve);
  });

  return {
    url: `https://127.0.0.1:${httpsPort}`,
    async close() {
      await new Promise((r) => proxy.close(r));
      await app.close();
    },
  };
}

async function main() {
  const databaseUrl = process.env.TEST_DATABASE_URL;
  if (!databaseUrl) throw new Error("TEST_DATABASE_URL is required");

  const fixture = await startFixedCertHttpsFixture({ databaseUrl });
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

  console.log(JSON.stringify({ accountId, vaultId, password, baseUrl: fixture.url }, null, 2));
  console.log("Fixture is running with a FIXED, checked-in demo certificate (safe to `adb reverse` its port).");
  console.log("Press Ctrl+C to stop.");

  process.on("SIGINT", async () => {
    await fixture.close();
    process.exit(0);
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
