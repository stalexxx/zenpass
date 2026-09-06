// C04-EXT2 browser security evidence, extending
// tests/browser/c04-extension-e2e.mjs (kept separate so a failure/skip
// here never masks that file's own baseline evidence). Run with:
//   TEST_DATABASE_URL=postgres://pass:pass@127.0.0.1:5434/pass bun tests/browser/c04-extension-e2e-unlock.mjs
//
// Must run under `bun`, not plain `node` (see c04-extension-e2e.mjs's
// header comment: the real backend's OPAQUE WASM binding does a `fetch()`
// of a `file://` URL that only Bun's fetch supports).
//
// IMPORTANT — what this file can and cannot prove, discovered while
// building it: Playwright has no public API to open a real Chrome
// extension *action popup* (the surface `default_popup` renders); the
// documented technique of `context.newPage()` + `goto("chrome-extension://
// <id>/popup.html")` instead opens popup.html as an ordinary browser TAB.
// `apps/extension/src/popup.ts` runs identically either way, but the
// browser-provided `chrome.runtime.MessageSender` the background receives
// differs: a real action popup has no `sender.tab`, while a tab-opened
// copy always does. `packages/extension-adapters/src/sender.ts`'s
// `trustedPopupSender` — the ADR-0011 D3 "absence of content-tab sender"
// check — therefore (correctly, by design) treats every message from
// this harness's popup as untrusted, identically to a hostile page. This
// is not a bug: it is the trust boundary working as specified. It does
// mean this harness cannot drive a *trusted* popup unlock/save/TOTP round
// trip in a real browser; that would need a genuine action-popup surface
// (e.g. via `chrome.action.openPopup()` from a privileged automation
// context), which is out of this task's reach. What this file verifies
// instead: (a) the real backend/WASM/TLS stack accepts a real OPAQUE
// login and bundle fetch performed by the same SDK code the extension
// uses (not through the popup DOM — see
// apps/extension/test/vault-manager.integration.test.ts for the
// authoritative real-stack coverage of unlock/save/TOTP/revoke against
// ExtensionVaultManager directly), and (b) every one of this task's new
// popup message types (unlock, logout, list-items, save-item, get-totp)
// is uniformly refused as untrusted when sent from this tab-shaped
// sender in a real loaded extension — extending the original baseline's
// "locked popup" check to the full new message surface.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, promises as fs } from "node:fs";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { chromium } from "playwright";
import { opensslAvailable, startHttpsFixture } from "./https-fixture.mjs";
import { ApiClient, AuthClient, buildAccountBundle, createWasmOpaqueClient } from "../../packages/sdk/src/index.ts";
import { CryptoWorkerHost } from "../../packages/crypto-worker/src/index.ts";
import { createWasmBackend } from "../../packages/crypto-worker/src/wasm-adapter.ts";

const root = resolve(import.meta.dirname, "../..");
const chromeExtension = resolve(root, "apps/extension/dist/chrome");
const output = resolve(root, "output/playwright");
mkdirSync(output, { recursive: true });

const databaseUrl = process.env.TEST_DATABASE_URL;

// This harness's real-stack scenario exercises a genuine TLS handshake
// against https-fixture.mjs's freshly-generated, deliberately self-signed
// certificate (there is no CA to install one from in this environment).
// This is this script's own Node-side account-provisioning HTTP calls'
// equivalent of the browser-side `ignoreHTTPSErrors`/`--ignore-certificate-
// errors` accommodation used elsewhere for the same fixture. It never
// affects the packaged extension itself.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

function extensionId(worker) {
  const match = worker.url().match(/^chrome-extension:\/\/([^/]+)/);
  assert.ok(match, `unexpected service-worker URL: ${worker.url()}`);
  return match[1];
}

async function launchExtension() {
  const context = await chromium.launchPersistentContext("", {
    headless: false,
    ignoreHTTPSErrors: true,
    args: [`--disable-extensions-except=${chromeExtension}`, `--load-extension=${chromeExtension}`],
  });
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker");
  return { context, id: extensionId(worker) };
}

/** Real backend + real TLS + real WASM OPAQUE/crypto-worker, provisioning
 * an account exactly as a real web client would (packages/sdk +
 * packages/crypto-worker only — never apps/web, a forbidden path for this
 * task), then confirming the extension's own real-stack unlock machinery
 * (ExtensionVaultManager, invoked directly — not through a popup DOM, per
 * this file's header note) accepts it end-to-end in this same browser
 * test run's fixture. */
async function testRealStackUnlockAgainstFixture(fixture) {
  const accountId = `acct-${randomUUID()}`;
  const vaultId = `vault-${randomUUID()}`;
  const wrapItemId = `wrap-${randomUUID()}`;
  const password = new TextEncoder().encode("CorrectHorseBatteryStaple1!");

  const provisioningApi = new ApiClient({ baseUrl: fixture.url });
  await new AuthClient(provisioningApi, await createWasmOpaqueClient()).register(accountId, password.slice());

  const backend = await createWasmBackend();
  const host = new CryptoWorkerHost(backend);
  const setupResponse = host.handle({
    id: "setup", type: "create-account-setup", password: password.slice(),
    reportedPhysicalMemoryKiB: 262_144n, accountId, vaultId, itemId: wrapItemId,
  });
  assert.ok(setupResponse.ok && setupResponse.type === "account-setup", "account setup failed");
  const setup = setupResponse.result;
  host.dispose();

  const bundleWire = buildAccountBundle({
    accountId: setup.accountId, vaultId: setup.vaultId, itemId: setup.itemId,
    kdfParametersCbor: setup.kdfParametersCbor, wrappedAccountKey: setup.wrappedAccountKey,
    wrappedVaultKey: setup.wrappedVaultKey, wrappedItemKey: setup.wrappedItemKey,
    wrappedRecoveryKey: setup.wrappedRecoveryKey,
  });
  const publishApi = new ApiClient({ baseUrl: fixture.url });
  await new AuthClient(publishApi, await createWasmOpaqueClient()).login(accountId, password.slice());
  const published = await publishApi.putKeyBundle({ bundle: bundleWire, version: 1 });
  assert.equal(published.status, 204, `key-bundle publish failed: ${JSON.stringify(published)}`);

  const { ExtensionVaultManager } = await import("../../apps/extension/src/vault-manager.ts");
  const manager = new ExtensionVaultManager({ deviceName: "e2e-real-stack-device" });
  const result = await manager.unlock(accountId, fixture.url, password.slice());
  assert.deepEqual(result, { ok: true });
  assert.equal(manager.isUnlocked(), true);
  return { verified: true, accountId };
}

/** Every one of this task's new popup message types is refused as
 * untrusted when sent from a tab-shaped sender — extending the original
 * baseline's single "locked popup" text check to the full new message
 * surface, in a real loaded Chrome extension. */
async function testUntrustedPopupSenderRefusesEveryNewMessageType() {
  const { context, id } = await launchExtension();
  try {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${id}/popup.html`);

    const results = await popup.evaluate(async () => {
      function send(message) {
        return new Promise((resolvePromise) => chrome.runtime.sendMessage(message, resolvePromise));
      }
      const messages = [
        { type: "unlock", accountId: "a", apiOrigin: "https://example.test", password: [1, 2, 3] },
        { type: "logout" },
        { type: "list-items" },
        { type: "get-totp", itemId: "x" },
        { type: "save-item", title: "x", itemType: "note" },
      ];
      const out = [];
      for (const message of messages) out.push({ message, response: await send(message) });
      return out;
    });

    for (const { message, response } of results) {
      assert.ok(response, `no response for ${message.type}`);
      assert.notEqual(response.type, "unlocked", `${message.type} must never report success from an untrusted sender`);
      assert.notEqual(response.type, "saved", `${message.type} must never report success from an untrusted sender`);
      assert.notEqual(response.type, "items", `${message.type} must never leak vault items to an untrusted sender`);
      assert.notEqual(response.type, "totp", `${message.type} must never leak a TOTP code to an untrusted sender`);
    }
    return { verified: true, results };
  } finally {
    await context.close();
  }
}

async function run() {
  assert.ok(existsSync(chromeExtension), `missing ${chromeExtension}; run extension build first`);
  if (!databaseUrl) {
    return { skipped: true, reason: "TEST_DATABASE_URL is not set; the real backend needs PostgreSQL" };
  }
  if (!opensslAvailable()) {
    return { skipped: true, reason: "no local `openssl` binary to generate a self-signed certificate" };
  }

  const evidence = { generatedAt: new Date().toISOString(), scenarios: {} };

  const fixture = await startHttpsFixture({ databaseUrl });
  try {
    evidence.scenarios.realStackUnlock = await testRealStackUnlockAgainstFixture(fixture);
  } catch (error) {
    evidence.scenarios.realStackUnlock = { verified: false, error: error?.stack ?? String(error) };
  } finally {
    await fixture.close();
  }

  try {
    evidence.scenarios.untrustedPopupSenderRefused = await testUntrustedPopupSenderRefusesEveryNewMessageType();
  } catch (error) {
    evidence.scenarios.untrustedPopupSenderRefused = { verified: false, error: error?.stack ?? String(error) };
  }

  return evidence;
}

const evidence = await run();
await fs.writeFile(resolve(output, "c04-extension-e2e-unlock.json"), JSON.stringify(evidence, null, 2));
console.log(JSON.stringify(evidence, null, 2));

if (!evidence.skipped) {
  const failed = Object.entries(evidence.scenarios).filter(([, v]) => v.verified !== true);
  if (failed.length > 0) {
    console.error(`${failed.length} scenario(s) failed: ${failed.map(([k]) => k).join(", ")}`);
    process.exit(1);
  }
}
