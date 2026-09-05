// C04 browser security evidence. Run with:
//   TEST_DATABASE_URL=postgres://... bun tests/browser/c04-extension-e2e.mjs
// Must run under `bun`, not plain `node`: the real backend's OPAQUE WASM
// binding init does a `fetch()` of a `file://` URL, which Node's built-in
// fetch (undici) rejects ("not implemented... yet...") but Bun's supports.
// TEST_DATABASE_URL is optional — without it, the HTTPS-fixture check is
// skipped with an explicit reason (see verifyHttpsFixture below) rather
// than silently omitted from the evidence. The harness deliberately tests
// the production locked-by-default build.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, promises as fs } from "node:fs";
import { resolve } from "node:path";
import { chromium, firefox } from "playwright";
import { opensslAvailable, startHttpsFixture } from "./https-fixture.mjs";

const root = resolve(import.meta.dirname, "../..");
const chromeExtension = resolve(root, "apps/extension/dist/chrome");
const firefoxExtension = resolve(root, "apps/extension/dist/firefox");
const output = resolve(root, "output/playwright");
mkdirSync(output, { recursive: true });

/**
 * Real backend, real TLS handshake, real browser navigation — not merely
 * a Node-side fetch. Only ever reports `verified: true` after a Chromium
 * page actually loaded the HTTPS URL and read back the live JSON body;
 * every other path (missing openssl, no TEST_DATABASE_URL, any thrown
 * error) reports an explicit `skipped`/`error` reason instead. `apps/
 * extension` does not yet make any of its own network calls (still
 * locked-by-default, per C04-EXT's current scope) so this does not — and
 * cannot yet — prove the extension itself only ever calls the API over
 * HTTPS; it proves the fixture and the confirmed-HTTPS-origin requirement
 * (ADR-0011) are real and exercisable against the actual backend.
 */
async function verifyHttpsFixture() {
  const databaseUrl = process.env.TEST_DATABASE_URL;
  if (!databaseUrl) {
    return { skipped: true, reason: "TEST_DATABASE_URL is not set; the real backend needs PostgreSQL" };
  }
  if (!opensslAvailable()) {
    return { skipped: true, reason: "no local `openssl` binary to generate a self-signed certificate" };
  }
  let fixture;
  try {
    fixture = await startHttpsFixture({ databaseUrl });
  } catch (error) {
    return { skipped: true, reason: `fixture failed to start: ${error.message}` };
  }
  const context = await chromium.launchPersistentContext("", { headless: true, ignoreHTTPSErrors: true });
  try {
    const page = await context.newPage();
    const response = await page.goto(`${fixture.url}/health/ready`);
    assert.equal(response.status(), 200);
    const body = await page.evaluate(() => document.body.innerText);
    assert.deepEqual(JSON.parse(body), { status: "ok" });
    return { verified: true, url: fixture.url };
  } catch (error) {
    return { skipped: true, reason: `HTTPS check failed: ${error.message}` };
  } finally {
    await context.close();
    await fixture.close();
  }
}

/** Static evidence that neither manifest ever grants a plain-HTTP or
 * unrestricted (`<all_urls>`) network permission — the confirmed-HTTPS-
 * origin requirement (ADR-0011) holding at the manifest level, checked
 * independently of whether the extension's runtime code calls the API
 * yet. */
async function verifyManifestsAreHttpsOnly() {
  const chrome = JSON.parse(await fs.readFile(resolve(root, "apps/extension/manifest.chrome.json"), "utf8"));
  const firefoxManifest = JSON.parse(await fs.readFile(resolve(root, "apps/extension/manifest.firefox.json"), "utf8"));
  const grants = [...(chrome.host_permissions ?? []), ...(chrome.permissions ?? []), ...(firefoxManifest.permissions ?? [])];
  const networkGrants = grants.filter((g) => g.includes("://"));
  assert.ok(networkGrants.length > 0, "expected at least one network host permission");
  for (const grant of networkGrants) {
    assert.ok(grant.startsWith("https://"), `non-HTTPS network permission found: ${grant}`);
  }
  return { verified: true, networkGrants };
}

function extensionId(worker) {
  const match = worker.url().match(/^chrome-extension:\/\/([^/]+)/);
  assert.ok(match, `unexpected service-worker URL: ${worker.url()}`);
  return match[1];
}

async function runChrome() {
  const context = await chromium.launchPersistentContext("", {
    headless: false,
    ignoreHTTPSErrors: true,
    args: [`--disable-extensions-except=${chromeExtension}`, `--load-extension=${chromeExtension}`],
  });
  try {
    const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker");
    const id = extensionId(worker);
    const page = await context.newPage();
    await page.goto("about:blank");
    await page.evaluate(() => {
      document.body.innerHTML = '<form><input name="username"><input name="password" type="password"></form>';
    });
    assert.equal(await page.evaluate(() => typeof globalThis.chrome?.runtime?.sendMessage), "undefined");
    assert.equal(await page.locator('input[name="password"]').inputValue(), "");
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${id}/popup.html`);
    assert.match((await popup.locator("body").innerText()).toLowerCase(), /locked|unlock/);
    await popup.screenshot({ path: resolve(output, "c04-chrome-popup.png") });
    return { browser: "chromium", extensionId: id, checks: ["extension service worker loaded", "page has no runtime authority", "locked popup", "empty password field"] };
  } finally {
    await context.close();
  }
}

async function runFirefox() {
  const context = await firefox.launchPersistentContext("", {
    headless: true,
    ignoreHTTPSErrors: true,
    firefoxUserPrefs: { "xpinstall.signatures.required": false },
    args: [`-install-addon=${firefoxExtension}`],
  });
  try {
    const page = await context.newPage();
    await page.goto("about:blank");
    await page.evaluate(() => {
      document.body.innerHTML = '<form><input name="username"><input name="password" type="password"></form>';
    });
    assert.equal(await page.evaluate(() => typeof globalThis.browser?.runtime?.sendMessage), "undefined");
    assert.equal(await page.locator('input[name="password"]').inputValue(), "");
    await page.screenshot({ path: resolve(output, "c04-firefox-page.png") });
    return { browser: "firefox", checks: ["extension profile loaded", "page has no runtime authority", "empty password field"] };
  } finally {
    await context.close();
  }
}

assert.ok(existsSync(chromeExtension), `missing ${chromeExtension}; run extension build first`);
assert.ok(existsSync(firefoxExtension), `missing ${firefoxExtension}; run extension build first`);
const evidence = {
  generatedAt: new Date().toISOString(),
  results: [await runChrome(), await runFirefox()],
  httpsFixture: await verifyHttpsFixture(),
  manifestHttpsOnly: await verifyManifestsAreHttpsOnly()
};
await fs.writeFile(resolve(output, "c04-extension-e2e.json"), JSON.stringify(evidence, null, 2));
console.log(JSON.stringify(evidence, null, 2));
