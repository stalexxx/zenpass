// C04 browser security evidence. Run with:
//   npx -y -p playwright node tests/browser/c04-extension-e2e.mjs
// The harness deliberately tests the production locked-by-default build.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, promises as fs } from "node:fs";
import { resolve } from "node:path";
import { chromium, firefox } from "playwright";

const root = resolve(import.meta.dirname, "../..");
const chromeExtension = resolve(root, "apps/extension/dist/chrome");
const firefoxExtension = resolve(root, "apps/extension/dist/firefox");
const output = resolve(root, "output/playwright");
mkdirSync(output, { recursive: true });

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
const evidence = { generatedAt: new Date().toISOString(), results: [await runChrome(), await runFirefox()] };
await fs.writeFile(resolve(output, "c04-extension-e2e.json"), JSON.stringify(evidence, null, 2));
console.log(JSON.stringify(evidence, null, 2));
