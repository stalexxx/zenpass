// Reusable helper for driving a *genuine* Chrome MV3 extension action popup
// from Playwright, closing the C04-EXT2 disclosed gap
// (docs/security/C04-E2E-REPORT.md's "C04-EXT2: what changed and what is
// still genuinely open"). Playwright has no public API to open a real
// extension action popup: the documented `context.newPage()` +
// `goto("chrome-extension://<id>/popup.html")` workaround opens popup.html
// as an ordinary browser tab, which always carries `sender.tab`, so
// `trustedPopupSender` (packages/extension-adapters/src/sender.ts —
// correctly, by design, ADR-0011 D3) refuses every message from it exactly
// like a hostile page.
//
// The technique used here instead: `chrome.action.openPopup()`, called from
// the extension's own service worker (which holds `activeTab`/extension
// authority), opens a genuine `type: "page"` Chrome target that is NOT a
// tab — Playwright never surfaces it as a `Page`, so it is driven with a
// raw CDP session multiplexed over an existing Playwright `CDPSession`,
// using only public `Target.attachToTarget` (non-flatten) +
// `Target.sendMessageToTarget`/`Target.receivedMessageFromTarget` — no
// private Playwright internals. A message this real popup sends via
// `chrome.runtime.sendMessage` carries `sender.tab === undefined` and
// `sender.url === popupUrl()` — the exact `trustedPopupSender` contract,
// confirmed empirically while building this file (see
// c04-extension-e2e-popup.mjs's header comment for the one caveat found).
//
// Chrome must run **headed** (`headless: false`) — MV3 action popups do
// not open under headless Chrome. Launch args must also include
// `--ignore-certificate-errors`: Playwright's own `ignoreHTTPSErrors`
// context option does not extend to the extension service worker's own
// `fetch()` calls against a self-signed HTTPS fixture (confirmed by
// observing `net::ERR_CERT_AUTHORITY_INVALID` on the service worker's
// Network domain before this flag was added).
import assert from "node:assert/strict";

export function extensionIdFromWorkerUrl(url) {
  const match = url.match(/^chrome-extension:\/\/([^/]+)/);
  assert.ok(match, `unexpected service-worker URL: ${url}`);
  return match[1];
}

/** A raw CDP session multiplexed over an existing Playwright `CDPSession`
 * (`rootCdp`), attached (non-flatten) to `targetId`. Works for any target
 * type Playwright itself does not model as a `Page` — a real action popup,
 * or a content tab's own target when a Playwright-level `page.evaluate`
 * would otherwise trigger Chrome's own window-activation semantics (which
 * dismisses an open popup; see the header of c04-extension-e2e-popup.mjs). */
export async function attachRaw(rootCdp, targetId) {
  const { sessionId } = await rootCdp.send("Target.attachToTarget", { targetId, flatten: false });
  let nextId = 1;
  const pending = new Map();
  const listeners = new Map();
  const onMessage = (event) => {
    if (event.sessionId !== sessionId) return;
    const msg = JSON.parse(event.message);
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message));
      else resolve(msg.result);
    } else if (msg.method) {
      for (const cb of listeners.get(msg.method) ?? []) cb(msg.params);
    }
  };
  rootCdp.on("Target.receivedMessageFromTarget", onMessage);
  return {
    sessionId,
    targetId,
    send(method, params = {}) {
      const id = nextId++;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        rootCdp.send("Target.sendMessageToTarget", { sessionId, message: JSON.stringify({ id, method, params }) }).catch(reject);
      });
    },
    on(method, cb) {
      if (!listeners.has(method)) listeners.set(method, []);
      listeners.get(method).push(cb);
    },
  };
}

/** Evaluates `expression` inside a raw-attached target and returns its
 * value, throwing if Chrome reports an exception (a thrown error inside
 * the popup/page must fail the harness loudly, not silently resolve
 * `undefined`). */
export async function evalIn(raw, expression) {
  const result = await raw.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (result.exceptionDetails) {
    throw new Error(`Runtime.evaluate exception: ${JSON.stringify(result.exceptionDetails)}`);
  }
  return result.result?.value;
}

/** Launches Chrome with the given unpacked extension loaded, headed (MV3
 * popups require it) and with certificate-error tolerance extended to the
 * extension's own service-worker fetches (see this file's header). */
export async function launchExtensionChrome(chromium, extensionPath, extraArgs = []) {
  const context = await chromium.launchPersistentContext("", {
    headless: false,
    ignoreHTTPSErrors: true,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
      "--ignore-certificate-errors",
      ...extraArgs,
    ],
  });
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"));
  const id = extensionIdFromWorkerUrl(worker.url());
  return { context, worker, id };
}

/** A root CDP session with target discovery enabled, needed to enumerate
 * and attach to the popup target once it appears. Backed by a real
 * Playwright page (required by `context.newCDPSession`), which is never
 * itself used for navigation. */
export async function createRootCdp(context) {
  const anchor = await context.newPage();
  await anchor.goto("about:blank");
  const rootCdp = await context.newCDPSession(anchor);
  await rootCdp.send("Target.setDiscoverTargets", { discover: true });
  return { rootCdp, anchor };
}

/** Calls `chrome.action.openPopup()` from the extension's own service
 * worker, then polls `Target.getTargets` for the resulting real popup
 * target (it can first appear with an empty URL before Chrome resolves
 * it), and returns a raw CDP session attached to it. */
export async function openRealPopup(worker, rootCdp, { timeoutMs = 5000 } = {}) {
  const openResult = await worker.evaluate(async () => {
    try {
      await chrome.action.openPopup();
      return { ok: true };
    } catch (e) {
      return { ok: false, error: String(e?.message || e) };
    }
  });
  if (!openResult.ok) throw new Error(`chrome.action.openPopup() failed: ${openResult.error}`);

  let popupTargetId;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline && !popupTargetId) {
    const { targetInfos } = await rootCdp.send("Target.getTargets");
    const target = targetInfos.find((t) => t.url.includes("popup.html") && t.type === "page");
    if (target) popupTargetId = target.targetId;
    else await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(popupTargetId, "real popup target never appeared within the timeout");

  const raw = await attachRaw(rootCdp, popupTargetId);
  await raw.send("Page.enable");
  await raw.send("Runtime.enable");
  return raw;
}

/** Closes a real popup target directly via CDP (as opposed to a DOM
 * `window.close()` call from inside it) — used to simulate a popup closing
 * mid-operation for the lock-races-an-in-flight-operation scenario. */
export async function closeTarget(rootCdp, targetId) {
  await rootCdp.send("Target.closeTarget", { targetId });
}

/** Finds a real (non-popup, non-extension) page's own CDP target id, so it
 * can be driven via `attachRaw`/`evalIn` instead of Playwright's own
 * `page.evaluate`, which internally activates the target and dismisses
 * any currently-open real popup (confirmed empirically: any
 * Playwright-level navigation or activation on another target closes the
 * popup; a raw `Runtime.evaluate` against an already-loaded target's
 * existing execution context does not). */
export async function findPageTargetId(rootCdp, urlSubstring) {
  const { targetInfos } = await rootCdp.send("Target.getTargets");
  const target = targetInfos.find((t) => t.type === "page" && t.url.includes(urlSubstring));
  assert.ok(target, `no page target found matching ${urlSubstring}`);
  return target.targetId;
}

/** JS source (not itself executed here) that sets a form input's value via
 * the native property setter and dispatches `input`/`change` — the same
 * pattern `apps/extension/src/content.ts` uses for its own DOM writes — so
 * the popup's real event listeners observe the change exactly as they
 * would for a real keystroke-driven fill. */
export function setValueScript(selector, value) {
  return `(function(){
    var el = document.querySelector(${JSON.stringify(selector)});
    if (!el) throw new Error(${JSON.stringify("missing element " + selector)});
    var proto = el.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype
      : el.tagName === 'SELECT' ? window.HTMLSelectElement.prototype
      : window.HTMLInputElement.prototype;
    var setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
    setter.call(el, ${JSON.stringify(value)});
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`;
}

export function clickScript(selector) {
  return `(function(){
    var el = document.querySelector(${JSON.stringify(selector)});
    if (!el) throw new Error(${JSON.stringify("missing element " + selector)});
    el.click();
    return true;
  })()`;
}

/** Polls `document.body.innerText` inside `raw` until it matches `pattern`
 * or `timeoutMs` elapses; returns the final text either way (the caller
 * asserts on it, so a timeout produces a useful failure message instead of
 * a bare "polling timed out"). */
export async function waitForBodyText(raw, pattern, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let text = "";
  while (Date.now() < deadline) {
    text = await evalIn(raw, "document.body.innerText");
    if (pattern.test(text)) return text;
    await new Promise((r) => setTimeout(r, 250));
  }
  return text;
}
