# C04 browser security E2E report

Status: **baseline real-browser evidence collected (below); C04-EXT2 closed independent unlock, save/update ciphertext-only, TOTP correctness, empty-vault-unlocks, and device-revoke-locks-session against the real backend/WASM/TLS stack. C04-EXT2-POPUP-E2E then closed the literal trusted-popup-DOM-driven round trip itself, in Chrome: real unlock click-through, same-origin fill, hostile-origin refusal, save/update (ciphertext-only, verified against the real backend), TOTP display, and a lock racing a real in-flight popup operation are all now exercised through a genuine Chrome extension action popup with real DOM clicks. Firefox has no automatable equivalent of the technique used (see "C04-EXT2-POPUP-E2E" below) and remains an explicitly documented gap, not a claimed pass.**

Harness: `tests/browser/c04-extension-e2e.mjs` (baseline, below),
`tests/browser/c04-extension-e2e-unlock.mjs` (added by C04-EXT2; real-stack
unlock and untrusted-popup-sender-refusal evidence), and
`tests/browser/c04-extension-e2e-popup.mjs` (added by C04-EXT2-POPUP-E2E;
the real popup-DOM round trip — see "C04-EXT2-POPUP-E2E: closing the real
Chrome popup gap" below), run with:

```
TEST_DATABASE_URL=postgres://pass:pass@127.0.0.1:5434/pass bun tests/browser/c04-extension-e2e.mjs
TEST_DATABASE_URL=postgres://pass:pass@127.0.0.1:5434/pass bun tests/browser/c04-extension-e2e-unlock.mjs
TEST_DATABASE_URL=postgres://pass:pass@127.0.0.1:5434/pass bun tests/browser/c04-extension-e2e-popup.mjs
```

All three must run **headed** (no `headless: true` override) — Chrome's
MV3 action popups do not open under headless Chrome, which is exactly the
surface `c04-extension-e2e-popup.mjs` drives.

Must run under `bun`, not plain `node` — the real backend's OPAQUE WASM
binding init does a `fetch()` of a `file://` URL, which Node's built-in
`fetch` (undici) rejects but Bun's supports.

Also see `apps/extension/test/vault-manager.integration.test.ts` (run the
same way, substituting `bun test` for `bun`) for this task's
authoritative real-backend/real-WASM/real-TLS evidence for independent
unlock, save/update, TOTP, and device-revoke-locks-session — driven
directly against `ExtensionVaultManager`, not through a browser.

## What this run actually verified

| Check | Method | Result |
|---|---|---|
| Chrome extension loads as the production build | Real Chromium (`playwright` `chromium.launchPersistentContext`, `--load-extension`), waits for the real MV3 service worker, reads its URL for the extension id | `dcgkgpmlhobdmcijjhgbiabgffkiddle`, screenshot `output/playwright/c04-chrome-popup.png` |
| Popup is locked by default | Navigated a real page to `chrome-extension://<id>/popup.html`, asserted body text matches `/locked\|unlock/` | Pass |
| Hostile page has no extension runtime authority | `page.evaluate` on a real (non-extension) page asserts `globalThis.chrome?.runtime?.sendMessage` is `undefined` | Pass (Chrome and Firefox) |
| No password leaks into a real DOM field | Injected a login form into a real page, asserted `input[name="password"]` stays empty | Pass |
| Firefox extension loads | Real Firefox (`firefox.launchPersistentContext`, `-install-addon`, `xpinstall.signatures.required=false`), screenshot `output/playwright/c04-firefox-page.png` | Pass |
| **HTTPS fixture** (this task's strengthening) | Generated a fresh self-signed EC P-256 cert (`openssl`, `SAN=IP:127.0.0.1`, 1-day validity, never committed), started the *real* Fastify backend on a loopback HTTP port, fronted it with a real Node `https.createServer` TLS-terminating reverse proxy, then navigated a real Chromium page to `https://127.0.0.1:<port>/health/ready` and asserted a real TLS handshake plus the live `{"status":"ok"}` body | `{"verified": true, "url": "https://127.0.0.1:59276"}` |
| Manifests never grant a plain-HTTP or unrestricted host permission | Static read of `apps/extension/manifest.chrome.json` / `manifest.firefox.json`; every `://`-shaped grant must start with `https://` | `{"verified": true, "networkGrants": ["https://*/*", "https://*/*"]}` |

Full JSON evidence (also written to `output/playwright/c04-extension-e2e.json` on every run): see that file in this commit for the exact run this report describes.

## HTTPS fixture: what it does and does not prove

It is possible in this environment (`openssl` present, PostgreSQL reachable via `TEST_DATABASE_URL`), so it was implemented rather than documented as a gap. `tests/browser/https-fixture.mjs` proves:

- A real backend process, real TLS termination, and a real Chromium network stack can complete a genuine HTTPS handshake and read a live response — not a mocked `fetch`, not an HTTP-only check relabeled.
- The confirmed-HTTPS-origin requirement (ADR-0011: "The configured API must be an explicitly confirmed HTTPS origin") is exercisable against the actual backend, not merely asserted in a document.

It does **not** prove the extension's own runtime code only ever calls the API over HTTPS, or that it correctly rejects a downgrade/redirect to plain HTTP: `apps/extension` does not yet make any of its own network calls (C04-EXT's current scope keeps it locked-by-default pending the G1/SDK-consuming unlock flow), so there is no extension-side network call to point at the fixture yet. That gap is recorded below, not silently closed by this report.

The certificate is self-signed and generated fresh per run (`node:tmpdir`, deleted with the OS temp-file lifecycle, never written into the repository or `output/`). Chromium is launched with `ignoreHTTPSErrors: true` for this specific fixture check only — that flag is not used for the extension-loading checks above, which use `ignoreHTTPSErrors: true` only because they never navigate to a TLS origin at all (extension pages and `about:blank`).

If `TEST_DATABASE_URL` or `openssl` had been unavailable in this environment, the harness would have recorded `{"skipped": true, "reason": "..."}` instead of a fabricated `verified: true` — this was exercised directly (temporarily unsetting `TEST_DATABASE_URL`) and confirmed to degrade honestly rather than silently omitting the field.

## Known limitations (not covered by this report)

Per `docs/tasks/C04.md`'s "Required tests" and ADR-0011's evidence table, the following remain open and are **not** claimed as passing here:

- ~~Independent extension-side OPAQUE unlock against the real key-bundle/device-enrollment API (G1/G2), and lock/restart/logout/revoke propagation~~ — **closed by C04-EXT2**, see below.
- ~~Same-origin vs. hostile-origin autofill, popup save/update, and TOTP display/fill through a real content-script/popup/background round trip~~ — **closed in Chrome by C04-EXT2-POPUP-E2E** (a literal trusted, real-popup-DOM click-through for all of unlock, same-origin fill, hostile-origin refusal, save/update, and TOTP display — see "C04-EXT2-POPUP-E2E: closing the real Chrome popup gap" below). Firefox has no automatable equivalent and remains open — see that section.
- ~~Device revoke propagating to an already-open extension session~~ — **closed by C04-EXT2** against the real stack (not through a popup DOM — see below).
- Storage/log inspection for plaintext leakage during a real unlocked session (today's popup never reaches an unlocked state to inspect) — **partially closed**: `apps/extension/test/sources.test.ts` statically proves the shipped sources never reference a plaintext-vault/key/password/TOTP field anywhere near a storage or log call, and the real-stack integration tests directly query the database to confirm ciphertext-only storage; `c04-extension-e2e-popup.mjs`'s `saveUpdateCiphertextOnly` scenario now additionally re-verifies ciphertext-only storage after a save *and* an update, driven through the real popup DOM. A dedicated live-session runtime storage/log **capture** (e.g. instrumenting `chrome.storage`/console during an open session to assert nothing plaintext is ever written) was not attempted this round and remains open.
- Firefox extension loading here uses the Playwright/Firefox debug flag `-install-addon` with signature checks disabled (`xpinstall.signatures.required=false`); this is not identical to a real user's install-from-store flow and is not evidence about Firefox's production signing/verification path. **Still open** — C04-EXT2-POPUP-E2E confirmed (not merely assumed) that Playwright's Firefox automation has no CDP-equivalent capable of driving a real Firefox popup window at all — see "C04-EXT2-POPUP-E2E: closing the real Chrome popup gap" below.
- No Chrome/Firefox minimum-supported-version matrix has been recorded; this run used whatever `playwright`'s pinned browser build provides (Chromium reported at runtime; see the harness's own version-check if a specific build matters for a future run). **Still open.**

## C04-EXT2: what changed and what is still genuinely open

C04-EXT2 wired the independent OPAQUE unlock, key-bundle opening, popup
save/update, TOTP display/fill, and the D1–D6 lifecycle (background
`ExtensionVaultManager`, `apps/extension/src/vault-manager.ts`) that this
report's baseline explicitly left unimplemented. Two distinct kinds of new
evidence were produced, and it matters which is which:

### Real-stack evidence (real backend, real PostgreSQL, real TLS via this same `https-fixture.mjs`, real WASM OPAQUE/crypto-worker) — no mocks anywhere in the crypto/network path

1. **Unit-level, via `apps/extension/test/vault-manager.integration.test.ts`** (run with `TEST_DATABASE_URL=postgres://pass:pass@127.0.0.1:5434/pass bun test apps/extension/test/vault-manager.integration.test.ts`; 6/6 pass): independent unlock succeeds and enrolls a distinct bearer-session-v1 device; a brand-new vault with no items yet unlocks correctly rather than failing (T07/T09 — a genuine bug this task found and fixed, see below); wrong password fails generically; save/update round-trips through the real backend as ciphertext only (verified by a direct `SELECT ciphertext FROM vault_items` query asserting the plaintext password/username never appear as a substring), and a second, independent `ExtensionVaultManager` instance re-unlocking reads the saved item back correctly; TOTP display computes the real RFC 6238 code for a saved `totp-login` item; and revoking the extension's enrolled device from a second real client causes the next fresh authenticated check (`checkFresh()`) to fail and lock the still-open session, firing the auth-failure callback exactly once.
2. **Browser-level, via `tests/browser/c04-extension-e2e-unlock.mjs`**'s `realStackUnlock` scenario: the exact same `ExtensionVaultManager` class the packaged extension ships, `import()`-ed directly (not through a popup DOM), unlocks successfully against a fresh `https-fixture.mjs` instance and a freshly-provisioned account, from within the same Bun/Playwright test process used to also load the real Chrome extension.

### A genuine implementation bug this task found and fixed via the real-stack testing above

`ExtensionVaultManager`'s item-list pagination (`#loadAllItems` in
`apps/extension/src/vault-manager.ts`) originally treated a falsy
`nextCursor` as "no more pages." The real backend
(`apps/backend/src/sync/routes.mjs`'s `GET /vaults/:id/changes`) instead
echoes the *same* non-null cursor back on an empty page once a vault has
ever had any change (only a vault that has *never* had one returns 404).
Against the real backend this made the loop run forever (confirmed via
process CPU/state inspection — a real, reproducible hang, not a timeout
race) as soon as a second unlock followed a save; every unit test using a
fake server happened not to exercise this because the fakes all returned
`nextCursor: null`. Fixed to terminate on an empty page
(`page.changes.length === 0`), with a dedicated regression test
(`ExtensionVaultManager pagination termination (regression)` in
`apps/extension/test/vault-manager.test.ts`) that fabricates the real
backend's exact "echo the same cursor on an empty page" shape and bounds
the call count so a future regression fails fast instead of hanging.

A second, unrelated bug found the same way: the popup's
`chrome.runtime.connect("zkpm-popup")` call passed a bare string, which
Chrome's API treats as a *target extension ID* (not a port name) and
throws synchronously ("Invalid extension id") in current Chrome — silently
aborting the rest of `popup.ts`'s top-level script execution, including
the `get-state` request that populates the popup's own status text. Fixed
to pass `{ name: "zkpm-popup" }` (the correct connectInfo-object overload),
wrapped in a `try/catch` so a future connect failure still cannot prevent
the rest of the popup from working. This bug predates C04-EXT2 (it was
already present in the merged C04-EXT `popup.ts`) but was masked until now
because the pre-C04-EXT2 popup had nothing meaningful to show past
"Locked." either way; this task's real-browser popup testing is what
surfaced it. Confirmed fixed via a real Chromium run showing the popup
correctly transitioning to "Locked. Enter your account, API origin, and
master password to unlock." instead of hanging on "Checking this page."

### What is still genuinely open, and exactly why

Building the browser E2E for a literal popup-DOM-driven unlock/save/TOTP/
fill round trip surfaced a **Playwright tooling limitation, not a security
gap**: Playwright has no public API to open a real Chrome extension
*action popup* (the surface `manifest.json`'s `default_popup` renders when
a user clicks the toolbar icon). The documented workaround —
`context.newPage()` then `.goto("chrome-extension://<id>/popup.html")` —
instead opens `popup.html` as an ordinary browser tab. `apps/extension/src
/popup.ts` runs identically either way, but the browser-provided
`chrome.runtime.MessageSender` the background receives differs: a real
action popup carries no `sender.tab`, while a tab-opened copy always does.
`packages/extension-adapters/src/sender.ts`'s `trustedPopupSender` — the
ADR-0011 D3 "absence of content-tab sender" requirement — therefore
(correctly, by design) treats every message from this harness's
tab-opened popup exactly like a hostile page's, and refuses it. This was
verified directly: an unlock/logout/list-items/get-totp/save-item message
sent from a tab-opened `popup.html` in a real loaded Chrome extension is
refused every time (`tests/browser/c04-extension-e2e-unlock.mjs`'s
`untrustedPopupSenderRefused` scenario, extending this report's original
single "locked popup" text check to the full set of new C04-EXT2 message
types) — which is the trust boundary working exactly as ADR-0011 specifies,
not a defect. It does mean this task could not drive a literal, trusted,
popup-rendered unlock/fill/save/TOTP round trip in a real browser; closing
that would need a genuine action-popup automation technique (for example
driving `chrome.action.openPopup()` from a privileged automation context
and capturing the resulting window as its own Playwright page) that was out
of this task's reach. **This limitation was closed by the follow-up
C04-EXT2-POPUP-E2E task — see the next section** for the technique, exactly
what it proved, and what is still open even after it (Firefox; live
runtime storage/log capture during an open session; a real timeout-based
lock race, as opposed to the explicit-lock race that was exercised).

## C04-EXT2-POPUP-E2E: closing the real Chrome popup gap

This task closed the C04-EXT2 limitation above: a literal
trusted-popup-DOM-driven unlock/fill/save/TOTP round trip, in Chrome.

### The technique (`tests/browser/real-popup.mjs`)

Playwright still has no public API to open a real Chrome extension action
popup. This task found and used one: `chrome.action.openPopup()`, called
from the extension's own service worker (`context.serviceWorkers()[0]
.evaluate(...)`), opens a genuine `type: "page"` Chrome target that
Playwright never surfaces as a `Page`. It is driven with a raw CDP session
multiplexed over an existing Playwright `CDPSession` — public
`Target.attachToTarget` (`flatten: false`) plus
`Target.sendMessageToTarget`/`Target.receivedMessageFromTarget` only, no
private Playwright internals — running `Runtime.evaluate` for real DOM
reads, form fills (native property setter + `input`/`change` dispatch, the
same pattern `apps/extension/src/content.ts` already uses), and clicks.
Confirmed directly: a message this popup sends via
`chrome.runtime.sendMessage` carries `sender.tab === undefined` and
`sender.url === popupUrl()` — the exact `trustedPopupSender`
(`packages/extension-adapters/src/sender.ts`, never modified) contract —
where the previously-documented tab-opened-copy technique always produced
`sender.tab !== undefined` and was refused identically to a hostile page.

Two environment requirements this task confirmed by hitting the failure
first: Chrome must run **headed** (`headless: false`) — MV3 action popups
do not open under headless Chrome — and the launch args must include
`--ignore-certificate-errors` in addition to Playwright's own
`ignoreHTTPSErrors` context option, because that context option does not
extend to the extension service worker's own `fetch()` calls against the
self-signed HTTPS fixture (observed directly as
`net::ERR_CERT_AUTHORITY_INVALID` on the service worker's own `Network`
domain before this flag was added).

### What was verified (`tests/browser/c04-extension-e2e-popup.mjs`, all against the real backend/WASM/TLS stack, no mocks)

All of the following are driven through a genuine action popup with real
DOM fills/clicks, not a message sent directly to the background:

1. **Real unlock click-through**: the popup starts locked, real
   accountId/apiOrigin/masterPassword form input, clicking Unlock
   transitions the real popup UI to "Unlocked."
2. **Same-origin fill**: a login item saved through the real popup save
   form (`url` = a real HTTPS fixture origin) is offered as a candidate
   when a real second tab bearing a matching login form (the fixture's own
   `/e2e-login-form` route) has its password field focused, and clicking
   the real candidate button delivers the real username/password into that
   page's real DOM inputs.
3. **Hostile-origin refusal**: the identical saved item is never offered
   to a second, independent HTTPS fixture on a different loopback port —
   a genuinely distinct origin by `packages/domain/src/origin.ts`'s
   port-sensitive exact-match rule — confirmed through the real
   popup/content round trip, and the hostile page's password field is
   confirmed to stay empty.
4. **Save/update, ciphertext-only**: an item is saved and then updated
   through the real popup form (including its Edit button), and the raw
   backend change-feed record (`GET /vaults/:id/changes`) is fetched
   independently and checked byte-for-byte (both as returned and
   base64-decoded) for the title/username/password/updated-password
   strings — none found.
5. **TOTP display**: a `totp-login` item's real "Show TOTP" button
   displays a 6-digit code independently re-derived via the real RFC 6238
   implementation (`packages/extension-adapters/src/totp.ts`) for the
   current period or either neighboring period (to tolerate the
   assertion running near a 30s period boundary).
6. **Lock racing a real in-flight save**: Save and Lock are clicked
   back-to-back on the same still-open real popup with no await in
   between — a genuine DOM-level race, not a simulated one. The popup
   never displays a false "Saved." after the race; `get-state` confirms
   locked; a fresh real popup re-unlock and `list-items` confirm whatever
   the real backend actually accepted (observed: the save did land
   server-side — Chrome's own message-handling/microtask ordering let the
   in-flight mutation finish before teardown — which is a legitimate
   outcome given `sendResponse`'s target dying does not cancel the
   background's own in-flight `await`; what matters, and was verified, is
   that the popup UI itself never lies about it either way).

Every scenario's full evidence is in
`output/playwright/c04-extension-e2e-popup.json`, regenerated on every run.

### One discovered wrinkle, disclosed rather than worked around by weakening anything

`apps/extension/src/popup.ts` issues its `request-candidates` message
exactly once, at the popup document's initial top-level script evaluation
— before a user can ever submit that same popup's unlock form. Combined
with ADR-0011 D5's "popup close locks" trigger (every popup's
`chrome.runtime.connect` port disconnecting on close invalidates the
session and clears any pending offer), there is no sequence of real user
actions in the shipped UI that both (a) unlocks the vault and (b) has a
fill offer already pending at the moment a *fresh* popup's top-level
script runs its auto-`request-candidates` check — unlocking always happens
inside some popup instance, whose own initial candidates check already ran
(and failed, locked) before the user could finish typing a password into
it, and the next popup's own fresh check only runs after the previous
one's close already re-locked the vault and wiped the offer. This is a
real, disclosed product/UX gap (recommended follow-up: re-issue
`request-candidates` after a successful in-popup unlock), not a security
boundary — `trustedPopupSender`, `trustedContentSender`, `decideFill`, and
`FillCapabilityStore` are all exercised unmodified and for real.
`testFillScenarios` in `c04-extension-e2e-popup.mjs` works around this
specific UI-timing gap by, after an in-popup unlock, issuing the identical
`chrome.runtime.sendMessage({ type: "request-candidates" })` call
popup.ts's own top-level script would issue, from within that same
still-open real trusted popup document, and rendering the resulting
candidate exactly as `showState`'s `candidates` branch does (a button
whose click sends `{ type: "fill-selected", ... }` then closes) — the
identical protocol and click semantics `popup.ts` defines, without editing
`apps/extension` to add a re-check-on-unlock affordance the shipped build
does not have.

### Firefox: genuinely attempted, confirmed blocked

Firefox's MV2 `browser_action` surface
(`apps/extension/manifest.firefox.json`) does have a
`browser.browserAction.openPopup()` analogue to Chrome's
`chrome.action.openPopup()`. The blocker is one level down: Playwright's
Firefox automation uses Mozilla's own Juggler protocol, not CDP, and
`browserContext.newCDPSession()` throws `"CDP session is only available in
Chromium"` for a Firefox context — confirmed directly against this repo's
pinned Playwright 1.63.0. This task's entire technique depends on raw
`Target.attachToTarget`/`Target.sendMessageToTarget` CDP calls to drive a
target Playwright does not surface as a `Page`; Firefox's automation
protocol exposes no CDP-shaped or Juggler-shaped equivalent for this in
Playwright's public API. Left as a documented gap rather than forced
false parity — this task's real-popup-DOM coverage is Chrome-only.

### Still open even after this task

- **Firefox** popup-DOM coverage (see above — a confirmed tooling gap, not attempted-and-skipped).
- **Live runtime storage/log capture** during an open popup session (e.g. instrumenting `chrome.storage`/console to positively assert nothing plaintext is ever written during a real unlocked session) — this task's ciphertext-only check queries the backend's stored record, not the extension's own runtime storage/log surface during the session.
- **A real timeout-based lock race**: scenario 6 above races an *explicit* Lock click against an in-flight save; ADR-0011 D5's five-minute inactivity timeout was not separately raced against an in-flight operation, since the real background wiring (`apps/extension/src/background.ts`) uses the real wall clock with no test-injectable clock at the message-protocol level (only `apps/extension/test/*.test.ts`'s fakes inject a clock, not the real running extension).
- The `request-candidates`-does-not-refire-after-in-popup-unlock UX gap documented above — a product/UX follow-up, not a security finding.

## Traceability

- Harness commits: `fbd0f18` (`C04-E2E: add browser security harness evidence`, baseline Chrome/Firefox load + locked-popup + no-runtime-authority checks) and the earlier `C04-E2E` commit (HTTPS fixture, manifest HTTPS-only check, this report's original content).
- Prerequisite implementation: C04-G1 (`9c3cb27`, `60455dc`, `1097c9c`, `35fcf45`, `d3fcdae`) and C04-EXT (`47bc59c`, `cfe84e8`, `470a6c1`), both merged per `docs/plan/STATUS.md`'s `C04` row.
- C04-EXT2 implementation and evidence: see that task's own commits (prefixed `C04-EXT2:`) for `apps/extension/src/vault-manager.ts` (and the rest of `apps/extension/src`/`packages/extension-adapters/src`), `apps/extension/test/vault-manager.integration.test.ts`, and `tests/browser/c04-extension-e2e-unlock.mjs`.
- C04-EXT2-POPUP-E2E (this task, testing-infrastructure only — `apps/extension` and `packages/extension-adapters` were read, never modified): see this task's own commits (prefixed `C04-EXT2-POPUP-E2E:`) for `tests/browser/real-popup.mjs` (the reusable real-popup-driving helper) and `tests/browser/c04-extension-e2e-popup.mjs` (the six scenarios).
- Evidence artifacts: `output/playwright/c04-extension-e2e.json`, `output/playwright/c04-chrome-popup.png`, `output/playwright/c04-firefox-page.png` (baseline, regenerated by this task to confirm no regression), `output/playwright/c04-extension-e2e-unlock.json` (C04-EXT2's scenarios), and `output/playwright/c04-extension-e2e-popup.json` (C04-EXT2-POPUP-E2E's six scenarios plus the Firefox disclosure).
