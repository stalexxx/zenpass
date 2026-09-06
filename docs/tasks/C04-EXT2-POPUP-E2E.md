# C04-EXT2-POPUP-E2E: real Chrome extension action-popup browser E2E

Goal: close the one remaining disclosed gap from C04-EXT2
(`docs/security/C04-E2E-REPORT.md`'s "C04-EXT2: what changed and what is
still genuinely open" section): a literal trusted-popup-DOM-driven
unlock/save/fill/TOTP click-through could not be verified in a real browser,
because Playwright has no public API to open a real Chrome extension action
popup, and the documented `context.newPage()` + `goto("chrome-extension://
<id>/popup.html")` workaround opens `popup.html` as an ordinary tab — which
correctly carries `sender.tab`, so `trustedPopupSender`
(`packages/extension-adapters/src/sender.ts`) refuses every message from it
identically to a hostile page (ADR-0011 D3 working as designed, not a gap in
it). This means the popup-DOM path is implemented and unit/integration
tested, but not exercised end-to-end through an actual browser-rendered
action popup with real DOM clicks.

This is a **testing-infrastructure task**, not a security-boundary change.
Do not weaken `trustedPopupSender` or any authority check to make it
"testable" — if a real popup genuinely cannot be automated after a good-faith
attempt, say so plainly and document exactly what was tried, rather than
loosening production code.

Dependencies: C04-EXT2 (merged, `e5f0a51`).

Allowed paths: `tests/browser/`, `docs/security/C04-E2E-REPORT.md`,
`docs/tasks/C04-EXT2-POPUP-E2E.md`. You may read (but should not need to
modify) `apps/extension/`, `packages/extension-adapters/`. If you find you
genuinely need a small, non-security-relevant test hook inside
`apps/extension/` (e.g. exposing something for automation purposes only, not
weakening any authority check), stop and report it as a blocker for
integrator review rather than making that call yourself — the same rule
C04-EXT2 followed.

Forbidden paths: everything else, especially `packages/extension-adapters/
src/sender.ts` (the `trustedPopupSender` authority check itself),
`crates/crypto-core/`, `docs/contracts/`, any frozen contract.

Suggested approach (not mandatory — investigate and use whatever genuinely
works): Chrome's extension action popup can be opened programmatically via
`chrome.action.openPopup()`, callable from a context with the `activeTab`/
extension permission such as the extension's own service worker. Playwright
exposes the service worker via `context.serviceWorkers()` and can run
arbitrary code in it via `serviceWorker.evaluate(...)`. Calling
`chrome.action.openPopup()` from there opens a real popup-type window
(distinct from a tab — no `sender.tab` should be set on messages it sends),
which should surface to Playwright as a new page event
(`context.on("page", ...)` or `context.waitForEvent("page")|"backgroundpage"`)
that can then be driven with normal Playwright DOM APIs (click, fill, etc.).
This requires Chrome to be run with a real window (not headless — MV3
extension popups generally require a non-headless run; check whether the
existing harness in `tests/browser/c04-extension-e2e.mjs` already runs
headed and reuse that setup). Firefox's popup automation story may differ
entirely (WebExtensions `browserAction`/`pageAction` — investigate
`browser.action.openPopup()` equivalents and existing Firefox automation
precedent) or may need to stay a documented gap for this browser if there
is no viable technique; do not force parity with Chrome if it doesn't exist.

If, after a genuine attempt, no technique reliably produces a
`sender.tab === undefined`, `sender.url === popupUrl()` popup context
automatable by Playwright, do not fabricate success: document precisely
what was tried, what failed and why, and leave the gap explicitly recorded
in `docs/security/C04-E2E-REPORT.md` exactly as C04-EXT2 already did —
extend that report's existing disclosure, do not delete or soften it unless
you have new evidence that actually closes it.

Required E2E (if the popup-automation technique works): reusing the real
backend/WASM/HTTPS-fixture stack already built by prior C04 tasks —
1. A real click-through in the actual rendered popup: enter accountId/
   apiOrigin/password, click unlock, observe the popup UI transition to its
   unlocked state.
2. Same-origin fill: with a real page open in another tab bearing a
   same-origin login form, the popup shows a matching candidate; clicking it
   delivers fields into that page's real DOM inputs.
3. Hostile-origin: a candidate for a different origin is not offered/is
   refused, confirmed through the real popup UI, not just a unit assertion.
4. Save/update through the real popup form, verified against the real
   backend (ciphertext-only, as C04-EXT2's integration test already
   verifies for the underlying logic — this round adds the actual DOM
   click path on top).
5. TOTP display/fill through the real popup "Show TOTP" button.
6. Lock/restart/timeout racing a real in-flight popup operation (e.g. start
   a save, close the popup or let the 5-minute window lapse using the
   manager's injectable clock/deadlines if the harness allows it, confirm
   the operation fails closed).

Verification: the new E2E script(s) run standalone
(`TEST_DATABASE_URL=... bun tests/browser/<new-file>.mjs`), plus a re-run of
`tests/browser/c04-extension-e2e.mjs` and
`tests/browser/c04-extension-e2e-unlock.mjs` to confirm no regression.

Completion report format: Standard completion report (`docs/plan/
INTEGRATOR.md`). State plainly whether the popup-automation gap is now
closed, partially closed (e.g. Chrome only), or still open with a documented
reason, and update `docs/security/C04-E2E-REPORT.md` accordingly (extend,
never silently overwrite prior findings). Do not touch `docs/plan/
STATUS.md` — the integrator updates C04's status line after review.
