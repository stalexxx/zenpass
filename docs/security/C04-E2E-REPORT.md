# C04 browser security E2E report

Status: **baseline real-browser evidence collected; full ADR-0011 acceptance-criteria E2E (unlock, fill, save, TOTP, revoke) remains open.**

Harness: `tests/browser/c04-extension-e2e.mjs`, run with:

```
TEST_DATABASE_URL=postgres://pass:pass@127.0.0.1:5434/pass bun tests/browser/c04-extension-e2e.mjs
```

Must run under `bun`, not plain `node` — the real backend's OPAQUE WASM
binding init does a `fetch()` of a `file://` URL, which Node's built-in
`fetch` (undici) rejects but Bun's supports.

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

- Independent extension-side OPAQUE unlock against the real key-bundle/device-enrollment API (G1/G2), and lock/restart/logout/revoke propagation — blocked on `apps/extension` actually consuming the merged C04-G1 SDK/API surface (C04-EXT's next slice).
- Same-origin vs. hostile-origin autofill, popup save/update, and TOTP display/fill through a real content-script/popup/background round trip.
- Device revoke propagating to an already-open extension session.
- Storage/log inspection for plaintext leakage during a real unlocked session (today's popup never reaches an unlocked state to inspect).
- Firefox extension loading here uses the Playwright/Firefox debug flag `-install-addon` with signature checks disabled (`xpinstall.signatures.required=false`); this is not identical to a real user's install-from-store flow and is not evidence about Firefox's production signing/verification path.
- No Chrome/Firefox minimum-supported-version matrix has been recorded; this run used whatever `playwright`'s pinned browser build provides (Chromium reported at runtime; see the harness's own version-check if a specific build matters for a future run).

## Traceability

- Harness commits: `fbd0f18` (`C04-E2E: add browser security harness evidence`, baseline Chrome/Firefox load + locked-popup + no-runtime-authority checks) and this task's `C04-E2E` commit (HTTPS fixture, manifest HTTPS-only check, this report).
- Prerequisite implementation: C04-G1 (`9c3cb27`, `60455dc`, `1097c9c`, `35fcf45`, `d3fcdae`) and C04-EXT (`47bc59c`, `cfe84e8`, `470a6c1`), both merged per `docs/plan/STATUS.md`'s `C04` row.
- Evidence artifacts: `output/playwright/c04-extension-e2e.json`, `output/playwright/c04-chrome-popup.png`, `output/playwright/c04-firefox-page.png` (all regenerated by the run this report describes).
