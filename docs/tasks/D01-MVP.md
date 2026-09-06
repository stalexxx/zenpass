# D01-MVP: wire the Tauri desktop shell to a real, configurable backend

Goal: turn the existing bare Tauri smoke-test shell (`apps/desktop`, commits
`3ac7cec`/`d44fc74`) into a working desktop client by running C05's real web
vault inside it, verified end-to-end against a real backend on this dev
machine. `apps/desktop`'s `tauri.conf.json` already points `frontendDist` at
`../../web/dist` and its CSP already permits `wasm-unsafe-eval`/`worker-src
blob:` — the desktop shell is *already* built to host the real web app, not
a stand-in; this task makes that actually work end-to-end rather than only
loading a static shell, and proves it.

**Human scope decision, 2026-09-06:** personal/dev-scope development may
proceed now without waiting on H02/full R01 (mirrors R01/D02's own
carve-out). Any claim of signed, distributable, or public-release-ready
desktop artifacts remains out of scope and blocked on H02.

Dependencies: C05 (React web client, merged), R01 (a running backend to
point at — personal-deployment scope is sufficient; you do not need public
release). Read `apps/desktop/README.md`, `apps/desktop/src-tauri/
tauri.conf.json`, `apps/desktop/src-tauri/src/main.rs`, and `apps/web/src/
App.tsx`'s `API_BASE_URL` resolution (`globalThis.ZKPM_API_BASE_URL`,
falling back to `http://localhost:8787`) before writing anything — this is
the exact mechanism R01's web deployment already used
(`apps/web/index.html`'s optional `./config.js`) to point the same built web
bundle at a real backend without a rebuild; reuse that pattern for Tauri
rather than inventing a second configuration mechanism.

Allowed paths: `apps/desktop/`, `docs/tasks/D01-MVP.md`. You may read (not
modify) `apps/web/` to understand what you're hosting.

Forbidden paths: `apps/web/` (the web client itself is C05's/frozen for
this task — if you find a genuine web-client bug that only manifests inside
Tauri's WebView, report it as a blocker rather than patching `apps/web/`
yourself), `crates/crypto-core/`, `crates/crypto-ffi/` (its one existing
`native_protocol_status` smoke command may stay as-is; do not expand its
native-crypto surface in this task — the desktop app uses the same WASM
crypto path as web, running inside Tauri's WebView, exactly like a normal
browser; native `crypto-ffi` JNI/FFI usage is a separate, later
optimization/OS-keychain task, not this one), `docs/contracts/`,
`packages/`, `apps/backend/`, `apps/extension/`.

## Required implementation

- Build `apps/web` for production (`bun run --filter @zkpm/web build`) and
  confirm Tauri's `beforeBuildCommand`/`frontendDist` wiring actually
  bundles that real build output, not a stale or placeholder one.
- Add a build-time or launch-time way to set `window.ZKPM_API_BASE_URL`
  inside the Tauri-hosted page, mirroring R01's `./config.js` pattern (e.g.
  a small config file Tauri's dev/build commands generate or that a user
  edits post-install) so the desktop app can point at a real backend
  (`http://127.0.0.1:8787` for local dev, or a real deployed origin) without
  a source rebuild. Update `tauri.conf.json`'s `security.csp`
  `connect-src` if a real HTTPS origin needs to be reachable (today it only
  allows `http://127.0.0.1:8787`/`http://localhost:8787`); do not weaken the
  CSP beyond what's actually needed (no wildcard `connect-src`).
- Confirm the WASM crypto path actually initializes inside Tauri's WebView
  (macOS's WKWebView here) — this is the same WASM module `apps/web` already
  ships, but Tauri's WebView is not identically configured to a Chrome/
  Firefox tab, so verify rather than assume: `wasm-unsafe-eval` CSP,
  `worker-src blob:` for the crypto Worker, and IndexedDB availability (used
  by `IndexedDBLocalRepository`) all need to actually work in this WebView.
  If something doesn't work, report exactly what and why, and only patch
  `apps/desktop`'s own configuration (CSP, Tauri capabilities/permissions)
  to fix it — not `apps/web`'s code.
- Verify Tauri's window/OS chrome doesn't break any existing web-app
  behavior that assumes a browser tab (e.g. `window.close()` calls
  anywhere, clipboard access for the password generator/TOTP copy,
  focus/visibility-based session timers if any exist).

## Required tests / verification (real, on this machine — no emulator needed)

- A real backend running locally (`docker compose` per `infra/` /
  `apps/backend`'s existing dev instructions, or the already-running
  personal-deployment VPS if reachable and appropriate for a dev/test
  account — prefer local for a clean test unless there's a good reason to
  use the deployed instance).
- `cd apps/desktop && bun run tauri dev` (or the built app via `bun run
  tauri build` and launching the resulting bundle) actually opens a native
  window, loads the real onboarding/unlock screen, and:
  1. Registers a fresh test account through the real OPAQUE flow.
  2. Confirms the recovery-kit reveal/confirm gate works.
  3. Creates a login item and a TOTP item, confirms both display correctly.
  4. Locks and re-unlocks with the master password.
  5. Confirms the item persists (real IndexedDB inside the WebView) across
     a full app restart (quit and relaunch the Tauri app, not just reload).
  Capture screenshots of each step as evidence (save under
  `output/desktop/`, mirroring `output/playwright/` for browser evidence).
- `bun run --filter @zkpm/web test` and `bun run --filter @zkpm/web build`
  still pass (confirms you didn't touch the frozen web client).
- `cargo test --workspace` and `bun run check:boundaries` still pass.

## Explicit non-goals for this MVP (do not attempt)

- OS keychain-backed key wrapping (native `crypto-ffi` usage from the Tauri
  Rust backend instead of WASM in the WebView) — a real architecture change,
  separate follow-up task (D01-EXT).
- Biometric unlock (Touch ID / Windows Hello) — separate follow-up.
- Extension native messaging — separate follow-up.
- Code signing / notarization / distributable installers — blocked on H02
  regardless; do not attempt.
- Windows/Linux verification — this dev machine is macOS; note in your
  report that only macOS was verified, and that Windows/Linux remain
  unverified (not necessarily broken, just unverified), consistent with
  this task's Allowed scope of "verified end-to-end on this dev machine."

## Completion report format

Standard completion report (`docs/plan/INTEGRATOR.md`). State plainly what
was verified (the real click-through above, with screenshot evidence) versus
what's explicitly out of scope (the non-goals above) versus any genuine
blocker found (e.g. a WebView incompatibility that would require touching
`apps/web`). Do not touch `docs/plan/STATUS.md` — the integrator updates it
after review.
