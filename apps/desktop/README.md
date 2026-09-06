# Desktop shell (D01)

This is the internal-use Tauri shell for the web client. It links the Rust
crypto FFI only through a narrow protocol-status smoke command; vault
plaintext and key material never cross that command boundary.

## Local development

Start the backend on `127.0.0.1:8787`, then run:

```sh
bun run --filter @zkpm/desktop dev
```

The desktop window loads the web client from `127.0.0.1:5173` during
development. The backend development allowlist includes the exact
`tauri://localhost` WebView origin; no wildcard CORS rule is used.
`bun run --filter @zkpm/desktop build` produces an unsigned,
unbundled local binary for smoke testing.

## Deliberately not enabled yet

This shell does not claim completion of D01. OS keychain storage, biometric
unlock, browser-extension native messaging, platform installers and signing
remain gated on the R01/H02 security design and external-audit release gate.

## MVP click-through verification (D01-MVP)

`bun run --filter @zkpm/desktop build` produces a real, unsigned macOS
`.app`/`.dmg` in `src-tauri/target/release/bundle/`. That bundle loads the
real `apps/web` vault (built to `apps/web/dist`) with no separate desktop UI
and no changes required to `apps/web`. A real backend on `127.0.0.1:8787`
(the same default `ApiClient` base URL the web client already falls back to
via `window.ZKPM_API_BASE_URL`) is all that's needed; the CSP `connect-src`
and the backend's dev `WEB_ORIGIN` allowlist already cover
`http://127.0.0.1:8787` / `http://localhost:8787` and the `tauri://localhost`
WebView origin out of the box.

A full click-through was performed on this native macOS build against a real
Postgres-backed backend: register a fresh account with real OPAQUE, confirm
the recovery-kit gate, create a login item and a TOTP item (with a real
rolling 6-digit code), lock, re-unlock, then fully quit and relaunch the
`.app` — the vault re-unlocks with the same master password and both items,
including the live TOTP code, are still there. Screenshots are in
`output/desktop/` (captured with macOS `screencapture`, region-cropped to the
app window only).
