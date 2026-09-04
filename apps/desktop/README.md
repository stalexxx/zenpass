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
