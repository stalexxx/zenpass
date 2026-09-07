# ZenPass — a zero-knowledge password manager

ZenPass is a personal password manager built around a zero-knowledge server:
the backend never sees your master password, your vault encryption keys, or
your plaintext vault data. Registration and login use the
[OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/) protocol
(an asymmetric PAKE), and every vault item (passwords, secure notes, TOTP
seeds) is end-to-end encrypted client-side before it ever reaches the
server or gets written to disk.

> **Status: personal / internal deployment only.** This project has not had
> an independent external security audit. Public release is explicitly
> gated on that audit (see [`H02` in `docs/plan/STATUS.md`](docs/plan/STATUS.md),
> currently `BLOCKED`). Treat this as a working system for its owner's own
> use, not as production-ready software for other people's secrets yet.

## What it does

- Passwords, secure notes, and TOTP (RFC 6238) codes, with a built-in CSPRNG
  password generator.
- End-to-end encrypted sync across devices, with offline editing, optimistic
  concurrency (`baseRevision`), idempotent mutation replay, and tombstone
  deletes.
- Import from CSV, Bitwarden, 1Password (classic CSV), and Enpass exports;
  encrypted-by-default export with a re-authentication gate for plaintext.
- A recovery kit (shown once at onboarding) as the only way back into a
  vault if the master password is lost — there is no server-side password
  reset, by design.
- Multi-device support with per-device session/token management and
  revocation.

## Clients

| Client | Path | Stack |
|---|---|---|
| Web | `apps/web` | React + strict TypeScript, WASM crypto in a Worker |
| Browser extension (Chrome/Firefox) | `apps/extension` | Manifest V3, background/popup/content-script boundary |
| Desktop | `apps/desktop` | Tauri shell around the web client |
| Android | `apps/android` | Native Kotlin + Jetpack Compose, UniFFI bindings to the Rust crypto core |

All clients talk to the same backend contracts and share the same
cryptography — no client re-implements a primitive; they all bind to
`crates/crypto-core` (via WASM, a Worker, or UniFFI).

## Backend

| Backend | Path | Status |
|---|---|---|
| Node/Bun (`apps/backend`) | production reference implementation | live, currently serving traffic |
| Rust (`apps/backend-rust`, crate `zkpm-backend`) | Axum/Tokio/SQLx port with full auth/devices/account/sync parity | reviewed cutover candidate, **not yet live** — see [`infra/rust-backend/RUNBOOK.md`](infra/rust-backend/RUNBOOK.md) |

The Rust backend is a from-scratch, byte-for-byte parity port of the Bun
service (same OpenAPI contract, same wire formats, same generic-failure
semantics), built to eventually replace it. Cutting production over to it
requires a human to walk through the runbook above — it is not automatic.

## Cryptography

All cryptographic primitives live in `crates/crypto-core` (Rust) and are
exposed to clients via `packages/crypto-wasm` (WASM, web/extension/desktop)
and `crates/crypto-ffi` (UniFFI, Android). No other package or app is
permitted to implement a cryptographic primitive directly — see
[`AGENTS.md`](AGENTS.md).

Key design decisions are recorded as ADRs in [`docs/decisions/`](docs/decisions/),
starting with the frozen crypto envelope
([ADR-0003](docs/decisions/ADR-0003-crypto-envelope-v1-approval.md)) and the
Rust backend migration ([ADR-0013](docs/decisions/ADR-0013-rust-backend.md)).
The threat model and residual risk decisions live in
[`docs/security/`](docs/security/).

## Repository layout

```
apps/            Web, extension, desktop, Android, and both backends
packages/        Shared TS packages: sdk, domain, importers, crypto-wasm/worker, contracts
crates/          Rust workspace: crypto-core, crypto-ffi, crypto-core-tests
db/              SQL migrations for the Bun backend (source of truth, mirrored in apps/backend-rust)
docs/            Plan, task specs, ADRs, security docs, UX flows, contracts (OpenAPI/fixtures)
infra/           Deployment: Docker Compose, Caddy, backup/restore, Terraform, the Rust cutover candidate
tests/           Cross-package E2E, security, and Rust-backend-candidate test suites
```

## Getting started

Prerequisites: [Bun](https://bun.sh) `>=1.2.15`, a Rust toolchain (pinned
per-crate via `rust-toolchain.toml`), Docker (for a local PostgreSQL and for
running the stack via Compose).

```sh
bun install
bun run build          # builds every workspace package/app + the Rust workspace
bun run test            # unit/integration tests across all packages + cargo test --workspace
bun run test:e2e        # cross-package end-to-end tests
bun run test:security    # security-focused test suite
bun run check:boundaries # enforces the package dependency boundaries
```

Each app under `apps/*` has its own README/dev instructions for running it
standalone (e.g. `apps/web`, `apps/backend`, `apps/backend-rust`).

To run the full stack locally against a real PostgreSQL, see
`infra/docker-compose.yml` (dev) or `infra/docker-compose.prod.yml`
(production shape, used as the basis for the real VPS deployment described
in `docs/plan/STATUS.md`'s `R01` row).

## How this project is developed

This repository is built through bounded, single-purpose agent tasks, each
scoped to an explicit set of allowed file paths and a written specification.
The rules every task follows are in [`AGENTS.md`](AGENTS.md); the overall
plan, dependency graph, and status model are in
[`docs/plan/MASTER.md`](docs/plan/MASTER.md); live task status is tracked in
[`docs/plan/STATUS.md`](docs/plan/STATUS.md).

## Security

No component may decrypt user vault data — the server only ever stores and
serves ciphertext. If you find a security issue, please do not open a
public GitHub issue; see [`docs/security/`](docs/security/) for the current
threat model and known residual risks, and reach out to the maintainer
directly.

## License

No license file is currently published in this repository — all rights are
reserved by default. Do not treat the presence of this source on a public
host as permission to use, copy, or redistribute it.
