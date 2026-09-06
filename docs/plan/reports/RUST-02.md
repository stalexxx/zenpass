# RUST-02 completion report

Task: RUST-02 — Rust production foundation and database baseline.
Status: REVIEW. No self-merge of the worker branch by the agent; merged into
`main` only by explicit user instruction in-session (see Commits).

Commits: branch `agent/RUST-02-rust-foundation`, based on RUST-01 commit
`14f6347` (no integrator merge of RUST-01 existed, so this branch carries
both). Worker commits (prefix `RUST-02:`):
- `RUST-02: production foundation (config, CLI, middleware, DTO, migrations)`
- `RUST-02: SQLx offline metadata, SBOM, deny config, CI workflow, docs`
Final merge into `main` performed by user instruction, with RUST-01/RUST-02
status rows added to `docs/plan/STATUS.md` in the merge commit.

Changed paths:
- apps/backend-rust/: renamed crate to `zkpm-backend`; exact foundation
  pins (Cargo.toml, Cargo.lock); `src/config.rs` (strict `ZKPM_*` config,
  production/test separation, verify-full TLS); `src/main.rs` (clap
  serve/migrate/healthcheck); `src/lib.rs` (CORS allowlist, server UUID
  request IDs, allowlisted JSON logs, body/timeout/concurrency limits,
  bounded shutdown, generic `ApiError` mapping); `src/request_id.rs`;
  `src/error.rs`; `src/dto.rs` (OpenAPI shape skeleton, no routes);
  `src/migrate.rs` + `migrations/0001..0005_*.sql` (byte-identical copies of
  `db/migrations/`, exclusive advisory lock, legacy-history adoption);
  `.sqlx/` offline metadata; `deny.toml`; `sbom/zkpm-backend.cdx.json`;
  `tests/foundation.rs`, `tests/logs.rs`, `tests/process.rs`,
  `tests/postgres.rs`; README.
- .github/workflows/rust-backend.yml: new CI (PostgreSQL 16 service, fmt,
  clippy, build, unit + ignored-PG tests, binary migrate + `cargo sqlx
  prepare --check`, audit/deny, offline rebuild, diff hygiene).
- docs/tasks/RUST-02.md: status BLOCKED -> REVIEW.
- docs/plan/reports/RUST-02.md: this report.
- docs/plan/STATUS.md: RUST-01/RUST-02 rows (merge commit, user-authorized).

Contract changes: none. Frozen contracts, crypto-core sources/pins,
existing `db/migrations/*.sql`, Bun backend, root Cargo workspace/lock and
production Compose/Caddy untouched.

Verification commands and results (2026-09-06..07, macOS arm64,
rustc 1.93.1, PostgreSQL 16.15 disposable Docker containers, trust auth
only on isolated loopback containers):
- `cargo fmt --all -- --check`: PASS.
- `cargo clippy --locked --all-targets -- -D warnings`: PASS
  (DATABASE_URL set for macro expansion).
- `cargo build --locked`: PASS.
- `cargo test --locked`: PASS — 13 foundation + 1 logs + 2 native-crypto
  (kept from RUST-01) + 5 process tests.
- `RUST_TEST_DATABASE_URL=... cargo test --locked --test postgres --
  --ignored`: PASS — 11/11 real-PostgreSQL tests: fresh install, full
  legacy adoption without DDL replay, partial (001-003) adoption + apply,
  re-run no-op, schema-drift refusal, wrong/incomplete history refusal,
  partial-failure consistency + resume, concurrent migrate serialization,
  legacy-runner compatibility, readiness pause/resume transitions, TLS
  (plaintext refusal, matching-CA success, wrong-CA refusal, same-CA
  wrong-SAN hostname refusal).
- `cargo sqlx prepare --check` against a migrated scratch DB: PASS;
  committed `.sqlx/` (9 query files); `SQLX_OFFLINE=true cargo build
  --locked --offline` with `DATABASE_URL` unset: PASS.
- `cargo audit`: 1 vulnerability + 1 warning, both inherited from frozen
  crypto-core pins (rsa 0.9.10 RUSTSEC-2023-0071, no fix; rand 0.8.5
  RUSTSEC-2026-0097 unsound warning) — recorded, not changed per task
  constraints; release gates remain.
- `cargo deny check advisories licenses sources bans`: all ok (license
  inventory: MIT/Apache-2.0/ISC/BSD-2/3-Clause/Unicode-3.0/Zlib/
  BlueOak-1.0.0/CDLA-Permissive-2.0; crate licensed Apache-2.0 like
  crypto-core).
- SBOM: `sbom/zkpm-backend.cdx.json` (CycloneDX, 234 components).
- `git diff --check`: PASS.
- Approved crypto pins byte-identical to RUST-01 record: argon2 0.6.0,
  chacha20poly1305 0.11.0, minicbor 2.3.0, opaque-ke 4.0.1, rand 0.8.5,
  sha2 0.10.9, zeroize 1.9.0.
- New direct pins: axum 0.8.9, base64 0.22.1, clap 4.6.6, secrecy 0.10.3,
  serde 1.0.229, sqlx 0.8.6 (+macros/migrate/tls-rustls-ring), thiserror
  2.0.20, time 0.3.55, tokio 1.53.1, tower-http 0.7.1 (cors,timeout),
  tracing 0.1.44, tracing-subscriber 0.3.23, uuid 1.26.0; dev tower 0.5.3,
  http-body-util 0.1.4, serde_json 1.0.151, uuid (tests). zeroize is not a
  direct dependency (secrecy/zeroizing buffers cover secret handling).

Known limitations:
- No product routes (auth/devices/account/sync are RUST-03); health
  endpoints only. DTO/validation semantics (e.g. strict canonical-padding
  base64) may need alignment with the Bun reference during RUST-03 parity.
- Baseline set is fixed to versions 1-5; future Rust-only migrations need a
  legacy-table maintenance decision (currently: baseline set synced,
  newer versions recorded in `_sqlx_migrations` only).
- TLS positive test uses disposable containers + short-lived openssl certs;
  production PostgreSQL TLS deployment is RUST-04 scope.
- tracing callsite-interest is process-global: the log-capture test lives
  in its own `tests/logs.rs` binary by design.
- CI workflow is newly added and has not yet run on GitHub runners.

Security considerations:
- Fail-closed config; production requires verify-full CA/hostname TLS for
  remote DB and explicit CORS origins; loopback-only outside production.
- Logs exclude bodies, query strings, headers/Authorization, tokens,
  OPAQUE/ciphertext material, SQL parameters, raw DB errors; client
  request IDs are dropped, server UUIDs generated; fixed route names via a
  post-routing capture layer (outer middleware never sees raw paths).
- Advisory-locked single-writer migrations; adoption proves schema
  equivalence (tables/columns/sequences/constraints/indexes) before
  writing baseline checksums; drift/mismatch refuses without side effects;
  legacy history preserved for old-server rollback. No vault data read;
  disposable databases only.
- Resource bounds: 1 MiB body (configurable 1 KiB..16 MiB), 15 s request
  timeout, 64 concurrency (immediate 503, no queue), 10 s shutdown drain,
  pool max 10 / 2 s acquire.

Follow-up tasks:
- RUST-03 (needs RUST-02 integration): product parity routes on this
  foundation; align DTO validation with Bun reference behavior.
- RUST-04: Linux/container/client E2E, TLS deployment, cutover proposal.
- H02/external audit still gates any release; inherited rsa/rand findings
  stay open.
No RUST-03 work started; production not switched.
