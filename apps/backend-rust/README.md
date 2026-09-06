# RUST-01 backend proof of concept

Isolated **local-only PoC**, not a replacement for `apps/backend`.
Stack/remaining work: [ADR-0013](../../docs/decisions/ADR-0013-rust-backend.md),
[migration handoff](../../docs/plan/RUST-MIGRATION.md).

Rust 1.93.1, Axum 0.8.9, Tokio 1.53.1, SQLx 0.8.6/PostgreSQL (no ORM).
Exact direct pins/features: Cargo.toml; full resolution: Cargo.lock. Standalone
workspace; existing root crypto-core is linked without source or direct-pin changes.
Run Cargo commands **from this directory** so rust-toolchain.toml is honored.

## Run

Use a dedicated disposable PostgreSQL 16 instance. This example has no credentials
and trusts only the isolated development container connection; never use its trust
configuration for production. Host publishing is restricted to loopback.

```sh
docker run --detach --name rust01-poc-postgres \
  --env POSTGRES_HOST_AUTH_METHOD=trust --env POSTGRES_DB=rust01_poc \
  --publish 127.0.0.1:55439:5432 postgres:16-alpine
cd apps/backend-rust
POC_DATABASE_URL=postgres://postgres@127.0.0.1:55439/rust01_poc cargo run --locked
```

Default bind: `127.0.0.1:3100`, override with `POC_BIND` (numeric loopback only).
`POC_DATABASE_URL` is mandatory; only numeric loopback PostgreSQL hosts allowed.
Configuration errors never echo supplied values. No .env file is loaded.

- `GET /health/live`: 200, `{"status":"ok"}` even if DB unavailable.
- `GET /health/ready`: bounded SELECT 1; 200 `ok` or 503 `not_ready`.
- Product API routes do not exist. No migrations or data writes at server startup.
- Ctrl-C/SIGTERM triggers graceful shutdown with a five-second drain bound.
- Pool max 4; readiness/acquire timeout 2 seconds.
- Fixed JSON log target/fields; RUST_LOG cannot enable SQL or dependency dumps.

## Verify

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
cargo test --locked
POC_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:55439/rust01_poc \
  cargo test --locked --test postgres -- --ignored
```

The PostgreSQL test is explicitly ignored in the ordinary suite, **not counted as
passing there**. Run the second command to verify actual readiness and rollback of
a parameterized insertion in a connection-local temporary table. It creates no
application tables and never reads vault data. Missing test URL fails that run.

Native OPAQUE tests call the existing core in-process with fresh generated input,
then drop secret buffers. No fixed password/key fixture, no secret output, no HTTP
auth handler. Blocking smoke work holds its semaphore permit inside the closure.
Tests prove native compatibility, not native/WASM parity or audited production auth.

Cleanup (only the dedicated container created above):

```sh
docker rm --force --volumes rust01-poc-postgres
```

## Deliberately left to the next agent

RUST-02: production config/middleware/CLI, remaining crate pins, SQLx compile-time
queries/offline metadata, migration-history adoption, dependency/TLS/CI review.
RUST-03: auth/devices/account/sync parity. RUST-04: Linux/container/client E2E and
reviewed cutover/rollback. Existing production infrastructure stays on Bun.
PoC only uses a constant runtime-typed SELECT 1, not query! or a migration runner.
Do not deploy this service publicly or treat it as a completed backend rewrite.
