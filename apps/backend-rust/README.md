# Rust backend (RUST-02 production foundation)

Isolated crate, not a replacement for `apps/backend` yet: the Bun service
remains the reference implementation until RUST-04 cutover approval.
Stack/decisions: [ADR-0013](../../docs/decisions/ADR-0013-rust-backend.md),
[migration handoff](../../docs/plan/RUST-MIGRATION.md),
[RUST-02 report](../../docs/plan/reports/RUST-02.md).

Rust 1.93.1, Axum 0.8.9, Tokio 1.53.1, SQLx 0.8.6/PostgreSQL 16 (no ORM:
explicit parameterized SQL, typed rows, compile-time `query!` macros and
subject-area storage functions). Exact direct pins/features: Cargo.toml;
full resolution: Cargo.lock. Standalone workspace; the existing root
crypto-core is linked with pinned version `=0.1.0` and unchanged sources.
Run Cargo commands **from this directory** so rust-toolchain.toml is honored.

## Commands

```sh
zkpm-backend serve        # HTTP API; never runs migrations implicitly
zkpm-backend migrate      # exclusive-locked forward migration runner
zkpm-backend healthcheck  # bounded DB probe, exit code 1 on failure
```

Configuration is strictly typed environment variables (`ZKPM_*`, see
`src/config.rs`); errors never echo supplied values and no `.env` file is
loaded. Development/test allow loopback only (bind and database host);
production additionally requires `ZKPM_DATABASE_TLS=verify-full` with a PEM
CA file for any non-loopback database host, and explicit `ZKPM_CORS_ORIGINS`
(exact origins, no wildcards). Defaults: bind `127.0.0.1:8080`, pool 10,
acquire timeout 2s, body limit 1 MiB, request timeout 15s, concurrency 64,
shutdown drain 10s.

## Local run

Use a dedicated disposable PostgreSQL 16 instance. This example has no
credentials and trusts only the isolated development container connection;
never use its trust configuration for production. Host publishing is
restricted to loopback.

```sh
docker run --detach --name rust02-postgres \
  --env POSTGRES_HOST_AUTH_METHOD=trust --env POSTGRES_DB=rust02 \
  --publish 127.0.0.1:55440:5432 postgres:16-alpine
cd apps/backend-rust
ZKPM_DATABASE_URL=postgres://postgres@127.0.0.1:55440/rust02 \
  cargo run --locked -- migrate
ZKPM_DATABASE_URL=postgres://postgres@127.0.0.1:55440/rust02 \
  cargo run --locked -- serve
```

- `GET /health/live`: 200 `{"status":"ok"}` even if the DB is unavailable.
- `GET /health/ready`: bounded compile-time `SELECT 1`; 200 `ok` or 503
  with a generic `ApiError` body (`error`, `message`, server-generated
  `requestId`).
- Product API routes do not exist yet (DTO skeleton in `src/dto.rs` maps
  `packages/contracts/openapi.yaml`; RUST-03 implements the routes).
- JSON logs carry only fixed route names, status, timing and generated
  request IDs; bodies, query strings, headers, tokens, SQL parameters and
  raw DB errors are never logged.
- Ctrl-C/SIGTERM drains in-flight requests within the shutdown bound.

## Migration history adoption

`migrations/` holds byte-identical copies of `db/migrations/*.sql`
(renamed to SQLx `000N_*.sql` numbering, versions 1-5). The originals stay
authoritative for the Bun backend. `migrate` serializes runs with a session
advisory lock, adopts an existing legacy `schema_migrations` history only
after proving schema equivalence (scratch-schema replay in a rolled-back
transaction), writes baseline rows with real SQLx checksums, and keeps the
legacy table in sync so the old server stays deployable. Fresh installs
apply all migrations and record both histories.

## Verify

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
cargo test --locked
RUST_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:55440/postgres \
  cargo test --locked --test postgres -- --ignored
```

The PostgreSQL suite needs a dedicated disposable server (trust auth only
for that local container), Docker for the pause/resume and TLS-container
scenarios, and `openssl` for test certificates. It creates private
databases per test and drops them afterwards; no production data is ever
touched.

SQLx compile-time checks use committed `.sqlx` offline metadata
(`SQLX_OFFLINE=true cargo build --locked --offline` works with no
`DATABASE_URL`). To regenerate after query changes: apply migrations to a
scratch database, then `cargo sqlx prepare` (with `DATABASE_URL` set) and
commit the result; CI enforces `cargo sqlx prepare --check`.

Dependency review: `cargo audit` (two inherited findings from the frozen
crypto-core pins, recorded in the RUST-02 report — this task must not
change them) and `cargo deny check advisories licenses sources bans`
(`deny.toml`).

Cleanup (only the dedicated container created above):

```sh
docker rm --force --volumes rust02-postgres
```

## Deliberately left to the next tasks

RUST-03: auth/devices/account/sync parity. RUST-04: Linux/container/client
E2E and reviewed cutover/rollback. Do not deploy this service publicly or
treat it as a completed backend rewrite.
