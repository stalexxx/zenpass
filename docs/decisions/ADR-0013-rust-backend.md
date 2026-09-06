# ADR-0013: Rust backend, SQLx without ORM, and bounded native PoC

Date: 2026-09-06.
Status: accepted for architectural direction and RUST-01 PoC by the user in this
session. Production migration/release is NOT approved by this record.
Supersedes only ADR-0001's backend-language choice once the migration is integrated.
Existing JS/Bun backend remains authoritative until RUST-04 cutover approval.

## Authority and scope

The user chose Rust, requested explicit technologies/crates/ORM policy, then
instructed: add to the plan, begin implementation, finish only Proof of Concept,
and leave the remainder to another agent. RUST-01 covers planning and PoC only.
This is not human approval to change authentication, recovery, cryptographic
suites, frozen contracts, or the trust boundary. Existing approval/release gates
remain in force; no earlier ADR is edited in place.

## Architecture and technology decisions

A modular monolith: HTTP -> application operations -> PostgreSQL; the existing
Rust crypto-core is invoked directly. No custom primitives or client-side crypto
operations in HTTP handlers. No server WASM adapter once fully migrated.
Modules: config, telemetry, HTTP/DTO/errors, auth, devices, account, sync, storage.
Start with one server crate; avoid generic CRUD repositories and unnecessary
internal crates. Keep the existing PostgreSQL schema and REST/JSON contracts.

| Concern | Selected technology/crates | Implementation boundary |
|---|---|---|
| Language/build | Rust stable, Cargo, edition 2024 | New backend only; old core edition/pins unchanged |
| Runtime | tokio | Minimal features; bounded pool/CPU work, shutdown |
| HTTP | axum | Existing REST/JSON; typed extractors/state |
| Middleware | tower, tower-http | Explicit timeouts, body/concurrency bounds, CORS, generated request IDs |
| Persistence | sqlx, PostgreSQL 16 | **No ORM**: neither SeaORM nor Diesel; no generic repository layer |
| Queries | SQLx query!/query_as!/query_file! macros | RUST-02 introduces offline .sqlx metadata, CI prepare --check |
| Migration runner | SQLx migrate, SQL files | RUST-02; explicit baseline adoption of existing schema_migrations |
| JSON | serde, serde_json | DTOs separate from internal/DB models |
| IDs | uuid | Current contract formats; no identifier-format migration |
| Time | time | UTC, existing wire precision/format |
| Binary transport | base64 | Existing prefixed/padded vs URL-safe encodings remain distinct |
| Errors | thiserror | Safe HTTP mapping; no raw SQL/parser errors to clients |
| Logging | tracing, tracing-subscriber | JSON allowlist; suppress dependency/SQL details |
| Config | std::env plus typed Config | Fail closed; no config framework |
| Commands | clap | serve/migrate/healthcheck at production-foundation stage |
| Secrets | secrecy, zeroize | No secret Debug/serialization; zeroization is best effort |
| Cryptography | existing crypto-core path dependency | Preserve exact approved crypto pins; no replacement library |
| Database TLS | SQLx rustls backend | PoC: tls-rustls-ring; production verifies CA/hostname |
| Edge TLS | existing Caddy | Production infra remains unchanged in PoC |
| Packaging | Docker, Debian slim GNU/glibc runtime, non-root | RUST-04 pins image digests and validates Linux build |
| Deployment | existing Docker Compose, single API instance | No Redis/Kubernetes/message broker added |
| Tests | cargo test, tokio::test, tower::ServiceExt, http-body-util | PoC implemented |
| Later verification | reqwest (dev), proptest (dev), cargo-fuzz | RUST-02/03/04; no unneeded runtime dependencies |
| Dependency checks | cargo-audit, cargo-deny | RUST-02/04 CI and closure/license review |

No utoipa/code-first OpenAPI or additional validator crate. Existing
packages/contracts/openapi.yaml remains the source of truth. Manually mapped DTOs
must pass language-neutral contract fixtures and endpoint parity tests. Serde
shape validation plus explicit semantic validation must preserve unknown-field,
null/optional, binary-codec and rejection semantics.

## Why SQLx without ORM

Current sync/session/device operations use explicit transactions, row locks and
PostgreSQL advisory locks. SQLx keeps these visible and parameterized while offering
compile-time SQL/type checks. Those checks do not prove ownership, idempotency,
race safety or isolation; real concurrent PostgreSQL tests are mandatory.
No string interpolation of values or user-supplied SQL identifiers.

Migrations remain forward-only reviewed SQL. Run once as a separate deploy job,
not implicitly on API startup. SQLx's history is different from the existing
schema_migrations table: compare applied versions and actual schema, validate an
explicit baseline, never replay historical DDL blindly, and test both fresh and
upgraded databases plus rollback to the old application. Do not mark baseline
checksums accepted without independently establishing schema equivalence.

## Version and feature policy

RUST-01 pins Rust **1.93.1** in the package's rust-toolchain.toml, and every direct
registry dependency exactly in apps/backend-rust/Cargo.toml. Cargo.lock records the
full PoC resolution. Use --locked. The standalone workspace avoids rewriting the
approved root Cargo.lock. Resolving a separate lock is not an audit of its
transitive dependency closure; that remains an explicit RUST-02/04 gate.

Verified registry metadata: SQLx 0.9.0 requires Rust 1.94.0; choose **SQLx 0.8.6**
for this 1.93.1 PoC, not an implicit compiler/crypto-stack upgrade. Axum **0.8.9**,
Tokio **1.53.1**, secrecy **0.10.3**, serde **1.0.229**, thiserror **2.0.20**,
tracing **0.1.44**, tracing-subscriber **0.3.23**; dev tower **0.5.3**,
http-body-util **0.1.4**, serde_json **1.0.151**. Cargo.toml is authoritative for
features. Non-PoC crates listed above are selected technologies, not already
validated/pinned dependencies: RUST-02 must pin compatible versions and exact
features when introducing them, and document them before product migration.
No wildcard versions, opportunistic upgrades, or cryptographic pin changes.

## Authentication, concurrency, and sensitive data

Preserve existing OPAQUE exchange, token/session/device semantics and rate limits;
no JWT/OAuth framework replacement. CPU-bound crypto runs in spawn_blocking after
acquiring a bounded semaphore. Keep the permit inside the closure: HTTP timeout
cannot cancel an already running blocking task. Bound pending work and login state.

Keep one API instance until a separately approved shared-state design exists.
Pending OPAQUE login state must have bounded capacity, TTL and atomic one-time
consumption. Durable throttling stays in PostgreSQL. No change to missing recovery
or WebAuthn contracts is implied by this ADR.

Logs exclude bodies, ciphertext, token/OPAQUE material, keys, query strings, SQL
parameters, raw database errors and untrusted request IDs. Use fixed route names,
status and timing; production adds server-generated correlation IDs. Avoid default
TraceLayer spans containing full URI. TLS libraries implement transport security;
application vault/OPAQUE/token primitives stay in crypto-core per existing policy.

## PoC boundary and consequences

Only loopback health/live, health/ready, typed local DB configuration, allowlisted
logs, graceful shutdown, real SQLx readiness/transaction tests, and native-core
OPAQUE smoke tests. PoC's constant SELECT 1 is runtime typed SQLx, deliberately not
claimed as compile-time query/offline-metadata validation. No auth/sync routes,
migrations, CLI framework, production TLS, deployment changes or client switch.

The new crate compiles a native dependency on crypto-core. OPAQUE is exercised in
tests with ephemeral generated input, never exposed as an HTTP endpoint. This
proves native compatibility, not protocol parity with WASM or a completed audit.

Threats affected: T02/T09/T10 (future authorization/transactions), T11/T15 (logs),
T12 (new dependency closure), T17 (timeouts/resources), T19 (native secret lifetime).
RUST-01 does not close any existing H01/H02 residual finding. RUST-02/03/04 must
retain security review and external audit requirements before release.

## Sources

- https://docs.rs/axum/0.8.9/axum/
- https://docs.rs/sqlx/0.8.6/sqlx/macro.query.html
- https://docs.rs/crate/sqlx/0.9.0 (MSRV also confirmed via cargo info)
- https://docs.rs/tokio/1.53.1/tokio/task/fn.spawn_blocking.html
- Existing ADR-0003, ADR-0005, ADR-0006 and frozen api/sync/crypto contracts.
