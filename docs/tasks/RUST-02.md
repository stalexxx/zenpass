# RUST-02: Rust production foundation and database baseline

Status: REVIEW. Owner: next agent, not dispatched by RUST-01.
Dependencies: RUST-01 integrated and its report accepted by integration agent.
Goal: prepare the selected stack for product parity without switching production.

Allowed paths: `apps/backend-rust/`, `docs/tasks/RUST-02.md`,
`docs/plan/reports/RUST-02.md`, `.github/workflows/rust-backend.yml`.
Forbidden: existing backend, crypto implementation/pins, existing migrations,
contracts, root Cargo workspace/lock, production deployment configuration.

Inputs: MASTER.md, INTEGRATOR.md, RUST-MIGRATION.md, RUST-01 report, ADR-0013,
ADR-0003/0005/0006, all docs/contracts/*-v1.md, packages/contracts/openapi.yaml,
THREAT-MODEL.md, DECISIONS.md, current db/migrations/*.sql and backend db.mjs.
Read all before editing. Integrator resolves scope/approval blockers.

Required implementation:
- Exact version/features for remaining selected foundation dependencies (including
  tower-http, clap, uuid, time, base64, zeroize as used); resolve and scan closure,
  record dependency/license/SBOM evidence without changing approved crypto pins.
- CLI serve/migrate/healthcheck, strict environment config, pool/query limits,
  bounded shutdown, CORS allowlist, generated correlation IDs, redacted JSON logs.
- Existing OpenAPI-sourced DTO mapping and safe application error mapping.
- SQLx compile-time query checks, offline .sqlx metadata and CI prepare --check.
- Migration runner with exclusive locking and explicit old-history baseline adoption.
  Preserve original SQL bytes; compare actual schema before adoption. No blanket
  "mark all applied" and no historical migration replay on an existing database.
- DB TLS CA/hostname verification; isolated test mode separated from production config.

Tests/acceptance:
- Fresh DB, upgraded copy, re-run, schema drift rejection, concurrent migration
  invocations, partial failure and old-server schema compatibility.
- Malformed config/errors, TLS failure, header/body/query/SQL log exclusion,
  body/time/concurrency limits, shutdown with active connections, health transitions.
- fmt/clippy/build/test --locked; real PostgreSQL 16 CI, SQLx offline rebuild/check.
- No auth/sync implementation or production cutover in this task.

Completion: standard INTEGRATOR.md report, task-ID commits, REVIEW only; never merge.
