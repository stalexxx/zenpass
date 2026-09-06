# RUST-01: Native Rust backend proof of concept

Status: REVIEW. Owner: current implementation agent.
Authority: user chose Rust and authorized planning plus implementation through PoC only (2026-09-06).
Dependencies: existing B01/B02 and frozen A02 contracts. No production release authority.

## Goal and allowed paths

Prove Axum + Tokio + SQLx/PostgreSQL + native crypto-core coexist in a reproducible,
standalone backend package, without replacing the Bun service.
Allowed paths: `apps/backend-rust/`, `docs/tasks/RUST-01.md`,
`docs/tasks/RUST-02.md`, `docs/tasks/RUST-03.md`, `docs/tasks/RUST-04.md`,
`docs/decisions/ADR-0013-rust-backend.md`, `docs/plan/MASTER.md`,
`docs/plan/RUST-MIGRATION.md`, `docs/plan/reports/RUST-01.md`.
The planning paths are explicitly included by the user's planning instruction.
Do not modify root workspace/lockfile, existing backend, crypto-core, contracts,
existing migrations, production infrastructure, or integrator-owned STATUS.md.

## Inputs (read before implementation)

- `docs/plan/MASTER.md`, `docs/plan/INTEGRATOR.md`
- `docs/contracts/api-v1.md`, `docs/contracts/crypto-envelope-v1.md`, `docs/contracts/sync-v1.md`
- `docs/security/THREAT-MODEL.md`, `docs/security/DECISIONS.md`
- `docs/decisions/ADR-0001-stack.md`, `docs/decisions/ADR-0003-crypto-envelope-v1-approval.md`, `docs/decisions/ADR-0006-b04-opaque-server-binding-and-scope.md`

## Deliverables and acceptance

- ADR, staged migration plan, and bounded follow-on tasks for another agent.
- Standalone Cargo workspace under apps/backend-rust with exact direct pins,
  lockfile and pinned installed compiler; no existing crypto dependency upgrades.
- Local-only HTTP service: GET /health/live (200) and GET /health/ready
  (200 only after a bounded real SELECT 1; 503 otherwise); all other routes absent.
- Typed, redacted configuration, finite DB pool/timeouts, graceful shutdown.
- Allowlisted request logging tested against untrusted URI/header/body markers.
- Native OPAQUE round-trip and malformed-message tests: ephemeral generated input
  only, no secret printing/persistence or public authentication endpoint.
- Real PostgreSQL integration test for readiness and transaction rollback.
- fmt, clippy, build and all PoC tests pass; README reproduces verification.
- STOP at PoC; future production features remain unimplemented and undispatched.

## Completion

Use the standard report in `docs/plan/INTEGRATOR.md`; leave work in REVIEW for
integration, never merge this branch. Report blockers to integrator via report.

Verification complete: 9 ordinary tests plus 1 explicitly executed real-PostgreSQL test passed; fmt, clippy and locked build passed. See `docs/plan/reports/RUST-01.md`.
