# RUST-04: Rust backend integration and cutover proposal

Status: REVIEW. Reviewed cutover candidate produced; production switch NOT
executed or authorized by this task — see docs/plan/reports/RUST-04.md.
Dependencies: RUST-03 integrated, parity accepted, security findings reviewed.
Goal: produce a concrete reviewed deployment/rollback candidate; production switch
requires explicit user release authorization and existing H02 gates.

Allowed paths: `apps/backend-rust/`, `infra/rust-backend/`,
`.github/workflows/rust-backend.yml`, `tests/rust-backend/`,
`docs/tasks/RUST-04.md`, `docs/plan/reports/RUST-04.md`.
Changes outside these paths (including production Compose/Caddy switching and old
backend removal) require integration task ownership and approved cutover scope.
Inputs: MASTER/INTEGRATOR, RUST-MIGRATION, ADR-0013, RUST-01/02/03 reports,
frozen API/crypto/sync contracts, current security/H02/release/backup runbooks,
existing deployment and web/extension/desktop E2E instructions. Read before edits.

Required deliverables:
- Non-root Linux GNU/glibc backend container: multi-stage build, Debian slim runtime,
  compiler/crate/image pins, --locked build, CA certificates and safe config.
- Separate migration job, private DB connectivity, existing Caddy integration design,
  liveness/readiness and bounded graceful shutdown/resource limits.
- CI fmt/clippy/unit/real-PG/contract checks, offline SQLx check, dependency/advisory/
  license/SBOM/security evidence. Address PoC's unreviewed transitive closure.
- Existing web/extension/desktop smoke and full relevant user-flow E2E against Rust,
  backup restore on disposable DB, migration-baseline and old-server rollback drills.
- Cutover runbook with exact candidate artifacts, backup/restore point, health and
  parity criteria, rollback triggers; drain/invalidate in-flight login state safely.
  Never replay production mutating traffic to both backends for comparison.

Acceptance: all evidence passes, no unaccepted critical/high finding, independent
review and existing external-audit/release gates satisfied. Prepare artifacts first;
request production authorization only for the concrete reviewed final switch.
Keep old backend available for approved rollback; no self-merge.
Completion: standard INTEGRATOR.md report with commands/results and explicit gates.
