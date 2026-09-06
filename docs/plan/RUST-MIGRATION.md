# Rust backend migration and handoff

Authority: user request 2026-09-06. Architecture: [ADR-0013](../decisions/ADR-0013-rust-backend.md).
The current agent stops after RUST-01. RUST-02/03/04 are left for another agent;
no follow-on agent is dispatched by this task. Existing backend stays operational.
The integration agent owns merge/status/release decisions.

## Sequence

RUST-01 (PoC REVIEW) -> integrator accepts/merges -> RUST-02 (foundation)
-> RUST-03 (product parity) -> RUST-04 (cutover evidence) -> human release gate.

| Task | Deliverable | Entry and exit |
|---|---|---|
| [RUST-01](../tasks/RUST-01.md) | Isolated native-stack PoC and this plan | No product routes; report with real DB and native crypto evidence |
| [RUST-02](../tasks/RUST-02.md) | Hardened foundation, exact remaining dependency pins, safe migration-history adoption, SQLx offline checks | RUST-01 integrated; fresh/existing DB and log/resource tests |
| [RUST-03](../tasks/RUST-03.md) | Existing auth/devices/account/sync behavior on Rust | RUST-02 integrated, auth-boundary review; complete parity/concurrency evidence |
| [RUST-04](../tasks/RUST-04.md) | Linux container/CI/client E2E, backup/rollback rehearsal, cutover proposal | RUST-03 integrated; security/release review, explicit production approval |

## Instructions for the next agent

1. Start from the integrator-approved RUST-01 commit/merge, not a different task's worktree.
2. Read MASTER, your task file, ADR-0013, RUST-01 report and referenced security/contracts.
3. Do RUST-02 first. Preserve API/crypto/sync fixtures, existing migrations and crypto pins.
4. Request integrator decisions for contract/approval blockers. Do not infer that Rust
   approval authorizes new authentication/recovery flows or accepts H02 findings.
5. Keep the Bun service as reference until client parity, baseline adoption and rollback
   are proven. Never shadow/replay production mutating auth or sync traffic.
6. Commit per task ID, leave REVIEW reports, and never merge your own branch.

## Required evidence beyond PoC

- Canonical OpenAPI DTO/response/error parity and language-neutral fixtures.
- Exact dependency/feature pins for all introduced crates; advisory/license/SBOM review.
- Compile-time SQLx queries, offline metadata, CI prepare --check.
- Existing schema_migrations -> SQLx baseline, fresh DB, schema drift rejection,
  repeatability, exclusive migration locking, old-server rollback compatibility.
- OPAQUE native/WASM parity with approved setup/credential formats and generic failures;
  setup lifetime, bounded admission/state and CPU execution, no secret telemetry.
- Sessions: refresh replay/concurrency, device binding/revocation, cross-account isolation.
- Account bundle codec/CAS, sync revision/idempotency/tombstone/concurrency parity.
- Shutdown/cancellation/load limits, CA/hostname validation, safe CORS and request IDs.
- Real web/extension/desktop compatibility, Linux build, recovery of encrypted backups,
  tested rollback, independent review and existing H02 release gates.

## Status bookkeeping

RUST-01's worker report records REVIEW without editing integrator-owned
`docs/plan/STATUS.md`. Integrator should add the RUST rows there when accepting the
planning commit; RUST-02/03/04 remain BLOCKED until dependencies are merged.
