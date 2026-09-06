# RUST-03: Existing backend behavior on Rust

Status: BLOCKED. Owner: next agent, not dispatched by RUST-01.
Dependencies: RUST-02 integrated; integrator/security review of native auth boundary
and the remaining existing H01/H02 constraints. No new auth/recovery contract authority.

Allowed paths: `apps/backend-rust/`, `docs/tasks/RUST-03.md`,
`docs/plan/reports/RUST-03.md`.
Forbidden: existing backend, contracts/fixtures, crypto-core or other crypto packages,
existing DB migrations, clients, root workspace, production infrastructure.
Inputs: MASTER/INTEGRATOR/RUST-MIGRATION, RUST-01/02 reports, ADR-0013,
ADR-0003/0005/0006/0008/0011, current security decisions/threat model/audit findings,
all frozen API/crypto/sync contracts, OpenAPI, sync-state-machine and fixtures,
existing apps/backend/src auth/devices/account/sync code and tests. Read before edits.

Required behavior:
- Native crypto-core OPAQUE server exchange preserving setup/record/message encoding,
  generic auth failures, rate/admission limits, bounded TTL state with atomic take.
  Bounded spawn_blocking work with permit held until actual completion.
- Existing session issue/hash/rotation/logout and device enrollment/revoke behavior,
  including current device and issued_via provenance rules. All application crypto
  stays in approved crypto-core. If token helpers are missing, escalate through
  integration; do not add hashes/random/token primitives in server code.
- Existing account bundle codec, authorization and CAS; implement only existing
  approved endpoint surface. Do not invent recovery-reset or WebAuthn support.
- Sync ownership, baseRevision, mutationId replay, tombstones, monotonic changes,
  cursor encoding and exact conflict/rejection semantics.
- DTO/errors/wire parity proven against the Bun reference in isolated test databases.

Required tests:
- Native/WASM interoperability against existing approved fixtures and client flows;
  ephemeral secret input only, no printed/stored plaintext or session/OPAQUE secrets.
- Wrong/malformed/replayed/concurrent auth, refresh, enrollment and revoke; verify
  cross-account isolation, revoked-session behavior and state cleanup under limits.
- Concurrent sync/CAS, duplicate mutation replay, stale revision, tombstones,
  ordering, pagination and rollback/failure injection with real PostgreSQL.
- Shared frozen fixtures unchanged; fmt/clippy/build/test --locked; log redaction.

Exit: complete parity report plus explicit remaining limitations/security blockers.
No client switch, production deploy, merge or release. Standard integration report.
