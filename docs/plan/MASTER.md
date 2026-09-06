# Zero-Knowledge Password Manager — Agent Execution Plan

## Objective

Build a personal password manager with a zero-knowledge cloud and web client. The first release supports passwords, secure notes, TOTP, password generation, import/export, offline work, and encrypted synchronization. Chrome/Firefox extensions, desktop, and mobile are follow-on clients over the same contracts.

## Operating rules

- Work in isolated `agent/<task-id>-<slug>` worktrees; the integration agent owns merge and release branches.
- Read this file, the task file, referenced contracts, and `AGENTS.md` before editing.
- Edit only `Allowed paths`; do not change a frozen contract without an ADR and human security approval.
- Never invent cryptography. Rust is the only crypto implementation; clients consume its WASM/UniFFI bindings.
- Use atomic commits prefixed with the task ID. Do not merge your own branch.
- Every task ends with the completion report template in its task file.
- Security-sensitive changes require human review; public release requires external audit.

## Status model

`BLOCKED → READY → IN_PROGRESS → REVIEW → MERGED`

The integration agent is the only agent allowed to mark a task `MERGED`.

## DAG

```text
A00 ─┬─ A01 ─ A04 ─ H01 ─┬─ B01 ─ B03 ─┐
     ├─ A02 ──────────────┤             ├─ B05 ─┬─ C01 ─┐
     └─ A03 ──────────────┤             │      └─ C02 ─┴─ Q01 ─ H02 ─ R01
                          └─ B02 ─ B04 ─┘
R01 ─┬─ C04 (full browser-extension client)
     ├─ D01
     └─ D02
C01 ── C05 (React + TypeScript web-client migration)
B01+B02 ── RUST-01 (PoC only) ── RUST-02 ── RUST-03 ── RUST-04 ── human release gate
```

## Waves

| Wave | Tasks | Entry gate |
|---|---|---|
| 0 | A00 | repository is empty or existing state is documented |
| 1 | A01, A02, A03 | A00 merged |
| 2 | A04 | A01 and A02 merged |
| Gate | H01 | A04 vectors and threat model reviewed by a human |
| 3 | B01, B02 | H01; B02 may use A02 only |
| 4 | B03, B04 | B01/B02 as applicable |
| 5 | B05, C02 | B02+B04 and A02 |
| 6 | C01 | B03+B05+C02 |
| Gate | Q01 | B04+B05+C01+C02 merged; extension client excluded from MVP |
| Gate | H02 | Q01 clean or findings explicitly accepted |
| Release | R01 | H02 complete |
| Follow-on | C04, D01, D02 | R01 complete and envelope/sync stable |
| Client follow-on | C05 | C01 merged; API/crypto/sync contracts frozen |

## Rust backend migration (2026-09-06)

The user selected Rust and authorized the current agent to plan the migration and
finish **only RUST-01 Proof of Concept**. [ADR-0013](../decisions/ADR-0013-rust-backend.md)
selects Axum/Tokio/PostgreSQL/SQLx without an ORM. The [migration plan](RUST-MIGRATION.md)
assigns the remaining foundation, product parity, and cutover work to RUST-02/03/04
for another agent. Existing contracts, crypto approvals and release gates remain.
No production switch or follow-on dispatch is authorized by the PoC task.

## Integration policy

The integrator verifies allowed paths, contract compatibility, generated artifacts, migrations, lockfile changes, CI, and task acceptance criteria. Contract changes require an ADR in `docs/decisions/` and all affected tasks return to `READY`. No backend component may decrypt user vault data.

## Release gates

All unit, contract, integration, E2E, fuzz, SAST, dependency, secret-scanning, SBOM, and backup-restore checks pass; no Critical/High security finding remains; two devices sync offline edits without loss; recovery works only with the recovery key; and a database dump reveals no vault plaintext.
