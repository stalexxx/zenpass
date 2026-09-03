# ADR-0004: Metadata leakage budget and retention (SD-0005)

Status: **PROPOSED — UNSIGNED.** This ADR records no decision. It is the
preparation draft for the human security approval of the metadata leakage
budget and retention policy required by SD-0005
(`docs/security/DECISIONS.md`). It was added to close record-integrity gap
G-08 (`docs/security/H01-REVIEW-CHECKLIST.md` §4, issue #1 follow-up):
the decision register referenced an `ADR-0004` that did not exist as a file.
Every policy decision below is explicitly **PENDING**; no budget value,
retention period, or disclosure wording is chosen or inferred by this draft.
Metadata policy may not be treated as approved until this ADR carries a
signature.

## Context

- SD-0005: "Metadata leakage is minimized, not zero; budget and retention
  require approval." Reviewer: pending. Evidence expected: T11 verification
  and metadata inventory. Affected tasks: A01, A02, B02, B05, Q01, R01.
- `docs/security/THREAT-MODEL.md` T11 mitigation: encrypt names/URLs/
  usernames and sensitive fields; minimize and document size/timing/change
  metadata and telemetry. Verification: wire/DB/backup/log inspection,
  metadata inventory, and negative assertions.
- `docs/security/THREAT-MODEL.md` "Open questions" items 2 (accepted
  metadata leakage budget and user-facing disclosure) and 4 (backup
  retention/deletion across live data, replicas, object storage, and backup
  expiry) are unresolved and are owned by this ADR.
- `docs/contracts/sync-v1.md` and `docs/contracts/api-v1.md` (with
  `packages/contracts/schemas/item-record.schema.json`) define the fields the
  backend legitimately stores and transmits; these are the factual source for
  the inventory below.
- B05 must implement sync "retention" (tombstones) and may not invent
  retention values; the concrete values must originate from approval of this
  ADR.
- Q01 owns the release-gate evidence (dump inspection, backup restore drill)
  that must demonstrate compliance with whatever budget is approved here.

## Metadata inventory (factual, contract-derived — not a decision)

Compiled at HEAD `4d18633` from sync-v1, api-v1, and the JSON schemas. This
table is a **draft inventory**: the authoritative T11 "metadata inventory"
verification artifact must be produced by inspecting the implemented wire,
database, backup, and log surfaces (Q01, with B02/B05 owners) before
signature; discrepancies append findings below.

| Surface | Data | Exposure characteristics |
|---|---|---|
| Sync item record | `itemId`, `vaultId` | Stable per-item/vault identifiers; enable correlation of changes to the same item within and across sessions |
| Sync item record | `ciphertext` length | Approximates plaintext item size (bounded by the 1 MiB envelope limit); not padded by the current contract |
| Sync item record | `envelopeVersion`, `revision` | Protocol version; per-item change count/frequency |
| Sync item record | `deleted` (tombstone) | Existence and timing of deletion; tombstone lifetime is the retention decision D-3 |
| Sync item record | `createdAt`, `updatedAt` | Item creation/change timing available to the server |
| Mutations | `mutationId`, `baseRevision` | Idempotency linkage and conflict/retry patterns |
| Change feed | opaque cursor, pagination `limit` | Read progress and access timing patterns |
| Devices | `name` (user-provided free text), `publicKey`, enrollment/last-seen timing | Device fingerprinting/correlation; names may themselves be sensitive |
| Auth/session | OPAQUE messages (no password material), token issuance/expiry/rotation, rate-limit counters | Login/logout cadence, guessing-attempt timing |
| Infrastructure | TLS/load-balancer/access logs, source IP, user agent | Network-layer identity and timing; retention governed by decision D-5/D-6 |
| Logs/telemetry | Structured redacted logs (no bodies/tokens/ciphertext per api-v1) | Scope and redaction guarantees are decision D-6 (T15) |
| Backups | Live data replicas, object storage, backup expiry | Deletion propagation is decision D-4/D-5 (open question 4) |

## Decisions to be approved (all PENDING)

| # | Decision | Status | Notes and constraints |
|---|---|---|---|
| D-1 | Accepted metadata leakage budget: the definitive list of server-visible metadata and its precision (timestamp granularity, size observability, identifier stability, timing correlation) | **PENDING** | Post-approval additions require a new ADR row; the inventory above is input, not the budget |
| D-2 | User-facing disclosure wording for residual metadata exposure | **PENDING** | Threat-model open question 2; wording requires human review |
| D-3 | Tombstone and conflict-history retention: lifetime, purge semantics, and whether tombstoned ciphertext length remains observable | **PENDING** | B05 implementation input; no value may be inferred by tasks or this draft |
| D-4 | Account deletion (`/account/delete` returns 202 "Deletion scheduled"): grace period, cascade scope, and deletion verification | **PENDING** | Scheduling semantics currently undefined in contracts |
| D-5 | Backup retention/expiry across live data, replicas, and object storage | **PENDING** | Threat-model open question 4; no value chosen here |
| D-6 | Telemetry/diagnostics scope and redaction guarantees (T15) | **PENDING** | Must be consistent with B02 redacted-logging acceptance criteria |
| D-7 | Acceptance of residual leakage risk after D-1..D-6 are set | **PENDING** | Recorded as findings below with severity and rationale |

Out of scope for this ADR: any mitigation that would alter
`crypto-envelope/v1` bytes or semantics (for example ciphertext padding to
hide lengths) — such a change requires a contract v2, its own ADR, and
renewed H01 approval (SD-0003). This draft changes no contract and creates
no backend code.

## Evidence required before signature

| Evidence | Owner | Status |
|---|---|---|
| Verified metadata inventory: wire/DB/backup/log inspection with negative assertions (T11) | Q01 owner, with B02 and B05 owners | Not started; blocked on implementation waves |
| Dump/backup inspection demonstrating no vault plaintext and documenting residual metadata (release gate) | Q01 owner | Pending Q01 entry |
| Retention mechanisms implemented exactly per approved D-3..D-5 values, with tests | B05 owner (sync retention), B02 owner (infra/backup) | Blocked (B02 review rework; B04 pending H01) |
| Redacted-logging/telemetry verification (T15) | B02 owner, verified in Q01 | Pending B02 completion |
| Disclosure text (D-2) reviewed for accuracy against the implemented budget | Human security reviewer with product/UX owner (A03 artifact owner) | Not started |
| Register/status updates on approval | Integration agent | On signature only |

## Findings record

| ID | Severity | Description | Affected | Disposition | Status |
|---|---|---|---|---|---|
| — | — | None recorded at preparation of this draft | — | — | — |

Rules: append rows only, never edit a recorded finding; Critical/High
findings block R01 until fixed or formally accepted (SD-0006); severity and
disposition belong to the human reviewer.

## Signature

I have reviewed the verified metadata inventory and evidence, and record my
decision on the metadata leakage budget and retention policy (D-1..D-7).

| Field | Value |
|---|---|
| Reviewer name | — |
| Role | Human security reviewer (SD-0005) |
| Decision | ☐ Approve budget and retention as recorded ☐ Approve with findings (all dispositions recorded above) ☐ Reject — return to owners |
| Date | — |
| Signature/attestation | — |

**No signature recorded as of preparation of this draft.**

## Effects of approval (on signature only)

- SD-0005 in `docs/security/DECISIONS.md` moves from open to approved; the
  integrator updates the register and threat-model open questions 2 and 4.
- B05 receives concrete retention values (D-3..D-5); Q01 gains acceptance
  criteria derived from the budget (D-1) for the T11, dump-inspection, and
  backup-restore gates; R01 requires the user-facing disclosure (D-2).
- Any contract change needed to satisfy the budget returns affected tasks to
  READY via the integrator; crypto-envelope changes additionally require a
  v2 ADR and H01 re-approval.
- Public release still requires the external audit (SD-0006, H02).
