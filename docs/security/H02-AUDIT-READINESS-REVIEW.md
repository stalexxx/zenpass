# H02 audit-readiness review

Date: 2026-09-04
Reviewer: Claude (agent), preparatory pass only

## Purpose and status of this document

This document is **preparatory work for H02, not the H02 external audit itself**.
It independently checks that the Q01 evidence, the Q01 findings register, and
the `H02-RESIDUAL-RISK-ACCEPTANCE.md` decision are internally consistent, and
that the boundary between what is accepted for personal/internal use and what
still blocks public release is stated unambiguously. It does not add new
security testing beyond re-running the existing read-only regression gates.

**This review does not close H02 or R01.** `MASTER.md`'s DAG requires H02 to be
an external security audit of crypto-core, OPAQUE integration, recovery,
extension isolation, sync rollback, and supply chain (`docs/tasks/H02.md`).
Claude is not an independent external auditor: it has full access to the
source and design rationale, cannot hold professional liability for findings,
and cannot perform the black-box/adversarial testing an external audit firm
would perform. `STATUS.md`'s H02 row must remain `BLOCKED` (owner: external
auditor) and R01 must remain `BLOCKED` until that audit happens and its
findings are remediated or formally accepted by a human security owner.

## Personal/internal vs. public release boundary

| | Personal/internal deployment | Public release |
|---|---|---|
| Q01-001 (no external audit) | **Accepted residual risk** (`H02-RESIDUAL-RISK-ACCEPTANCE.md`, 2026-09-04) | **Hard blocker.** Independent external audit of crypto-core, OPAQUE, recovery, sync anti-rollback, extension isolation, and supply chain required. |
| Q01-002 (unsigned metadata/backup/disclosure policy) | Accepted residual risk | Blocker. Policy values must be approved and published in the relevant ADR/runbook before release. |
| Q01-003 (dependency-light SAST/secret/SBOM baseline only) | Accepted residual risk | Blocker. Maintained vulnerability, secret, license, and SBOM attestation service must be added to CI and evidence retained with the release. |
| H02 task status | Not required to proceed with personal use | `BLOCKED`, owner `external auditor` — must stay `BLOCKED` in `STATUS.md` until real audit evidence exists |
| R01 (release) | N/A — release gate is for public release, not personal use | `BLOCKED` on H02; cannot be marked `MERGED` by this or any preparatory review |

The acceptance in `H02-RESIDUAL-RISK-ACCEPTANCE.md` is explicit that it is
scoped to personal/internal deployment only, is not external audit evidence,
and does not authorize relaxing any cryptographic or zero-knowledge guarantee.
This review found that scoping consistent across `Q01-FINDINGS.md`,
`Q01-GATE-REPORT.md`, and `STATUS.md`'s Q01/H02 rows — none of them claim H02
or R01 is satisfied.

## Q01-001..003 evidence/gap/owner table

| ID | Severity | Evidence that exists today | What is still missing | Owner | Blocks public release? |
|---|---|---|---|---|---|
| Q01-001 | High | Full automated Q01 harness (`docs/security/Q01-GATE-REPORT.md`): two-device offline/reconnect E2E against real PostgreSQL + WASM OPAQUE, isolated dump inspection, isolated backup/restore, dependency-light SAST/secret/SBOM baseline, `bun audit` clean. `cargo test --workspace` (64 tests) passing. Human residual-risk acceptance recorded for personal/internal use. | Independent, credentialed external security audit report covering crypto-core, OPAQUE integration, recovery flow, extension isolation, sync anti-rollback, and build supply chain; any resulting findings tracked to remediation or formal acceptance. | H02 / human security reviewer (external auditor) | **Yes — hard blocker** |
| Q01-002 | Medium | Automated dump inspection runs against test-only forbidden terms; ADR-0004 exists as the vehicle for the policy. | Signed-off metadata-leakage budget, backup-retention period, and user-facing disclosure language in ADR-0004/runbooks; production forbidden-term list supplied by an operator. | Human security reviewer / R01 release owner | **Yes** |
| Q01-003 | Medium | `bun run test:security` baseline: secret scan (private-key/live-token signatures), dynamic-eval SAST guard, SBOM-input dependency-graph check — all passing (re-verified this review, see Verification below). `bun audit` clean (re-verified). | A maintained SAST/secret-scanning/license/SBOM attestation service (not a bespoke lightweight harness), with its output retained as part of the release evidence. | R01 release owner | **Yes** |

No Q01-001..003 finding is disposed as fully closed; all three remain
residual risks accepted for personal/internal use only, exactly as recorded
in `Q01-FINDINGS.md`.

## Checks an external auditor should independently reproduce

An external audit satisfying H02 should, at minimum, re-run and extend beyond
these automated gates rather than trust them at face value:

1. **Crypto-core review**: manual/independent review of `crates/crypto-*`
   (envelope format, Argon2id calibration, key hierarchy, zeroization) against
   `docs/security/THREAT-MODEL.md` T08/T19 and ADR-0003, including adversarial
   fuzzing of the wire format beyond the existing golden-vector tests.
2. **OPAQUE integration**: independent verification of the OPAQUE
   registration/login binding against the reference protocol, including
   server-side misuse and downgrade attempts (T08, T09).
3. **Recovery flow**: attempt account takeover via the recovery path,
   malformed recovery keys, and reset-then-revoke races (T14).
4. **Extension isolation**: hostile content-script/page E2E against the
   Chrome/Firefox extension boundary, beyond C03's baseline minimum-permission
   tests — full unlock/save/TOTP flows are explicitly deferred to C04 per
   `Q01.md` and are not yet auditable end-to-end.
5. **Sync anti-rollback**: adversarial replay, reorder, and rollback attempts
   against the mutation/change-feed contracts (T10), beyond the two-device
   happy-path E2E in the Q01 harness.
6. **Supply chain**: reproducible-build verification, dependency provenance,
   and a maintained (non-bespoke) SAST/secret/license/SBOM scan with signed
   attestations retained (T12, T13), superseding the Q01-003 baseline.
7. **Dump/backup drill on production-shaped data**: re-run
   `Q01_DUMP_INSPECTION=1`/`Q01_BACKUP_RESTORE=1` against a realistic (not
   test-only) forbidden-term list and production-scale data.
8. **Policy sign-off review**: confirm ADR-0004's metadata/backup/disclosure
   values match what was actually implemented (Q01-002).

## Verification performed for this review (read-only, no product changes)

- `bun audit` — no vulnerabilities found.
- `bun run test:security` — 3 pass, 2 skip (dump-restore tests skip without
  `Q01_DUMP_INSPECTION=1`/`Q01_BACKUP_RESTORE=1` + `TEST_DATABASE_URL`, matching
  the documented gating in `Q01-GATE-REPORT.md`), 0 fail.
- `bun run check:boundaries` — package boundaries valid.

No plaintext vault data, keys, passwords, or TOTP secrets were created,
logged, or persisted while producing this review.

## References

- `docs/tasks/H02.md`, `docs/tasks/Q01.md`
- `docs/security/Q01-FINDINGS.md`
- `docs/security/Q01-GATE-REPORT.md`
- `docs/security/H02-RESIDUAL-RISK-ACCEPTANCE.md`
- `docs/security/THREAT-MODEL.md`
- `docs/plan/MASTER.md`, `docs/plan/STATUS.md`

## Explicit non-closure statement

This review does not satisfy `docs/tasks/H02.md`'s acceptance criteria. It
performs no external audit, engages no independent auditor, and grants no
sign-off. `STATUS.md` must continue to show H02 as `BLOCKED` (owner: external
auditor) and R01 as `BLOCKED` on H02 until a genuine external audit is
completed and its findings are remediated or formally accepted by a human
security owner.
