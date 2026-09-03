# ADR-0003: Human security approval of crypto-envelope/v1, KDF calibration, crypto libraries, and recovery semantics

Status: **PROPOSED — UNSIGNED.** This ADR records no decision. It is the H01
approval/finding record template prepared for the human security reviewer.
Cryptographic implementation may not merge until this ADR carries a signature
(`docs/tasks/H01.md`, `docs/security/DECISIONS.md` SD-0003).

## Context

- `docs/contracts/crypto-envelope-v1.md` defines the normative bytes
  (envelope, AAD, canonical CBOR, Argon2id parameters, OPAQUE suite, typed
  errors, versioning/migration, recovery reset).
- `fixtures/crypto/` contains language-neutral fixtures: AAD canonicalization,
  malformed-envelope rejections, KDF parameter encoding, recovery semantics.
- `docs/security/THREAT-MODEL.md` (A01, merged) and
  `docs/security/RECOVERY.md` define the security objective and recovery
  guarantees; SD-0004 approved the irreversibility principle.
- Known evidence gaps G-01..G-10 are registered in
  `docs/security/H01-REVIEW-CHECKLIST.md` §4. Gaps G-01..G-06 currently block
  full vector and library verification.

## Decision to be approved (what a signature covers)

1. Freeze `crypto-envelope/v1` byte format: algorithms, key hierarchy, AAD
   construction, canonical envelope, limits, and typed errors as written.
2. Approve Argon2id calibration policy (500–1000 ms target; `memoryKiB ≥
   65536`, `iterations ≥ 3`, `parallelism ≥ 1`, ≤ 25 % physical memory;
   parameters never silently weakened).
3. Approve the OPAQUE RFC 9807 Ristretto255 suite usage rules as written.
4. Approve the specific crypto libraries, versions, and licenses listed in
   the Library approval table below (table must be filled before signature).
5. Approve recovery reset/rotation semantics: independent wrap, one-time
   display with confirmation challenge, client-side reset, session/device
   revocation, wrapper version increment, permanent loss with no support
   bypass.
6. Accept the disposition of every finding recorded below.

## Library approval table (to be completed before signature)

| Primitive | Library | Exact version | License | Maintenance/audit notes | Reviewer verdict |
|---|---|---|---|---|---|
| Argon2id (RFC 9106) | — | — | — | — | — |
| XChaCha20-Poly1305 (IETF) | — | — | — | — | — |
| OPAQUE (RFC 9807, Ristretto255) | — | — | — | — | — |
| Canonical CBOR (RFC 8949) | — | — | — | — | — |

Constraints: primitives live only in `crates/crypto-core` (`unsafe_code =
"forbid"`); clients consume bindings (SD-0001); upgrades re-run vector
verification with a new ADR row; suite changes require H01 re-approval.

## Independent verification evidence (to be completed)

| Step (checklist §3.2) | Tool + version | Command(s) | Result/digest | Date |
|---|---|---|---|---|
| CBOR canonicalization re-derivation | — | — | — | — |
| AEAD round-trip + tamper rejection | — | — | — | — |
| Key-wrapping vectors | — | — | — | — |
| OPAQUE RFC 9807 vectors | — | — | — | — |

## Findings record

| ID | Severity (Critical/High/Medium/Low) | Description | Affected (contract/threat/task) | Disposition (fix / accepted with rationale) | Status |
|---|---|---|---|---|---|
| — | — | — | — | — | — |

Rules: any Critical/High finding returns A04 to `READY` via the integrator
before any crypto implementation merges; accepted findings require an explicit
rationale; append rows only, never edit a recorded finding.

## Signature

I have executed the H01 review checklist
(`docs/security/H01-REVIEW-CHECKLIST.md`), independently verified the evidence
marked ready, and record my decision below.

| Field | Value |
|---|---|
| Reviewer name | — |
| Role | Human security reviewer (H01) |
| Decision | ☐ Approve and freeze `crypto-envelope/v1` ☐ Approve with findings (all dispositions recorded above) ☐ Reject — A04 returns to READY |
| Date | — |
| Signature/attestation | — |

**No signature recorded as of preparation of this draft.**

## Effects of approval (on signature only)

- `crypto-envelope/v1` becomes frozen; changes require v2, a new ADR, new
  fixtures, and renewed H01 approval (contract "Versioning and migration").
- SD-0003 in `docs/security/DECISIONS.md` moves from pending to approved; the
  integrator updates the register and the contract status line.
- B01 (Rust crypto-core), B03 (bindings), and B04 (auth) unblock per the DAG.
- Public release still requires the external audit (SD-0006, H02).
