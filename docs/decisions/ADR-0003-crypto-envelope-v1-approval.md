# ADR-0003: Human security approval of crypto-envelope/v1, KDF calibration, crypto libraries, and recovery semantics

Status: **APPROVED WITH FINDINGS — 2026-09-03.** The human security reviewer
has approved the v1 freeze subject to the bounded findings and mandatory
follow-up below. This is not a release approval: SD-0006 and H02 remain in
force, and the deferred work is a prerequisite for production crypto delivery.

## Context

- `docs/contracts/crypto-envelope-v1.md` defines the normative bytes
  (envelope, AAD, canonical CBOR, Argon2id parameters, OPAQUE suite, typed
  errors, versioning/migration, recovery reset).
- `fixtures/crypto/` contains language-neutral fixtures: AAD canonicalization,
  malformed-envelope rejections, KDF parameter encoding, recovery semantics.
- `docs/security/THREAT-MODEL.md` (A01, merged) and
  `docs/security/RECOVERY.md` define the security objective and recovery
  guarantees; SD-0004 approved the irreversibility principle.
- Known evidence gaps G-01..G-11 are registered in
  `docs/security/H01-REVIEW-CHECKLIST.md` §4. Gaps G-01..G-06 currently block
  full vector and library verification; the G-11 fixture bytes were corrected
  but still require independent confirmation under G-05.
- The dependency-neutral implementation routing and independent-validation
  procedure for G-01..G-05 are documented in
  `docs/security/H01-CRYPTO-FIXTURES-VERIFIER-PLAN.md`. It is not verification
  evidence and does not select a production library.
- The Argon2id target-device calibration evidence protocol for G-07 is
  documented in `docs/security/H01-ARGON2ID-CALIBRATION-PROTOCOL.md`. It is
  unsigned and non-binding, selects no parameter values, and records no
  measurements; the evidence itself is to be produced by B01 (post-approval)
  or A04 rework and reviewed by the human reviewer.
- Candidate library evidence for G-06 (commit `6b21492`, branch
  `stalexxx/h01-library-evidence-opencode`) was independently re-verified
  against crates.io, the RustSec advisory-db, and pinned project refs on
  2026-09-03; corrections C-1..C-4 and the still-unverified claim register are
  recorded in `docs/security/H01-LIBRARY-EVIDENCE-VERIFICATION.md`. Neither
  document selects or approves a library; the table below is completed only by
  the human reviewer, with versions re-verified at pin time. Note:
  `DEPENDENCY-POLICY.md`, cited by the review checklist (§3.3) and the
  candidate evidence, does not exist in this repository (see verification §0).

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

## Library approval table

| Primitive | Library | Exact version | License | Maintenance/audit notes | Reviewer verdict |
|---|---|---|---|---|---|
| Argon2id (RFC 9106) | `argon2` (RustCrypto) | `=0.6.0` | MIT OR Apache-2.0 | RustCrypto; Argon2id is the default variant. No crate-specific audit was identified in the evidence pass; re-verify source and full dependency closure at pin time. | approved with B01 verification |
| XChaCha20-Poly1305 (IETF) | `chacha20poly1305` (RustCrypto) | `=0.11.0` | Apache-2.0 OR MIT | Pure-Rust RustCrypto implementation. Its 2020 NCC audit predates this major version; H02 external audit remains required. | approved with B01 verification |
| OPAQUE (RFC 9807, Ristretto255) | `opaque-ke` (facebook) with `ristretto255` feature | `=4.0.1` | Apache-2.0 OR MIT | Based on RFC 9807; its June 2021 audit predates 4.x. RFC-vector conformance and dependency closure remain B01/G-04 work. | approved with B01 verification |
| Canonical CBOR (RFC 8949) | `minicbor` | `=2.3.0` | BlueOak-1.0.0 | Selected only behind the mandatory strict canonical-CBOR wrapper and regression suite described in F-2 below; its deterministic-ordering behavior and license-policy compatibility were not independently established. | conditional approval |

Candidate evidence (verified library/version/license/maintenance facts,
alternatives considered, and an uncertainty register) is collected in
`docs/security/H01-LIBRARY-EVIDENCE.md` (queried 2026-09-03). It selects no
library and grants no approval; this table is completed only by the human
reviewer before signature, with versions re-verified at pin time.

Constraints: primitives live only in `crates/crypto-core` (`unsafe_code =
"forbid"`); clients consume bindings (SD-0001); upgrades re-run vector
verification with a new ADR row; suite changes require H01 re-approval.

## Independent verification evidence (to be completed)

| Step (checklist §3.2) | Tool + version | Command(s) | Result/digest | Date |
|---|---|---|---|---|
| CBOR canonicalization re-derivation | Hand-rolled canonical CBOR encoder/decoder, Python 3.14.3 — **executed by prep agent; reviewer must repeat with an independently chosen tool** | inline script; transcript summarized in checklist §3.2.1 | 20/21 PASS. `aad-item-payload-01` byte-match PASS; `kdf-parameters-01` byte-match FAIL → candidate finding F-1 (G-11); digest sha256:211f279c…c098 | recorded at HEAD `cc7870b` |
| AEAD round-trip + tamper rejection | — blocked (G-02) | — | — | — |
| Key-wrapping vectors | — blocked (G-03) | — | — | — |
| OPAQUE RFC 9807 vectors | — blocked (G-04) | — | — | — |
| Argon2id target-device calibration (G-07; protocol: `docs/security/H01-ARGON2ID-CALIBRATION-PROTOCOL.md`) | — not yet performed | — | — | — |

## Findings record

| ID | Severity (Critical/High/Medium/Low) | Description | Affected (contract/threat/task) | Disposition (fix / accepted with rationale) | Status |
|---|---|---|---|---|---|
| F-1 | — (to be assigned by reviewer) | `fixtures/crypto/kdf-parameters.json` `canonicalCborHex` is non-canonical CBOR: the final `outputLength` value 32 is encoded as single byte `0x20` (major type 1 → −1) rather than the RFC 8949 minimal encoding `0x18 0x20`, contradicting the contract's canonical-CBOR mandate (definite, minimal, ascending-key encoding). Discovered by prep-agent re-derivation, checklist §3.2.1. | `crypto-envelope/v1` fixtures; AC-2/AC-5; A04 | fix expected via A04 rework (G-11); severity and final disposition rest with the reviewer | open |
| F-1 follow-up | — (to be assigned by reviewer) | A04 corrected the positive bytes to `0x18 0x20`; the historical `0x20` input is retained as a semantic `InvalidKdfParameters` regression because it canonically encodes −1. A separate non-minimal-integer regression expects `NonCanonicalCbor`. | `crypto-envelope/v1` fixtures; AC-2/AC-5; A04 | reviewer independently verifies the repair and records severity/disposition for F-1 | remediation awaiting review |
| F-2 | Medium | G-01..G-05 leave the v1 fixtures without a completed independent, non-Rust verifier and without source-backed wrapping coverage. G-07 has no target-device calibration result. G-09 still has a recovery-wrap placeholder. G-10 does not specify recovery-code display encoding. G-11 has not been independently adapter-verified. | AC-2/AC-4/AC-5; A04, B01, H01 | **accepted only to start B01/B04 implementation**. Before production crypto delivery: B01 supplies strict canonical-CBOR decode/re-encode enforcement and tests (minimal integer encodings, deterministic key order, duplicate keys, indefinite values, tags, floats); A04/B01 add independent adapter-backed AEAD/wrapping/OPAQUE/recovery verification and a real recovery-wrap vector; B01 records calibration; reviewer decides recovery-code encoding. | deferred; blocks release and any claim of full vector approval |
| F-3 | Medium | G-06 evidence leaves full transitive dependency closure, feature unification, WASM behavior, exact license-text verification, and current audit applicability unverified. | AC-3; B01, H02 | accepted only to start B01/B04. B01 pins exact versions, resolves and scans the lockfile/SBOM, confirms feature and target behavior, and re-verifies licenses/advisories before merge; H02 covers independent external audit. | deferred; blocks release |

Rules: any Critical/High finding returns A04 to `READY` via the integrator
before any crypto implementation merges; accepted findings require an explicit
rationale; append rows only, never edit a recorded finding.

## Human approval record

The following attestation was supplied by the user in this integration session.
It is recorded verbatim; it authorizes the limited acceptance described in
F-2/F-3, rather than asserting verification evidence which is not present.

| Field | Value |
|---|---|
| Reviewer name | stalexxx |
| Role | Human security reviewer (H01) |
| Decision | ☒ Approve with findings (all dispositions recorded above) |
| Date | 2026-09-03 |
| Signature/attestation | `Я, stalexxx, как human security reviewer, approve with findings принимаю все до следующего этапа` |

Provenance: direct user statement in this session on 2026-09-03. Repository
`CODEOWNERS` names `@stalexxx`; no external identity-verification claim is
made by this record.

## Effects of approval

- `crypto-envelope/v1` becomes frozen; changes require v2, a new ADR, new
  fixtures, and renewed H01 approval (contract "Versioning and migration").
- SD-0003 in `docs/security/DECISIONS.md` moves from pending to approved; the
  integrator updates the register and the contract status line.
- B01 (Rust crypto-core), B03 (bindings), and B04 (auth) unblock per the DAG.
- Public release still requires the external audit (SD-0006, H02).
