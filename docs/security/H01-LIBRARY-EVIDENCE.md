# H01 library/license/maintenance candidate evidence (G-06)

Prepared by the H01 evidence-preparation agent on 2026-09-03 (branch
`stalexxx/h01-library-evidence-opencode`, for issue #1 follow-up). This file is
**evidence only**. It selects no library, adds no dependency, approves nothing,
and does not alter `crypto-envelope/v1`. Per `docs/tasks/H01.md`,
`DEPENDENCY-POLICY.md`, and issue #1, library selection and approval belong to
the human security reviewer, recorded in
`docs/decisions/ADR-0003-crypto-envelope-v1-approval.md`. Every **Reviewer
verdict** cell below is intentionally blank.

## 1. Method and sources

Live sources were queried on **2026-09-03** from the task environment. All
time-sensitive facts (versions, dates, download counts) are valid only for that
date and must be re-verified at pin time.

| Source ID | Source | URL pattern | Queried for |
|---|---|---|---|
| S1 | crates.io REST API, crate + version metadata | `https://crates.io/api/v1/crates/{name}` | name, exact versions, license, publish dates, repository, downloads |
| S2 | crates.io REST API, per-version dependencies | `https://crates.io/api/v1/crates/{name}/{version}/dependencies` | direct dependencies of the exact proposed version |
| S3 | RustSec advisory-db (GitHub `main`) | `https://github.com/rustsec/advisory-db/tree/main/crates/{name}` | advisories per crate name |
| S4 | Project READMEs/sources at pinned refs | `raw.githubusercontent.com` | audit claims, feature claims, RFC claims |

Fact classes used in the tables:

- **[V]** = verified against S1–S4 on 2026-09-03; source ID given inline.
- **[U]** = unverified or only partially verified; carried in §5 uncertainty
  register. Model/background knowledge is never stated as fact.
- **[P]** = proposal by this agent, carrying no approval weight.

Crates were not downloaded, built, or tested; no lockfile or manifest was
changed (`crates/crypto-core` remains dependency-free).

## 2. Candidate evidence tables

Each table carries the columns required by `H01-REVIEW-CHECKLIST.md` §3.3:
library, exact version, license, last release, maintenance/audit history,
transitive dependencies (direct deps listed; full closure needs lockfile
resolution post-approval), security alternatives considered.

### 2.1 Argon2id (RFC 9106)

| Field | `argon2` (RustCrypto) | `rust-argon2` (sru-systems) |
|---|---|---|
| Exact version (max stable, [V] S1) | 0.6.0 | 3.0.0 |
| License ([V] S1) | MIT OR Apache-2.0 | MIT/Apache-2.0 |
| Last release ([V] S1) | 2026-08-27 (v0.6.0) | 2025-07-17 (v3.0.0) |
| MSRV ([V] S1) | 1.85 | not declared |
| Downloads total / 90 days ([V] S1) | 49,644,124 / 17,898,603 | 21,014,475 / 3,090,504 |
| Maintenance ([V] S1) | Monorepo `RustCrypto/password-hashes`; release 7 days before query | Repo `sru-systems/rust-argon2`; no release in ~13.5 months |
| Audit history | None found for this crate **[U]** (no audit claim in README; absence not proven) | None found **[U]** |
| Direct deps, non-optional ([V] S2) | `base64ct ^1.7`, `blake2 ^0.11`; `cpufeatures ^0.3` only on x86/x86_64 | not queried **[U]** (lower priority; see §5 U-09) |
| Direct deps, optional ([V] S2) | `kdf ^0.1`, `password-hash ^0.6`, `rayon ^1.7`, `zeroize ^1` | not queried |
| RustSec ([V] S3) | none filed under `crates/argon2` | none filed under `crates/rust-argon2` |
| Argon2id support ([V] S4) | README: Argon2id is the default variant | supported per project docs **[U]** |
| Alternatives considered | `rust-argon2` (this table); `orion` KDF module (§2.2) | `argon2` (left column) |
| Reviewer verdict | — (blank; reviewer records in ADR-0003) | — (blank) |

### 2.2 XChaCha20-Poly1305 (IETF construction)

| Field | `chacha20poly1305` (RustCrypto) | `orion` (orion-rs) |
|---|---|---|
| Exact version (max stable, [V] S1) | 0.11.0 | 0.18.0 |
| License ([V] S1) | Apache-2.0 OR MIT | MIT |
| Last release ([V] S1) | 2026-06-28 (v0.11.0) | 2026-08-30 (v0.18.0) |
| MSRV ([V] S1) | 1.85 | 1.87 |
| Downloads total / 90 days ([V] S1) | 79,100,189 / 19,909,213 | 12,533,363 / 1,654,108 |
| Maintenance ([V] S1) | Monorepo `RustCrypto/AEADs`; crate updated 2026-08-05 | Repo `orion-rs/orion`; release 4 days before query |
| Audit history ([V] S4) | README: one NCC Group audit (2020, MobileCoin-funded) of aes-gcm + chacha20poly1305, "no significant findings" — **audit predates v0.11.0 by several major versions** | README states: "This library has **not undergone any third-party security audit**" |
| Direct deps, non-optional ([V] S2) | `aead ^0.6`, `chacha20 ^0.10`, `cipher ^0.5`, `poly1305 ^0.9` | `fiat-crypto ^0.3.0`, `subtle ^2.2.2` |
| Direct deps, optional ([V] S2) | `zeroize ^1.8` | `ct-codecs ^1.1.1`, `getrandom ^0.4.1`, `serde ^1.0.124`, `zeroize ^1.1.0` |
| RustSec ([V] S3) | none filed | RUSTSEC-2018-0012 / CVE-2018-20999 (streaming `reset()` flaw; patched ≥ 0.11.2; v0.18.0 not in affected range) |
| XChaCha20-Poly1305 support ([V] S4) | README: crate contains XChaCha20Poly1305 | provided per project docs **[U]** (module-level check not run) |
| Posture ([V] S4) | RustCrypto pure-Rust stack | pure Rust; README badges: `unsafe` forbidden, daily tests, dudect constant-time checks, RustSec audit CI |
| Alternatives considered | `orion` (right column); libsodium FFI class (§3.3) | `chacha20poly1305` (left column) |
| Reviewer verdict | — (blank) | — (blank) |

### 2.3 OPAQUE (RFC 9807, Ristretto255 profile)

| Field | `opaque-ke` (facebook, formerly novifinancial) |
|---|---|
| Exact version ([V] S1; **[P]** propose max **stable**) | 4.0.1 (published 2025-11-03). A prerelease 4.1.0-pre.2 (2026-03-27) exists and is **not** proposed |
| License ([V] S1) | Apache-2.0 OR MIT |
| Last stable release ([V] S1) | 2025-11-03 (v4.0.1); crate record updated 2026-03-27 |
| MSRV ([V] S1) | 1.85 (the 1.87 MSRV belongs to the unproposed 4.1.0-pre.2 prerelease) |
| Downloads total / 90 days ([V] S1) | 592,401 / 130,800 |
| Maintenance ([V] S1) | Repo `facebook/opaque-ke`; ~10 months since last stable release — activity level unverified **[U]** (§5 U-05) |
| Audit history ([V] S4) | README: audited by NCC Group, June 2021, sponsored by WhatsApp; findings against v0.5.0, fixes in v1.2.0 — **audit predates 4.x by three major versions** |
| RFC claim ([V] S4) | README at tag v4.0.1: "This implementation is based on RFC 9807". Byte-level conformance to the final RFC **not independently verified** here (§5 U-01) |
| Ristretto255 ([V] S4) | Cargo feature `ristretto255` exposing `opaque_ke::Ristretto255` (src/lib.rs at v4.0.1); optional dep `curve25519-dalek ^4` **[V] S2** |
| Direct deps, non-optional ([V] S2) | `derive-where ^1.4`, `digest ^0.10`, `displaydoc ^0.2`, `elliptic-curve ^0.13`, `generic-array =0.14.7` (pinned exact), `hkdf ^0.12`, `hmac ^0.12`, `rand ^0.8`, `subtle ^2.6`, `voprf ^0.5`, `zeroize ^1.8` |
| Direct deps, optional ([V] S2) | `argon2 ^0.5`, `curve25519-dalek ^4`, `ecdsa ^0.16`, `ed25519-dalek ^2`, `getrandom ^0.2` (wasm32), `rfc6979 ^0.4`, `serde ^1` |
| RustSec ([V] S3) | none filed under `crates/opaque-ke` |
| Alternatives considered | No other maintained Rust implementation of RFC 9807 was verified in this pass **[U]** (§5 U-06: single-candidate risk; alternatives not surveyed beyond `crates.io` search terms not yet run) |
| Reviewer verdict | — (blank) |

### 2.4 Canonical CBOR (RFC 8949 definite/deterministic encoding)

| Field | `ciborium` (enarx) | `minicbor` (twittner) | `serde_cbor` (pyfisch) |
|---|---|---|---|
| Exact version ([V] S1) | 0.2.2 | 2.3.0 | 0.11.2 |
| License ([V] S1) | Apache-2.0 (single, not dual) | **BlueOak-1.0.0** (unusual permissive license; see §5 U-08) | MIT/Apache-2.0 |
| Last release ([V] S1) | 2024-01-24 (19.3 months before query) | 2026-07-23 | 2021-08-15 |
| MSRV ([V] S1) | 1.58 | not declared | not declared |
| Downloads total / 90 days ([V] S1) | 227,009,596 / 56,187,830 | 13,989,498 / 5,055,737 | 80,977,478 / 10,185,382 |
| Maintenance ([V] S1) | No release in 19.3 months; repository activity recorded in verification review §2.5 but maintenance health remains **[U]** (§5 U-04) | Recent release; active | Unmaintained |
| RustSec ([V] S3) | none filed | none filed | **RUSTSEC-2021-0127 "serde_cbor is unmaintained"** (informational); RUSTSEC-2019-0025 / CVE-2019-25001 (nested-tag stack overflow; patched ≥ 0.10.2) |
| Direct deps ([V] S2) | `ciborium-io ^0.2.2`, `ciborium-ll ^0.2.2`, `serde ^1.0.100` | optional only: `half ^2.4.0`, `minicbor-derive ^0.19.5` | not queried (rejected on S3) |
| Canonical RFC 8949 §4.2.1 key-ordering support ([V] S4 absence) | No canonical/deterministic claim found in README — **unverified** (§5 U-03) | not checked — **unverified** (§5 U-03) | n/a (rejected) |
| Alternatives considered | `minicbor`, `serde_cbor` (rejected) | `ciborium`, `serde_cbor` (rejected) | rejected: unmaintained advisory |
| Reviewer verdict | — (blank) | — (blank) | — (blank; rejection evidence above) |

### 2.5 Cross-cutting dependencies already present in candidates

- `zeroize` appears across `argon2` (optional), `chacha20poly1305` (optional),
  `opaque-ke` (required) — relevant to threat T19. **[V] S2**
- `curve25519-dalek ^4` would enter only via `opaque-ke`'s `ristretto255`
  feature; its own audit/maintenance status is **not** assessed here. **[U]**
- The full transitive closure (RustCrypto traits, `generic-array =0.14.7` exact
  pin in `opaque-ke`, `fiat-crypto`, etc.) requires real lockfile resolution —
  B01 responsibility after approval. **[U]** (§5 U-07)

## 3. Rejected alternatives (evidence)

| Alternative | Rejection evidence | Class |
|---|---|---|
| `sodiumoxide 0.2.7` (libsodium FFI bindings) | RUSTSEC-2021-0137 "sodiumoxide is deprecated"; RUSTSEC-2017-0001 / CVE-2017-1000168 and RUSTSEC-2019-0026 / CVE-2019-25002 (both patched in 0.2.7) **[V] S3**; last release 2021-06-24 **[V] S1**; FFI-based, in tension with the pure-Rust `unsafe_code = "forbid"` posture of `crates/crypto-core` (**[P]** architectural note, reviewer confirms) | AEAD/KDF |
| `serde_cbor 0.11.2` | RUSTSEC-2021-0127 "serde_cbor is unmaintained" (informational); RUSTSEC-2019-0025 / CVE-2019-25001 (patched in 0.11.2) **[V] S3**; last release 2021-08-15 **[V] S1** | CBOR |
| Any primitive hand-written in this repository | Prohibited by `AGENTS.md` ("Do not implement cryptographic primitives outside the Rust crypto-core") and SD-0001; noted for completeness | all |

No claim is made that the rejected list is exhaustive; it covers only the
alternatives actually examined in this pass (§5 U-06).

## 4. Proposal status (not a selection)

The following are **[P] proposals for reviewer consideration only**; no library
is selected by this document:

1. For each primitive, the left-most non-rejected column above is the candidate
   this agent would shortlist (Argon2id: `argon2 0.6.0`; AEAD:
   `chacha20poly1305 0.11.0`; OPAQUE: `opaque-ke 4.0.1` stable only; CBOR:
   open between `ciborium` and `minicbor` pending U-03/U-04/U-08).
2. Pin exact versions (no caret ranges) in the ADR-0003 approval table at
   signature time, per `DEPENDENCY-POLICY.md`.
3. Treat audit age (§2.2, §2.3) as a reviewer decision: whether the 2020/2021
   NCC audits suffice for current major versions, or whether the external
   audit gate (SD-0006, H02) must cover them.

## 5. Uncertainty register

| ID | Uncertainty | What must resolve it |
|---|---|---|
| U-01 | `opaque-ke` claims "based on RFC 9807" (README, v4.0.1 tag) but byte-level conformance to the final RFC and to the contract's "standard transcript" wording is unverified; no RFC 9807 test vectors exist in-repo (G-04) | Reviewer + G-04 vector verification with official RFC 9807 vectors |
| U-02 | crates.io license metadata is publisher self-reported; LICENSE files were not separately fetched | B01 license scan (CI, `DEPENDENCY-POLICY.md`) at pin time |
| U-03 | Whether `ciborium`/`minicbor` enforce RFC 8949 §4.2.1 deterministic map-key ordering (shortest-length-then-byte-wise) is unverified; the G-11 fixture defect shows exactly this class of error is easy to introduce | B01 spike or reviewer test: encode map `{1..6}` and byte-compare; verifier (G-01) must regression-test canonical integers |
| U-04 | `ciborium` last release 2024-01-24; repository commit activity could not be verified (GitHub API timed out during evidence collection) | Reviewer re-check of repo activity / maintainer statements |
| U-05 | `opaque-ke` maintenance cadence: last stable 2025-11-03, prerelease 2026-03-27; commit activity unverified | Reviewer re-check |
| U-06 | Library survey breadth: only crates named in this pass were examined; no systematic crates.io search for competing RFC 9807 or Argon2 implementations was run; OPAQUE is effectively single-candidate | Reviewer-directed broader survey if required |
| U-07 | Only direct dependencies were listed (S2); full transitive closure, feature unification, and WASM target behavior are unknown | B01 lockfile + SBOM after approval |
| U-08 | `minicbor` license BlueOak-1.0.0 is permissive but uncommon; license-policy compatibility unassessed | Reviewer/licensing check |
| U-09 | `rust-argon2` dependency list and orion module-level AEAD support were not queried (de-prioritized as non-shortlist candidates) | Only if reviewer shortlists them |
| U-10 | All facts are as of 2026-09-03; versions/dates/counts drift | Re-verify at signature and pin time |
| U-11 | "No RustSec advisory filed" was checked by crate name on 2026-09-03; absence of an advisory is not proof of absence of vulnerabilities | Reviewer judgment + H02 external audit |

## 6. What this document does not do

- Does not select, rank as decided, or add any library or dependency.
- Does not fill or alter the Library approval table in ADR-0003 (reviewer
  completes it before signature).
- Does not approve, freeze, or modify `crypto-envelope/v1` (SD-0003 pending;
  issue #1 gate).
- Does not substitute for the external audit required before public release
  (SD-0006).
