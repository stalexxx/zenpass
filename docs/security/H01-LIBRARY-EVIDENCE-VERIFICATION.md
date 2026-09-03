# G-06 verification review: independent audit of the candidate library evidence (commit `6b21492`)

Verification-review agent: branch `stalexxx/g06-library-evidence-audit-opencode`,
2026-09-03. This is a **documentation-only verification review**. It selects no
library, adds no dependency, approves nothing, and does not modify
`crypto-envelope/v1`. **H01 remains BLOCKED**: AC-3 selection/approval belongs
to the human security reviewer in
`docs/decisions/ADR-0003-crypto-envelope-v1-approval.md` (unsigned draft), and
gap G-06 remains open pending that selection.

Subject under review: commit `6b21492` ("H01: add candidate library evidence
table for G-06 (issue #1)") on branch `stalexxx/h01-library-evidence-opencode`
(parent `0faf46c`). The commit adds `docs/security/H01-LIBRARY-EVIDENCE.md`
(hereafter "the candidate document") and cross-references in
`docs/security/H01-REVIEW-CHECKLIST.md` and
`docs/decisions/ADR-0003-crypto-envelope-v1-approval.md`. Diff scope verified:
exactly those three documentation files; no manifest, lockfile, code, fixture,
contract, STATUS, or task file touched; `crates/crypto-core` remains
dependency-free at `6b21492` (zero dependencies, `unsafe_code = "forbid"`).

Per the G-06 dispatch, this review follows option (a): the candidate document's
concrete time-sensitive claims were re-verified against primary sources and the
corrections below constitute the **corrected evidence of record**. Every claim
the candidate marked **[V]** was independently re-checked; every claim found
inaccurate or incomplete is corrected in §3; claims that remain uncertain stay
marked **unverified** in §4. Nothing here is a selection or approval.

## 0. Record-integrity finding (pre-existing, not introduced by `6b21492`)

`docs/security/DEPENDENCY-POLICY.md` is cited by
`docs/security/H01-REVIEW-CHECKLIST.md` §3.3, by the candidate document (§4
item 2), and by the G-06 dispatch, but **does not exist** anywhere in this
repository's history (`git log --all -- '**/DEPENDENCY-POLICY*'` is empty). All
"per DEPENDENCY-POLICY.md" statements therefore reference a missing artifact.
This review does not create that file (inventing a security policy is outside a
verification review's scope); the integrator/human reviewer must either supply
it or re-anchor the citations. Related precedent: gap G-08 (missing referenced
ADRs).

## 1. Method

Primary sources were re-queried live on **2026-09-03** (~13:37 local,
UTC+03), independently of the candidate agent's session:

| ID | Source | What was checked |
|---|---|---|
| V1 | crates.io REST API `https://crates.io/api/v1/crates/{name}` | max stable/newest version, per-version license, publish/update timestamps, `rust_version` (MSRV), total and 90-day downloads, repository URL |
| V2 | crates.io `.../crates/{name}/{version}/dependencies` | exact requirement strings, optional/target/kind flags for each proposed version |
| V3 | RustSec `advisory-db` at `main` (GitHub contents API + raw files) | advisory presence/absence per crate; full TOML + text of each cited or missing advisory |
| V4 | Project sources at pinned refs (`raw.githubusercontent.com`) | README/audit/feature claims at the exact tags corresponding to proposed versions |

Tooling: `curl` (UA `g06-evidence-audit (repo local verification)`) + `jq`.
No crate was downloaded, built, or tested; nothing outside
`docs/security/**` and `docs/decisions/**` was modified. As with the
candidate's data, all facts below are valid only for the query date (drift
register: §4 U-10).

## 2. Independent verification results

### 2.1 crates.io metadata (V1) — 1 error found, rest exact

| Crate | Claimed | Live value (2026-09-03) | Verdict |
|---|---|---|---|
| argon2 | 0.6.0 max stable; MIT OR Apache-2.0; rel 2026-08-27; MSRV 1.85; 49,644,124 / 17,898,603 dl | identical | ✅ |
| rust-argon2 | 3.0.0; MIT/Apache-2.0; rel 2025-07-17; MSRV not declared; 21,014,475 / 3,090,504 | identical | ✅ |
| chacha20poly1305 | 0.11.0; Apache-2.0 OR MIT; rel 2026-06-28; crate updated 2026-08-05; MSRV 1.85; 79,100,189 / 19,909,213 | identical | ✅ |
| orion | 0.18.0; MIT; rel 2026-08-30; MSRV 1.87; 12,533,363 / 1,654,108 | identical | ✅ |
| opaque-ke | 4.0.1 max stable; 4.1.0-pre.2 (2026-03-27) newest; Apache-2.0 OR MIT; stable rel 2025-11-03; record updated 2026-03-27; 592,401 / 130,800 | identical | ✅ |
| opaque-ke | **MSRV 1.87** | `rust_version` = **1.85** for 4.0.1; 1.87 is the MSRV of prerelease 4.1.0-pre.2 only | ❌ corrected → C-1 |
| ciborium | 0.2.2; Apache-2.0 (single); rel 2024-01-24; MSRV 1.58; 227,009,596 / 56,187,830 | identical | ✅ |
| minicbor | 2.3.0; BlueOak-1.0.0; rel 2026-07-23; MSRV not declared; 13,989,498 / 5,055,737 | identical | ✅ |
| serde_cbor | 0.11.2; MIT/Apache-2.0; rel 2021-08-15; 80,977,478 / 10,185,382 | identical | ✅ |
| sodiumoxide | last release 2021-06-24 (0.2.7) | identical | ✅ |

Maintenance-narrative claims: argon2 "release 7 days before query" ✅;
orion "release 4 days before query" ✅; rust-argon2 "no release in ~13.5
months" ✅; opaque-ke "~10 months since last stable" ✅ (exactly 10);
ciborium "~20 months" ⚠️ actually **19.3 months** (C-4, minor). Repository
attributions (RustCrypto/password-hashes, RustCrypto/AEADs,
sru-systems/rust-argon2, orion-rs/orion, facebook/opaque-ke, enarx/ciborium,
twittner/minicbor, pyfisch/cbor) all match the crates.io `repository` field ✅.

### 2.2 Per-version dependencies (V2) — all exact, including optionality and targets

Every dependency row of the candidate tables was reproduced exactly (crate,
requirement string, optional flag, target predicate, kind):

- `argon2 0.6.0`: non-optional `base64ct ^1.7`, `blake2 ^0.11`,
  `cpufeatures ^0.3` (only `cfg(any(target_arch = "x86", target_arch = "x86_64"))`);
  optional `kdf ^0.1`, `password-hash ^0.6`, `rayon ^1.7`, `zeroize ^1` ✅
  (dev-dependency `hex-literal ^1` exists but is outside the tables' runtime
  scope — not an error).
- `chacha20poly1305 0.11.0`: `aead ^0.6`, `chacha20 ^0.10`, `cipher ^0.5`,
  `poly1305 ^0.9`; optional `zeroize ^1.8` ✅.
- `orion 0.18.0`: non-optional `fiat-crypto ^0.3.0`, `subtle ^2.2.2`; optional
  `ct-codecs ^1.1.1`, `getrandom ^0.4.1`, `serde ^1.0.124`, `zeroize ^1.1.0` ✅.
- `opaque-ke 4.0.1`: all 11 non-optional rows exact, **including the
  `generic-array =0.14.7` exact pin**; all 7 optional rows exact, including
  `getrandom ^0.2` restricted to `cfg(target_arch = "wasm32")` and
  `curve25519-dalek ^4` ✅.
- `ciborium 0.2.2`: `ciborium-io ^0.2.2`, `ciborium-ll ^0.2.2`,
  `serde ^1.0.100` ✅.
- `minicbor 2.3.0`: optional-only `half ^2.4.0`, `minicbor-derive ^0.19.5` ✅.

**New evidence** (upgrades candidate U-09): `rust-argon2 3.0.0` non-optional
deps are `base64 ^0.22`, `blake2b_simd ^1.0`, `constant_time_eq ^0.4.2`;
optional `crossbeam-utils ^0.8`, `serde ^1.0` [V2, 2026-09-03].

### 2.3 RustSec advisory-db (V3) — 2 omissions found

- "None filed" for `argon2`, `rust-argon2`, `chacha20poly1305`, `opaque-ke`,
  `ciborium`, `minicbor`: **confirmed** — no advisory directory exists for any
  of them in `advisory-db` `main` as of 2026-09-03 ✅ (absence caveat: §4 U-11).
- `orion`: **RUSTSEC-2018-0012** confirmed exactly as claimed — alias
  CVE-2018-20999, streaming-state `reset()` flaw, `patched = [">= 0.11.2"]`;
  0.18.0 not in the affected range ✅.
- `serde_cbor`: RUSTSEC-2021-0127 (unmaintained, informational) confirmed ✅,
  but the crate **also has RUSTSEC-2019-0025 / CVE-2019-25001**
  (CBOR-deserializer nested-tag stack overflow; `patched = [">= 0.10.2"]`),
  which the candidate omitted → C-2. 0.11.2 is patched; the rejection stands.
- `sodiumoxide`: RUSTSEC-2021-0137 (deprecated) confirmed ✅, but the crate
  **also has RUSTSEC-2017-0001 / CVE-2017-1000168** (scalarmult accepted
  degenerate all-zero public keys; `patched = [">= 0.0.14"]`) and
  **RUSTSEC-2019-0026 / CVE-2019-25002** (`generichash::Digest::eq` always
  returned true; `patched = [">= 0.2.5"]`), both omitted → C-3. 0.2.7 is
  patched for both; the rejection stands.

Both omissions concern crates the candidate already rejects; no risk-bearing
shortlist row hid an advisory.

### 2.4 READMEs/sources at pinned refs (V4) — all confirmed

- `argon2` @ tag `argon2-v0.6.0`: README states Argon2id is the **(default)**
  variant ✅.
- `chacha20poly1305` @ `chacha20poly1305-v0.11.0`: README contains
  XChaCha20Poly1305 ✅ and the audit statement "one security audit by NCC
  Group, with no significant findings … thank MobileCoin for funding" (NCC
  report Feb 2020) ✅ — audit-age caveat stands (predates 0.11.0 by several
  major versions; reviewer decision, unchanged).
- `orion` @ tag `0.18.0` (note: orion tags carry no `v` prefix): README states
  "This library has **not undergone any third-party security audit**" ✅ and
  carries the claimed badges: `unsafe`-forbidden (Safety Dance), Daily tests,
  dudect (weekly), RustSec audit-check CI, MSRV 1.87 ✅.
- `opaque-ke` @ `v4.0.1`: README states "This implementation is based on
  RFC 9807" ✅; audit statement exact (NCC Group, June 2021, sponsored by
  WhatsApp; findings against `v0.5.0`; fixes in `v1.2.0`) ✅; `Cargo.toml`
  defines the `ristretto255` feature (a **default** feature) and `src/lib.rs`
  exposes `opaque_ke::Ristretto255` ✅.
- `ciborium` @ `v0.2.2`: README contains zero occurrences of
  "canonical"/"deterministic" — the candidate's absence claim holds at README
  level ✅ (claim-class caveat: absence in README ≠ absence in code; §4 U-03).

**Claim upgraded from [U] to verified:** orion's AEAD support. README
(`0.18.0`, "Features" list) states `AEAD: (X)ChaCha20-Poly1305` — i.e.
XChaCha20-Poly1305 is documented at the project's own pinned ref. A
module-level/run-time check was still not performed, so the upgrade is to
"README-verified", not "exercised".

### 2.5 New facts partially resolving candidate uncertainties (V-GH, GitHub REST API, 2026-09-03)

- U-04 (ciborium repo activity; candidate reported a GitHub API timeout):
  `enarx/ciborium` `pushed_at` 2026-06-19, not archived, 55 open issues —
  commit activity exists; last release remains 2024-01-24.
- U-05 (opaque-ke activity): `facebook/opaque-ke` `pushed_at` 2026-06-23, not
  archived, 8 open issues — activity after the 4.1.0-pre.2 prerelease
  (2026-03-27).

Both facts narrow the uncertainties but do not close them (release cadence and
maintainer responsiveness remain reviewer judgments).

## 3. Corrections required before integration (corrected evidence of record)

| ID | Class | Candidate text | Correction |
|---|---|---|---|
| C-1 | factual error | §2.3 opaque-ke "MSRV 1.87" | For the proposed stable **4.0.1** the crates.io `rust_version` is **1.85**. 1.87 is the MSRV of the *not-proposed* prerelease 4.1.0-pre.2. Conservative direction, no security impact, but pin-time documentation must be exact. |
| C-2 | evidence omission | §2.4 serde_cbor cites only RUSTSEC-2021-0127 | Add **RUSTSEC-2019-0025 / CVE-2019-25001** (deserializer nested-tag stack overflow; patched ≥ 0.10.2; 0.11.2 patched). Rejection unchanged. |
| C-3 | evidence omission | §3 sodiumoxide cites only RUSTSEC-2021-0137 | Add **RUSTSEC-2017-0001 / CVE-2017-1000168** (scalarmult degenerate public keys; patched ≥ 0.0.14) and **RUSTSEC-2019-0026 / CVE-2019-25002** (`generichash::Digest::eq` always true; patched ≥ 0.2.5). 0.2.7 patched for both; rejection unchanged. |
| C-4 | minor imprecision | §2.4 ciborium "no release in ~20 months" | 19.3 months (2024-01-24 → 2026-09-03). |

No other discrepancy was found in any [V]-marked claim. No fabricated claim
was detected. The candidate's own uncertainty register (U-01..U-11) was
reviewed and is honest in scope; §4 carries forward everything still open.

## 4. Claims that remain unverified (carry forward unchanged unless noted)

| ID | Unverified claim | Status after this audit |
|---|---|---|
| U-01 | `opaque-ke` byte-level conformance to final RFC 9807 and the contract's "standard transcript" | open; needs G-04 official-vector verification |
| U-02 | License text beyond crates.io self-reported metadata (LICENSE files not fetched) | open |
| U-03 | Whether `ciborium`/`minicbor` enforce RFC 8949 §4.2.1 deterministic key ordering | open; README absence confirmed only (§2.4); B01 spike / G-01 regression test still required |
| U-04 | ciborium maintenance health | **narrowed** (repo active, pushed 2026-06-19; no release since 2024-01-24) — still a reviewer judgment |
| U-05 | opaque-ke maintenance cadence | **narrowed** (repo active, pushed 2026-06-23; last stable 2025-11-03) — still a reviewer judgment |
| U-06 | Survey breadth; OPAQUE effectively single-candidate | open |
| U-07 | Transitive closure, feature unification, WASM target behavior | open (B01 lockfile + SBOM post-approval) |
| U-08 | BlueOak-1.0.0 policy compatibility for `minicbor` | open; note `DEPENDENCY-POLICY.md` itself is missing (§0) |
| U-09 | `rust-argon2` deps; orion AEAD support | **partially closed** by §2.2/§2.4 (deps now listed; AEAD README-verified; module-level check not run) |
| U-10 | Time drift: all facts valid 2026-09-03 only | open by nature; re-verify at signature and pin time |
| U-11 | Advisory absence ≠ vulnerability absence | open; H02 external audit still required (SD-0006) |

Audit-age judgments (2020 NCC audit predating `chacha20poly1305` 0.11.0; 2021
NCC audit predating `opaque-ke` 4.x) remain reviewer decisions, per candidate
§4 item 3.

## 5. Verdict for the integrator (option (a))

The candidate document **can be integrated after applying corrections C-1
through C-4** and noting the §0 missing-policy finding. Its verified facts
reproduce against live primary sources with the single MSRV error and two
advisory omissions documented above; its uncertainty register is accurate; it
selects nothing and approves nothing, and its checklist/ADR cross-references
keep AC-3 explicitly pending. This verification document should be merged
alongside (or merged into) the candidate evidence so the human reviewer reads
the corrected values, not the superseded ones.

Explicitly outside this review's authority and unchanged by it: any library
selection or rejection as decision, any ADR-0003 signature, any
`crypto-envelope/v1` freeze, any dependency addition, and any change to H01's
BLOCKED status. The candidate's reassignment of the G-06 resolution owner
("A04 or B01 proposal → H01 approval" → "H01 reviewer …; B01 re-verifies at
pin time") is a documentation observation, not an error, but the reviewer
should ratify it.
