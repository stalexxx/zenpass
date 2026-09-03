# H01 human security review — checklist and evidence map

Prepared by the H01 preparation agent at commit `284e957` (branch
`h01-review-prep-pi`). This document asserts **no approval**. Per `AGENTS.md`
and `docs/tasks/H01.md`, only the human security reviewer may approve findings
or freeze `crypto-envelope/v1`. This file maps every H01 acceptance item to
concrete verification steps and current evidence, and registers known gaps.

Amendment 2026-09-03 (library-evidence agent): candidate
library/license/maintenance evidence for G-06 was added in
`docs/security/H01-LIBRARY-EVIDENCE.md` (verified facts vs. proposals vs.
uncertainties separated; reviewer verdicts left blank; no selection recorded).
AC-3 and §3.3 were updated to point at it.

Amendment 2026-09-03 (G-10 documentation-prep task): an unsigned decision
worksheet for the recovery-code display encoding was added at
`docs/security/H01-RECOVERY-ENCODING-WORKSHEET.md` (binding requirements
traced to the contract, open rulings, neutral candidate/tradeoff inventory,
test/provenance requirements, and blank decision/signature fields). No
encoding is chosen or recommended there. AC-4, §3.4, and the G-10 gap row
were updated to point at it; the gap remains open.

Status legend:

- ✅ Evidence present, ready for human verification
- ⚠️ Partial evidence; verification possible with caveats
- ❌ Gap; acceptance item cannot be verified until resolved
- ⏳ Human decision/signature required

## 1. Acceptance criteria → evidence map

| # | H01 requirement (from `docs/tasks/H01.md`) | Reviewer verifies | Evidence location | Status |
|---|---|---|---|---|
| AC-1 | Threat model approved | Assets, boundaries, T01–T20 mitigations, metadata exposure are sound | `docs/security/THREAT-MODEL.md` (A01 MERGED) | ⏳ ⚠️ |
| AC-2 | Crypto specification approved and `crypto-envelope/v1` frozen | Byte-level contract: envelope, AAD, CBOR rules, Argon2id, OPAQUE, errors, versioning | `docs/contracts/crypto-envelope-v1.md` (status: proposed) + `fixtures/crypto/` | ⏳ ⚠️ vectors incomplete (G-02..G-04) and KDF fixture defect G-11 |
| AC-3 | Crypto libraries/dependencies approved | Named library + version + license + maintenance for each primitive | §3.3; candidate evidence table `docs/security/H01-LIBRARY-EVIDENCE.md` (verified facts, alternatives, uncertainty register; verdicts blank) | ⏳ ⚠️ candidate evidence prepared; selection and approval still pending (G-06) |
| AC-4 | Recovery semantics approved | Independent wrap, reset revocation, no support bypass, irreversibility | `docs/security/RECOVERY.md`, contract "Recovery reset and rotation", `fixtures/crypto/recovery-semantics.json`; encoding worksheet `docs/security/H01-RECOVERY-ENCODING-WORKSHEET.md` (unsigned, no choice recorded) | ⏳ ⚠️ G-09, G-10 |
| AC-5 | Independent vector verification | Fixtures re-derived/decrypted by a second, non-Rust implementation | §3.2 of this file; prep-agent run §3.2.1 (does not substitute) | ❌ G-01..G-05, G-11 |
| AC-6 | Signed review record/ADR; Critical/High findings return A04 to READY | Findings logged with severity and disposition; signature recorded | `docs/decisions/ADR-0003-crypto-envelope-v1-approval.md` (unsigned draft) | ⏳ awaiting human |

Pre-gate note: `docs/plan/STATUS.md` records A04 as `READY` after a **failed
review** ("no crypto-fixtures package/verifier; AEAD and OPAQUE vectors
incomplete"). The H01 gate condition ("A04 vectors and threat model reviewed by
a human") is therefore not fully satisfiable today. The reviewer may either
return A04 for rework first or approve with explicitly recorded findings.

## 2. Evidence inventory at HEAD `284e957`

| Artifact | Content | Notes |
|---|---|---|
| `docs/contracts/crypto-envelope-v1.md` | Normative byte-level contract | Status "proposed; implementation blocked until H01" |
| `fixtures/crypto/aad-item-payload.json` | Canonical AAD CBOR map, positive case | Re-encoded and byte-matched by prep agent (§3.2.1): canonical bytes valid |
| `fixtures/crypto/envelope-malformed.json` | Envelope shape + 6 reject cases → typed errors | Ciphertext/nonce are placeholders, not real AEAD output; structural reject cases confirmed (§3.2.1) |
| `fixtures/crypto/kdf-parameters.json` | Argon2id parameter map, positive + 4 negative | Re-derivation **FAILS**: `canonicalCborHex` ends `07 20` — outputLength 32 encoded as single byte `0x20` (major type 1, decodes −1) instead of minimal `0x18 0x20` → G-11; parameters themselves match contract bounds |
| `fixtures/crypto/recovery-semantics.json` | Recovery reset assertions | Placeholder ciphertext (56 B, G-09); structural checks pass (§3.2.1) |
| `crates/crypto-core` | Empty Rust boundary, `unsafe_code = "forbid"`, **no dependencies** | Intentionally unimplemented pending H01 |

Sanity decoding by the prep agent is an aid, **not** independent verification;
the reviewer must repeat it with an independent tool (§3.2).

#### 3.2.1 Prep-agent execution results (recorded at HEAD `cc7870b`)

Executed step 1 plus structural checks with a hand-rolled canonical CBOR
encoder/decoder (Python 3.14.3, independent of all repository code; no
`cbor2`/`PyNaCl` available in this environment — noted for the reviewer's
independent-tool choice):

- `aad-item-payload-01`: re-encode byte-match **PASS**; round-trip decode
  equals the source map; keys exactly {1..6} ascending.
- `kdf-parameters-01`: re-encode byte-match **FAIL** — new gap **G-11**
  (fixture `canonicalCborHex` is non-canonical; see §4). All four negative
  cases confirmed to violate documented bounds.
- `envelope-malformed-01`: nonce 24 B; `aad` equals AAD fixture bytes; all six
  reject cases structurally confirmed (23-B nonce, `0xbf…0xff` indefinite map,
  map(2) with duplicate key 1, v2 string, outer key 7, itemId change).
- `recovery-semantics-01`: key 32 B, nonce 24 B, 56-B placeholder ciphertext
  (G-09), 5 post-recovery assertions present.
- Result: 20/21 checks passed (the single failure is the G-11 defect);
  sha256 of result lines
  `211f279cbe976fbbb1854030f5a076011f5bc2e345756353e4863e36687c098c`.

This run does **not** close G-05: the human reviewer must repeat verification
with an independently chosen tool and record it in ADR-0003. Steps 2–4 remain
blocked by G-02..G-04.

## 3. Verification procedures

### 3.1 Byte-level contract review (AC-2)

For each item: confirm in `docs/contracts/crypto-envelope-v1.md`, then confirm
the fixture exercises it. Pass condition in italics.

1. Algorithms fixed: Argon2id (RFC 9106, 32 B), XChaCha20-Poly1305 (32/24/16 B),
   canonical CBOR (RFC 8949, definite only), `b64:` transport, OPAQUE
   (RFC 9807, Ristretto255). *No substitution without v2 + ADR + H01.*
2. Key hierarchy: random 32 B AccountKey/VaultKey/ItemKey; never derived from
   identifiers or plaintext; wrappers typed `account-wrap`, `recovery-wrap`,
   `vault-wrap`, `item-wrap`.
3. AAD = canonical CBOR of map `{1..6}`; nulls only where the kind lacks the
   identifier; decryption rejects context mismatch
   (`aad-item-payload.json`, reject case `aad-context-mismatch`).
4. Outer envelope = canonical CBOR map `{1..6}`; `aad` field must equal the
   AAD bytes; reject floats, tags, duplicate keys, indefinite lengths, unknown
   keys (`envelope-malformed.json`).
5. AEAD output `ciphertext || tag`; 24 fresh OS-CSPRNG nonce bytes; nonce reuse
   forbidden; authenticate before returning plaintext; limits 1 MiB item /
   64 KiB wrapped key.
6. Argon2id parameter map `{1..7}`; v19; 16-byte salt; bounds
   `memoryKiB ≥ 65536`, `iterations ≥ 3`, `parallelism ≥ 1`, ≤ 25 % physical
   memory; calibration 500–1000 ms; parameters never silently weakened
   (`kdf-parameters.json`).
7. OPAQUE: vetted RFC 9807 implementation, Ristretto255 profile, standard
   transcript; server never receives password/UnlockKey/AccountKey/recovery
   key; generic auth failure in UI. *Library unspecified → G-06.*
8. Typed errors leak no secret bytes or parser internals; UI cannot
   distinguish wrong password from bad remote credential material.
9. Versioning: `crypto-envelope/v1` string in every envelope and AAD; v1
   readers reject unknown versions/fields; migration is copy-on-write.

### 3.2 Independent vector verification (AC-5) — currently blocked

Required procedure once gaps G-01..G-05 are resolved:

1. **Canonicalization**: re-encode the AAD and Argon2id maps with an
   independent CBOR encoder (e.g. Python `cbor2` with canonical settings, or a
   hand-rolled RFC 8949 encoder) and byte-compare against
   `canonicalCborHex` in both fixtures.
2. **AEAD round-trip**: with an independent XChaCha20-Poly1305 implementation
   (e.g. libsodium via PyNaCl `crypto_aead_xchacha20poly1305_ietf_*`) verify,
   for each future positive vector: encrypt(test key, nonce, plaintext, aad)
   reproduces `ciphertext||tag`; decrypt succeeds; flipping any tag/ciphertext/
   AAD byte fails authentication.
3. **Wrapping**: verify account/recovery/vault/item wrap vectors unwrap only
   under the correct key kind and context.
4. **OPAQUE**: verify registration/login against official RFC 9807 test
   vectors for the chosen suite.
5. **Record evidence**: tool name + version + commands + output digest stored
   in the Evidence section of ADR-0003.

Today only step 1 is executable (existing fixtures). No positive AEAD,
wrapping, or OPAQUE vectors exist and no verifier package exists (§4).

Implementation routing for G-01..G-05, including the required A04 scope
amendment, harness/adapter boundary, vector matrix, and reviewer evidence
procedure, is specified in `H01-CRYPTO-FIXTURES-VERIFIER-PLAN.md`. That plan
does not verify vectors or constitute approval.

### 3.3 Dependency/library review (AC-3) — candidate evidence prepared, approval pending

Per `DEPENDENCY-POLICY.md`, crypto primitives require human security review
before entering `crates/crypto-core`. The reviewer needs, for each primitive,
one table row: **library, exact version, license, last release, maintenance/
audit history, transitive dependencies, security alternatives considered**.

A candidate evidence table meeting these column requirements now exists in
`docs/security/H01-LIBRARY-EVIDENCE.md` (sources queried 2026-09-03; verified
facts carry source IDs; proposals and uncertainties are separated; reviewer
verdicts are blank; no library is selected and `crypto-core` remains
dependency-free). The reviewer still must make the selection, complete the
Library approval table in ADR-0003, and sign.

Minimum selection set implied by the contract: Argon2id (RFC 9106),
XChaCha20-Poly1305 (IETF), OPAQUE RFC 9807 Ristretto255 with standard
transcript, canonical CBOR encoder/decoder. Additional checks: `unsafe_code =
"forbid"` compatibility, lockfile pinning, no primitive implemented outside
Rust crypto-core, upgrade path re-runs vector verification + ADR
(contract "OPAQUE suite"). H01 task inputs list "dependency licenses"; no such
artifact exists yet (G-06).

### 3.4 Recovery semantics review (AC-4)

Verify each statement appears consistently in `docs/security/RECOVERY.md`,
contract "Recovery reset and rotation", and the fixture's
`postRecoveryAssertions`:

1. Recovery key is 32 random bytes, wraps AccountKey independently of the
   password wrapper; display encoding is display-only.
2. Key shown once; saved-state requires a confirmation challenge derived from
   the recovery key.
3. Reset happens client-side (unwrap → new UnlockKey → new wrapper →
   authenticated upload); server stores only wrapped keys/reset authorization.
4. Successful reset revokes all sessions/devices, increments wrapper version,
   requires explicit re-enrollment.
5. Rotation is copy-on-write; item ciphertexts not rewritten for password
   rotation.
6. Loss of both password and recovery key is permanent; no support bypass
   (SD-0004, threat T14).
7. Consistency check across the three sources — re-enrollment wording in
   `RECOVERY.md` ("unless explicitly re-enrolled") vs contract ("requires
   explicit re-enrollment") must be confirmed equivalent by the reviewer.

Open reviewer questions (not decided here): recovery-code display encoding
unspecified (G-10 — unsigned decision worksheet prepared:
`H01-RECOVERY-ENCODING-WORKSHEET.md`; no encoding chosen or recommended);
fixture placeholder ciphertext length 56 B does not match
32 B key + 16 B tag = 48 B expected for `recovery-wrap` (G-09).

### 3.5 Threat-model consistency (AC-1)

Operationalizes the unsigned "Human review checklist" at the end of
`THREAT-MODEL.md`:

- [ ] Assets, boundaries, assumptions, metadata exposure approved.
- [ ] T01–T20 rows have an owner, severity, and evidence.
- [ ] Crypto and recovery decisions carry explicit human approval (→ ADR-0003).
- [ ] No mitigation weakens the zero-knowledge invariant (cross-check contract
      key hierarchy + OPAQUE + recovery sections against the invariants list).
- [ ] Critical/High findings fixed or formally accepted before release.

Specific ties: T08 needs Argon2id calibration evidence (G-07; evidence
protocol at `docs/security/H01-ARGON2ID-CALIBRATION-PROTOCOL.md` — unsigned,
no measurements recorded yet); T12 supply chain
needs §3.3; T14 is covered by §3.4; "Open questions" 2–5 (metadata budget,
browser matrix, backup retention, external-audit scope) are outside H01's
freeze decision and must not be silently assumed approved.

## 4. Evidence gap register

| ID | Gap | Blocks | Resolution owner |
|---|---|---|---|
| G-01 | No `crypto-fixtures` verifier package; A04 command `bun run --filter crypto-fixtures test` is also not yet executable (workspace uses Bun) | AC-5 | A04 rework (integrator dispatch) |
| G-02 | No positive AEAD round-trip vectors; fixture ciphertexts are placeholders, not real XChaCha20-Poly1305 output | AC-5, AC-2 | A04 rework |
| G-03 | No key-wrapping vectors (account/recovery/vault/item) | AC-5 | A04 rework |
| G-04 | No OPAQUE (RFC 9807) vectors | AC-5 | A04 rework |
| G-05 | No independent (non-Rust) verification implementation/procedure output | AC-5 | A04 rework + H01 reviewer |
| G-06 | No crypto library selection/version/license inventory; `crypto-core` has zero dependencies; "dependency licenses" input artifact absent — **partially addressed 2026-09-03**: candidate evidence table added (`docs/security/H01-LIBRARY-EVIDENCE.md`); no selection, dependency, or approval recorded | AC-3 | H01 reviewer (evidence prepared; selection pending); B01 re-verifies versions/licenses at pin time |
| G-07 | No Argon2id target-device calibration evidence (500–1000 ms within bounds). An unsigned, non-binding evidence protocol (device matrix, measurement method, contract constraints, results/provenance templates) was added by the G-07 documentation-prep follow-up: `docs/security/H01-ARGON2ID-CALIBRATION-PROTOCOL.md`. No measurements exist and the gap remains open | AC-2 (T08) | B01 (post-approval) or A04 |
| G-08 | `ADR-0003`/`ADR-0004` referenced by `docs/security/DECISIONS.md` did not exist as files | Record integrity | ADR-0003 draft added by this task (unsigned); unsigned ADR-0004 draft added by the G-08 record-integrity follow-up (issue #1) — referential integrity restored, SD-0005 policy decisions remain pending in the draft |
| G-09 | `recovery-semantics-01` placeholder ciphertext is 56 B; expected 48 B (32 B key + 16 B tag) for `recovery-wrap` | AC-4, AC-5 | A04 rework |
| G-10 | Recovery-code display encoding unspecified ("any printable code") — **worksheet prepared 2026-09-03**: unsigned decision worksheet added (`docs/security/H01-RECOVERY-ENCODING-WORKSHEET.md`; requirements, open rulings, neutral tradeoffs, test/provenance requirements, blank decision/signature fields); no encoding chosen; gap remains open | AC-4 | H01 reviewer decision (or A04 rework) |
| G-11 | `kdf-parameters-01.canonicalCborHex` is non-canonical: final `outputLength` 32 is encoded as single byte `0x20` (major type 1, decodes −1) instead of the RFC 8949 minimal form `0x18 0x20`; contradicts the contract's canonical-CBOR mandate. Discovered by prep-agent re-derivation (§3.2.1) | AC-2, AC-5 | A04 rework (fix fixture; verifier per G-01 must regression-test canonical integers) |

No severity is pre-assigned; severity and disposition (fix vs formally accept)
belong to the human reviewer in ADR-0003.

## 5. Approval and finding record

- Findings and the approval signature are recorded **only** in
  `docs/decisions/ADR-0003-crypto-envelope-v1-approval.md` (currently an
  unsigned draft).
- Critical/High findings → integrator returns A04 to `READY` (task rule).
- Approval → integrator flips the contract status to frozen/Approved and
  updates `SD-0003` in `docs/security/DECISIONS.md`; contract files are outside
  H01 allowed paths and are not modified by this task.
- Nothing in this checklist, the ADR draft, or the decision register
  constitutes approval.
