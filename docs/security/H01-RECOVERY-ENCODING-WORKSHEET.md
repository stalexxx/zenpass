# H01 follow-up: Recovery-code display encoding decision worksheet (G-10)

Status: **documentation preparation only. No encoding is chosen, recommended,
ranked, or approved, and nothing in this document is binding.**

Prepared by the G-10 documentation-preparation task at HEAD `59e55b4` (branch
`stalexxx/g10-recovery-encoding-opencode`). Per `AGENTS.md` and
`docs/tasks/H01.md`, only the human security reviewer may approve findings or
freeze `crypto-envelope/v1`; gap G-10 in `docs/security/H01-REVIEW-CHECKLIST.md`
§4 assigns the recovery-code display-encoding decision to the H01 reviewer (or
A04 rework). This worksheet organizes the material for that decision. It is a
worksheet, not a decision.

## 1. Purpose and boundary

- It selects **no** encoding. Candidates in §5 are listed with neutral,
  verifiable properties; there is no ranking, weighting, shortlist, or
  recommendation. Inclusion of a candidate is not endorsement.
- It adds **no** acceptance constraint beyond those already stated in
  `docs/contracts/crypto-envelope-v1.md`, `docs/security/RECOVERY.md`, and
  `docs/security/THREAT-MODEL.md`. §2 restates fixed facts with the contract as
  the normative source; §3 separates binding requirements (each traced) from
  open rulings that belong to the reviewer.
- It does not modify `crypto-envelope/v1`, fixtures, code, `STATUS.md`, or
  task files. G-10 closes only when the human reviewer records a decision
  (§7, mirrored as a disposition in ADR-0003 per checklist §5).
- Interaction with other gaps: G-09 (fixture placeholder ciphertext length,
  56 B vs. expected 48 B) is byte-level and unaffected by any display
  encoding; it remains open independently (R-5).

## 2. Fixed facts (restated; no additions)

| # | Fixed fact (source) |
|---|---|
| F-1 | The recovery key is 32 uniformly random bytes (OS-CSPRNG); "any printable code is a display encoding only" (contract, "Key hierarchy") |
| F-2 | The recovery kit contains a display-only recovery code and `RecoveryWrappedAccountKey`; the client requires a challenge confirmation **derived from the recovery key** before marking the kit saved (contract, "Recovery reset and rotation") |
| F-3 | The recovery key is shown once and never stored or transmitted in plaintext (`docs/security/RECOVERY.md`) |
| F-4 | No plaintext keys or recovery material may be logged, persisted client-side, or sent to the server (threat-model assets and invariants; `AGENTS.md`) |
| F-5 | Loss of both master password and recovery kit is permanent; support has no bypass (SD-0004, T14) |
| F-6 | Typed errors include `InvalidRecoveryKit` and `InvalidEncoding`; errors contain no secret bytes or raw parser details (contract, "Typed errors") |
| F-7 | Wrapping uses kind `recovery-wrap`, XChaCha20-Poly1305 under the v1 envelope/AAD; authentication is verified before any plaintext is returned (contract) |
| F-8 | Fixtures under `fixtures/crypto/` are language-neutral, deterministic, and test-only (contract, "Fixtures"); `recovery-semantics-01` stores its fixed test-only key as `hex:` |

Consequence (follows from F-1/F-7; stated neutrally): every candidate in §5 is
a bijective representation of the same 256-bit key, so offline/online guessing
resistance (T08, T14) is identical across candidates. The decision space is
usability, transcription error handling, entry-channel behavior, and
specification/test surface.

## 3. Decision requirements

### 3.1 Binding requirements (traced to fixed facts)

| # | Requirement | Traces to |
|---|---|---|
| R-1 | Deterministic bijection at fixed input length: encode(32 bytes) → code and decode(code) → the same 32 bytes; no truncation, salting, or lossy transformation of key material | F-1, F-7 |
| R-2 | The code consists solely of printable characters; the exact permitted character set (or word list) is defined by the decision | F-1 |
| R-3 | Exactly one canonical code form exists; entry-time normalization (case, whitespace, separators) is specified exactly by the decision — non-canonical input is either rejected or normalized exactly as specified, never silently accepted in multiple forms | F-1, F-6 |
| R-4 | Display/entry supports the one-time display and the confirmation challenge; the challenge validates the decoded bytes; failure produces a typed error containing no secret bytes | F-2, F-3, F-6 |
| R-5 | The choice changes no envelope, AAD, wrapper, or existing fixture bytes; the encoding is a display/entry-layer construct only | F-1, F-7 |
| R-6 | The code is generated only from the random 32 bytes (OS-CSPRNG); no user-chosen phrases; no entropy reduction under any candidate | F-1 |
| R-7 | The code is never logged, persisted in plaintext, or transmitted; diagnostics and errors carry no code bytes; the one-time display surface is transient and not captured by analytics or persistence | F-3, F-4 (T04, T15) |
| R-8 | Once chosen, encode/decode is exercised by deterministic language-neutral fixtures with fixed test-only keys before implementation merges, with independent (non-Rust) verification per checklist §3.2 | F-8 (AC-5) |

### 3.2 Open rulings required from the reviewer (not decided here)

| # | Ruling required |
|---|---|
| OQ-1 | Error detection: must the code carry a checksum/check symbols (and if so, which construction), or is well-formed-input validation plus challenge/AEAD failure sufficient feedback? |
| OQ-2 | Case policy on entry (case-insensitive decoding allowed? mixed case rejected?) |
| OQ-3 | Grouping separators in display (e.g., fixed-width groups) and characters ignored on entry (e.g., spaces, hyphens): allowed set and exact normalization rules |
| OQ-4 | Character-set policy: full standard alphabet vs. confusion-reduced alphabet |
| OQ-5 | Character-based vs. word-based code |
| OQ-6 | Maximum acceptable code length / entry effort |
| OQ-7 | Supported entry channels: keyboard only, or also paste (clipboard policy per T15), QR or file import of the kit (each adds surface and needs an explicit ruling) |
| OQ-8 | Implementation home: recovery encode/decode inside the Rust crypto-core (with typed-error mapping, consistent with SD-0001's boundary) or in client code outside the core; `AGENTS.md` forbids crypto primitives outside crypto-core — the reviewer rules whether this codec belongs there |
| OQ-9 | Distinctness from transport encodings `b64:`/`hex:` used by the API and fixtures (e.g., reject code inputs carrying those prefixes) to prevent format confusion |
| OQ-10 | Where the chosen specification is recorded after approval (contract amendment at freeze by the integrator, ADR-0003 disposition text, or both) — contract files are outside this task's allowed paths |

## 4. Threat/UX tradeoff dimensions (neutral; the reviewer assigns weights)

- D-1 Transcription accuracy (manual writing/typing): confusable characters,
  case sensitivity, length. Per-candidate facts in §5.
- D-2 Wrong-code feedback point: without a checksum, a well-formed but wrong
  code is detected only at challenge verification or AEAD unwrap
  (`AuthenticationFailed` → `InvalidRecoveryKit`); with a checksum, entry can
  fail earlier and more specifically. Both endpoints are local typed errors;
  no oracle is exposed either way (F-6, F-7). The kit-creation challenge
  (F-2) is an end-to-end validation exercise regardless of OQ-1.
- D-3 Entry-channel ergonomics: typing effort scales with length and alphabet;
  mobile keyboards; paste accuracy vs. clipboard exposure (T15: minimize
  copying, clear clipboard where possible); word entry via selection UI vs.
  free typing.
- D-4 Exposure surface: any displayed code is copyable/photographable; length
  affects writing time and likelihood of a durable copy; the one-time,
  transient display rule (F-3, R-7) is unchanged by format.
- D-5 Confusion with existing encodings: the API and fixtures already use
  `b64:` (transport) and `hex:` (fixtures); shared or similar alphabets
  increase mis-paste risk in both directions (OQ-9).
- D-6 Dependency and localization surface: word lists add data dependencies
  and language variants; character sets vary across keyboard layouts.
- D-7 Specification and test surface: some candidates have formal specs with
  published test vectors (RFC 4648, BIP-173/350, BIP-39); others are
  conventions; all require repository fixtures per R-8 and negative vectors
  per §6.
- D-8 Support and diagnostics: identical for all candidates — generic errors,
  no logging, no bypass (F-5, F-6).
- D-9 Frozen-format interplay: the encoding is outside the frozen envelope
  bytes (R-5), but once recorded it becomes part of the recovery-kit
  interface; a later change affects already-saved kits and needs a recorded
  migration statement (§7 field; the reviewer may state one now or defer).

## 5. Candidate encodings (descriptive facts; no ranking, no recommendation)

All lengths are for a 32-byte key. "Case-sensitive" means mixed case carries
information and must be entered as displayed. The list is not exhaustive; the
reviewer may specify a different encoding, defer specification to A04 rework
under stated constraints, or record a finding (C-10).

| ID | Candidate (reference) | Alphabet / words | Length | Case | Built-in error detection | Other neutral properties |
|---|---|---|---|---|---|---|
| C-1 | Hexadecimal (RFC 4648 §8) | 0–9, a–f | 64 chars | Case-insensitive decode is conventional | None | Same family as `hex:` fixture values (D-5); classic I/l/1 and O/0 pairs absent; residual pairs such as b/6 remain |
| C-2 | Base64, standard (RFC 4648 §4) | A–Z, a–z, 0–9, `+`, `/` | 43 chars (44 with `=` padding) | Case-sensitive | None | Same family as `b64:` transport values (D-5); contains I/l/1 and O/0 confusables; `+`/`/` require care on some channels |
| C-3 | Base64url (RFC 4648 §5) | A–Z, a–z, 0–9, `-`, `_` | 43 chars (padding omitted per spec) | Case-sensitive | None | Keyboard/URL-safe symbol set; same confusables as C-2 |
| C-4 | Base32 (RFC 4648 §6) | A–Z, 2–7 | 52 chars (56 padded) | Uppercase canonical; case-insensitive decode is conventional | None | Excludes 0, 1, 8, 9; retains the letters (I, L, O, U) that confusion-reduced alphabets exclude |
| C-5 | Crockford Base32 (spec of 2002) | 0–9 and letters excluding I, L, O, U | 52 chars (+1 optional check) | Case-insensitive by design; hyphens ignored | Optional mod-37 check symbol `*`; detects single-symbol substitutions | Spec permits decoders to map look-alike inputs (O→0, I/L→1); accepting that mapping is an OQ-2/OQ-3-style ruling |
| C-6 | z-base-32 (draft specification) | `ybndrfg8ejkmcpqxot1uwisza345h769` | 52 chars | Lowercase (case-sensitive) | None | Alphabet ordered for human distinguishability; never standardized as an RFC |
| C-7 | Base58 / Base58Check (Bitcoin) | 0–9, A–Z, a–z minus 0, O, I, l | 43–44 chars (varies with leading zero bytes); Base58Check ≈ 49–50 incl. checksum | Case-sensitive | None (Base58) / 32-bit checksum (Base58Check) | Variable length unless pinned by the decision (R-3) |
| C-8 | Bech32 / Bech32m (BIP-173/350) | Lowercase 32-char charset excluding 1, b, i, o | ≈58 chars: 52 data + 6 checksum, plus optional human-readable prefix | Lowercase only; mixed case invalid | 30-bit checksum; documented detection guarantees for short strings (BIP-173 notes weakened guarantees beyond 90 characters, addressed by Bech32m) | Variant choice (Bech32 vs. Bech32m) and any prefix are part of the ruling |
| C-9 | Word-list mnemonic, BIP-39-style encoding of the 32 bytes | Fixed 2048-word list | 24 words | Word matching per ruling | 8-bit checksum in the standard construction (detects a random single-word corruption with probability 1−2⁻⁸) | Only the entropy encoding is a candidate here; adopting it does **not** adopt BIP-39 seed derivation (PBKDF2) — the recovery key remains the raw 32 bytes (R-1); word-list dependency and language variants (D-6) |
| C-10 | Other / defer / reject | — | — | — | — | The reviewer may specify any encoding not listed, defer detailed specification to A04 rework under stated constraints, or record a finding |

Grouping separators, an application-level checksum, or a prefix are orthogonal
options (OQ-1, OQ-3, OQ-9) applicable to several candidates; the rows above
describe each base specification.

## 6. Test and provenance requirements (binding on the executing task after a decision; nothing changes in `fixtures/crypto/` today)

| # | Requirement |
|---|---|
| T-1 | Positive fixtures (language-neutral JSON under `fixtures/crypto/`): at least two fixed test-only 32-byte keys → expected canonical code string → round-trip decode bytes; the existing fixed test-only key in `recovery-semantics-01` may be reused or new fixed keys defined |
| T-2 | Negative fixtures: wrong length; characters outside the chosen set; checksum failure (if OQ-1 adds one); case violation (per OQ-2); non-canonical padding/normalization forms (per OQ-3); `b64:`/`hex:`-prefixed input (per OQ-9) — each mapping to the ruled typed error |
| T-3 | Normalization conformance: entry-time case folding, whitespace, and separator handling exactly as ruled; canonical re-encode of normalized input equals the canonical form |
| T-4 | Challenge integration: decoded bytes feed the kit-saved confirmation challenge; tampered or wrong codes fail the challenge with a typed error; no secret bytes in any error or log |
| T-5 | Property/fuzz testing (implementation task): uniformly random 32-byte values round-trip; mutated codes never decode to a different silently-accepted key; failures are typed errors; no panics or parser-detail leakage |
| T-6 | Independent verification (checklist §3.2 discipline): a non-Rust encoder/decoder re-derives every fixture code; tool name, version, commands, and output digest recorded in the ADR-0003 evidence table |
| T-7 | Provenance: all fixture keys are fixed test-only values; no real user recovery material, no production keys (`AGENTS.md`); fixtures remain deterministic; recorded evidence is append-only |
| T-8 | UI-surface tests (post-approval client tasks): one-time display; transient display surface not captured by analytics/persistence; clipboard behavior per the T15 ruling; generic failure UI |
| T-9 | Fixture changes are additive only; G-09's ciphertext-length rework proceeds independently |

## 7. Decision record (completed only by the human H01 reviewer)

All fields are blank by design. This worksheet records **no decision** until
the reviewer completes and signs it. Per checklist §5, the approval authority
for H01 remains `docs/decisions/ADR-0003-crypto-envelope-v1-approval.md`; this
decision must be mirrored there as a disposition.

| Field | Value |
|---|---|
| Chosen encoding — exact specification (candidate ID or full spec; alphabet or word list; canonical case; separators; checksum construction if any; entry normalization rules) | — |
| Rulings on OQ-1 … OQ-10 | — |
| Implementation home ruling (OQ-8) | — |
| Recording plan (OQ-10: contract text at freeze / ADR-0003 disposition / both) | — |
| Required tests before merge (accept from §6, or state exceptions) | — |
| Migration statement for previously displayed kits (D-9) | — |
| Findings arising (ID, severity, disposition; Critical/High → A04 returns to READY) | — |
| Alternatives explicitly rejected and why (optional) | — |
| Reviewer name | — |
| Role | Human security reviewer (H01) |
| Date | — |
| Signature/attestation | — |

**No decision recorded and no signature present as of preparation of this
worksheet.**

## 8. Non-goals

- No encoding chosen, recommended, ranked, or shortlisted.
- No approval, signature, or freeze — that authority belongs to the human
  reviewer via `docs/decisions/ADR-0003-crypto-envelope-v1-approval.md`.
- No change to `crypto-envelope/v1`, fixtures, code, `STATUS.md`, or task
  files.
- This document does not by itself close G-10 or H01 and does not alter any
  task status.
