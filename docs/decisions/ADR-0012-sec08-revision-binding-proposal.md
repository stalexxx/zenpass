# ADR-0012: Proposal to bind `revision`/`deleted` into `crypto-envelope`'s authenticated data

Status: **PROPOSED — pending human security review.** This is a draft for the
human security reviewer, prepared per `docs/tasks/SEC-08-ADR-DRAFT.md`. It
authorizes nothing by itself: no code, contract, or fixture in this repository
changes as a result of this document. GitHub issue #8 ("[ADR-needed]") stays
open until a human reviewer records a decision below.

## Context

SEC-04 (GitHub issue #4, merged) added the two invariants
`packages/sdk/src/repository.ts`'s `assertMonotonicPut` can enforce without
touching the frozen `crypto-envelope/v1` contract:

- **Revision monotonicity**: `incoming.revision` must never be lower than
  `existing.revision` (`packages/sdk/src/repository.ts:59-65`).
- **Same-revision integrity**: at equal revisions, every field of `incoming`
  (`ciphertext`, `envelopeVersion`, `deleted`, `createdAt`, `updatedAt`, via
  `sameRecordBytes`, `packages/sdk/src/repository.ts:23-31`) must match
  `existing` exactly (`packages/sdk/src/repository.ts:66-72`).

`assertMonotonicPut`'s own doc comment (`packages/sdk/src/repository.ts:33-56`)
already names the residual this ADR is asked to close, verbatim:

> This cannot detect a genuinely-valid *older* ciphertext relabeled by the
> server under a fabricated *higher* revision number: `crypto-envelope/v1`'s
> AAD binds `keyVersion` but not `revision`/`deleted`, so nothing in the
> envelope lets the client tell that case apart from a legitimate new write.

### The exact AAD construction today

`docs/contracts/crypto-envelope-v1.md:41-53` (Domain separation and
associated data) specifies the AAD as the canonical CBOR map:

```text
{ 1: "crypto-envelope/v1", 2: accountId, 3: vaultId-or-null,
  4: itemId-or-null, 5: recordType, 6: keyVersion }
```

The Rust implementation matches this exactly. `crates/crypto-core/src/
envelope.rs:69-125` (`Context` and `Context::encode_aad`) builds the AAD from
exactly six fields — `account_id`, `vault_id`, `item_id`, `record_kind`, and
`key_version` (plus the fixed format-version string) — with no `revision` or
`deleted` field anywhere in the struct or the encoding call
(`envelope.rs:114-125`):

```rust
canon::encode_owned(vec![
    canon::text(1, FORMAT_VERSION),
    canon::text(2, self.account_id),
    vault,
    item,
    canon::text(5, self.record_kind.as_str()),
    canon::int(6, i64::try_from(self.key_version)...),
])
```

`crates/crypto-core/src/envelope.rs:1-10`'s own module doc says as much:
"identifiers, record types and key versions are all bound into the
authentication of every envelope" — `revision` and `deleted` are conspicuously
absent from that list, and grepping the struct confirms it. The AAD is
authenticated by the AEAD tag exactly like the ciphertext
(`crates/crypto-core/src/aead.rs:41-65`, `seal`/`open` pass `aad` as
`Payload.aad` to `chacha20poly1305`'s combined encrypt/decrypt), so an
attacker without the key cannot forge or edit AAD bytes independently — but
they also gain nothing from that, because AAD as currently defined says
nothing about revision/deleted in the first place. `open_envelope`
(`envelope.rs:281-315`) verifies the outer kind against the AAD's embedded
kind, verifies `embedded_ctx == expected_ctx`, and only then calls
`aead::open`; none of those checks or the AAD schema itself carry `revision`
or `deleted`.

Confirming where `revision`/`deleted` actually live: `ItemRecord`
(`packages/contracts/src/index.ts:6-9`) carries `revision: number` and
`deleted: boolean` as plaintext top-level fields alongside the opaque
`ciphertext`/`envelopeVersion` strings — they are never inside the encrypted
payload, and the server assigns/stores `revision` directly
(`apps/backend/src/sync/routes.mjs:77,99-106`: `currentRevision + 1` inside
`upsertItem`). The backend already treats `ciphertext` as opaque; it has no
reason to parse AAD and this proposal does not ask it to.

### The exact attack

1. A legitimate client seals envelope `E` for item `(vaultId, itemId)` at some
   point, honestly reaching the server as `ItemRecord{revision: r, deleted: d,
   ciphertext: E, ...}`.
2. Later, a dishonest or compromised server (or a MITM able to inject a change
   feed page — the same untrusted-transport threat model already accepted
   throughout this repo's sync design) re-serves that exact byte-identical `E`
   to a client in a change-feed page, but relabels the surrounding plaintext
   metadata as `{revision: r' , deleted: d'}` with `r' > existing.revision` on
   the client (and, if `d' = false` while the true history moved to
   `deleted = true`, a tombstone can be undone; if `d' = true`, a live item can
   be relabeled as deleted).
3. `assertMonotonicPut` (`repository.ts:57-73`) sees `incoming.revision (r') >
   existing.revision` and returns without throwing — this is indistinguishable
   from a legitimate new write, because the check only compares the *claimed*
   metadata fields of two `ItemRecord`s; it never inspects the ciphertext's
   own authenticated content.
4. Nothing in `crypto-envelope/v1` lets the client discover that `E`'s AAD (if
   it authenticated a revision) would say `r`, not `r'` — because it doesn't
   authenticate a revision at all. The attack is a **stale-content replay
   labeled as fresh**, not a forgery of ciphertext bytes; AEAD authentication
   is fully intact for `E` and offers no defense here, because it authenticates
   a scope (`accountId`/`vaultId`/`itemId`/`recordType`/`keyVersion`) that does
   not include the field the attacker is lying about.

This is precisely the residual SEC-04 documented and ADR-0011's G1 named an
analogous instance of for key-bundle publication (`docs/decisions/
ADR-0011-c04-approval-packet.md:237-245`, "a malicious server can replay a
previously valid bundle to a fresh extension profile ... this online-only
first slice has no trusted persistent high-water mark and cannot guarantee
first-enrollment freshness"). ADR-0003's G-06/library findings do not cover
this gap; it is a contract-shape gap, not a library-correctness gap.

## Candidate designs

### Option A (recommended): extend the AAD to authenticate `revision` and `deleted`

**Mechanism.** Add two fields to the `Context` struct and the AAD CBOR map:

```text
{ 1: "crypto-envelope/v2", 2: accountId, 3: vaultId-or-null,
  4: itemId-or-null, 5: recordType, 6: keyVersion,
  7: revision, 8: deleted }
```

- Key `7`: unsigned integer, the item's own revision number (same domain as
  `ItemRecord.revision`, i.e. server-assigned per
  `apps/backend/src/sync/routes.mjs:104`).
- Key `8`: a canonical boolean-equivalent CBOR value (this project's `canon.rs`
  currently only shows `text`/`int`/`bytes`/`null` helpers used by
  `envelope.rs`; a canonical boolean encoding — CBOR simple values `0xf4`/
  `0xf5` — or a fixed 0/1 integer must be added to `crates/crypto-core/src/
  canon.rs` and specified byte-for-byte in the contract; this ADR does not
  itself pick the encoding, that is exactly the kind of byte-level decision
  this ADR is scoped to hand to a bounded follow-up task, see "Scope
  boundary" below).
- `RecordKind`s that have no revision concept (`AccountWrap`, `RecoveryWrap`,
  `VaultWrap`, `ItemWrap` — wrapper envelopes are not part of the sync
  change-feed and have no `ItemRecord.revision`/`deleted`) would encode
  `revision: 0` and `deleted: false` as fixed sentinel values, analogous to
  how `vaultId`/`itemId` are already `null` for kinds that don't need them
  (`envelope.rs:57-66`, `expects_vault`/`expects_item`). Only `ItemPayload`
  (and, if ever used for sync, `ExportManifest`) would carry real values.
- Field order matters for canonical CBOR (ascending integer key,
  `docs/contracts/crypto-envelope-v1.md:65`, "Maps sort by encoded integer
  key"); `7` and `8` slot in after the existing `6` without disturbing any
  existing key, so no existing key's meaning changes — this is a strict
  superset of the v1 AAD schema, not a reinterpretation of it.

**Where the client's claimed `revision` comes from before the server assigns
one.** This is the one subtlety worth being explicit about, because it looks
at first glance like a chicken-and-egg problem: `apps/backend/src/sync/
routes.mjs:77-106` shows the server — not the client — assigns the stored
`revision` as `currentRevision + 1` inside the mutation transaction, so how
can the client seal an envelope's AAD with a revision it doesn't yet know?
The answer is that the client already knows it deterministically under the
existing optimistic-concurrency contract: a `Mutation` carries `baseRevision`
(`packages/contracts/src/index.ts:10`), and `applyMutation`
(`apps/backend/src/sync/routes.mjs:63-110`) only accepts a mutation when
`mutation.baseRevision === currentRevision`, in which case (and only in that
case) the assigned revision is exactly `currentRevision + 1 ==
baseRevision + 1`. So the client seals the envelope's AAD with
`revision = baseRevision + 1` *before* sending the mutation; if the server's
atomic check accepts it, the assigned revision provably equals the claimed
one; if the check rejects it (409 `Conflict`), the mismatched envelope is
never persisted as that revision, and the client must re-derive a fresh
envelope against the corrected `baseRevision`. No round-trip or protocol
change is required — the client only needs to seal the ciphertext with the
revision it is *proposing*, which it always already knows.

**Where verification happens, and why this is not a drop-in
`assertMonotonicPut` change.** Checking that an incoming `ItemRecord`'s
claimed `(revision, deleted)` actually matches what's cryptographically bound
inside its ciphertext's AAD requires calling `open_envelope`
(`crates/crypto-core/src/envelope.rs:281-315`) with the item key, because AAD
authenticity can only be established by successfully running the combined
AEAD verify+decrypt (`aead.rs:72-97`) — there is no cheaper AAD-only
authentication check in XChaCha20-Poly1305, and `inspect_envelope`
(`envelope.rs:317-329`) explicitly does **not** verify authenticity, it only
structurally parses the AAD bytes as stored, which an attacker who doesn't
have the key cannot make lie under `open_envelope`, but *can* make lie under
`inspect_envelope` alone (mismatched AAD bytes just fail to open later; they
are not rejected by inspection). `LocalRepository`/`assertMonotonicPut`
(`repository.ts:90-106`) is deliberately plaintext-free — "a conforming
implementation must not decrypt anything either; decryption requires a
caller-held key this interface never sees" — so the new check cannot live
there without breaking that boundary. Concretely, Option A moves (or adds) the
revision/deleted authenticity check to wherever the SDK/client already calls
`open_envelope` with the item key — most naturally, the sync pull path or
vault-unlock/decrypt path that already has the key — comparing the AAD's
authenticated `revision`/`deleted` against the `ItemRecord`'s plaintext
`revision`/`deleted` metadata and failing closed on mismatch. This is an
architectural consequence worth the reviewer weighing explicitly: an item
that is stored locally via `putItem` but not yet decrypted (e.g. not yet
opened in the UI) is **not** protected by this check until it is decrypted;
see "Residual risks" below.

**`envelopeVersion`: new version required, not in-place.** Per
`docs/contracts/crypto-envelope-v1.md:125-131` ("Versioning and migration"):
"A future version uses a new string, fixtures, ADR, and explicit migration."
Adding authenticated fields changes what bytes AEAD authenticates, so a v1
reader could never open a v2 envelope's ciphertext (the AAD it re-derives
would omit keys `7`/`8`, producing a byte-for-byte different AAD than what
was actually used to seal, so `aead::open` would fail authentication) and a
v1-sealed envelope's AAD has no `revision`/`deleted` to check in the first
place. This is unambiguously a new `envelopeVersion` — `crypto-envelope/v2` —
not an in-place v1 change, consistent with the contract's own frozen-file
rule and with `AGENTS.md`'s "Do not edit a `docs/contracts/*/v1` contract
without an ADR and human security approval."

**Migration mechanics for existing ciphertext.** `docs/contracts/
crypto-envelope-v1.md:112-114` and `:127-131` already establish the pattern
used for password-wrapper rotation and version migration generally:
copy-on-write — decrypt old, validate, encrypt new, verify new, commit; old
remains recoverable until completion; item ciphertexts are not rewritten
proactively for wrapper rotation. The same pattern applies here:

- Every **new write** (create or edit) after v2 ships seals with v2
  immediately — no separate migration step is needed for the write path,
  because a write already fully re-encrypts its item (fresh nonce, fresh
  ciphertext) regardless of this ADR.
- **Existing items untouched since before v2** remain sealed as v1 envelopes
  indefinitely unless a client explicitly re-encrypts them. Dual-read support
  (accept both `crypto-envelope/v1` and `crypto-envelope/v2` on read,
  keyed off the envelope's own `1: version` field, exactly as
  `docs/contracts/crypto-envelope-v1.md:127` already anticipates — "v1
  readers reject unknown versions/fields," implying v2 readers are expected
  to know about v1) is required for as long as any v1 item can exist, i.e.
  effectively indefinitely unless a one-time forced re-encryption pass is
  run. A forced pass requires every client with the relevant item key to come
  online, decrypt, and re-seal every item it can reach — expensive, and not
  something this ADR can mandate a timeline for.
- Consequence the reviewer should weigh explicitly: **v1 items are not
  retroactively protected.** An old, never-edited item stays vulnerable to
  exactly the SEC-04/issue-#8 replay for as long as it remains a v1 envelope.
  This ADR proposes accepting that as a bounded, honestly-disclosed residual
  (see below) rather than mandating an expensive forced re-encryption sweep
  as part of the same change — but the reviewer may instead decide the
  bounded follow-up task must include an opportunistic re-encryption-on-next-
  decrypt step (cheap, incremental, no forced sweep) to shrink the exposure
  window over time; this ADR recommends that opportunistic step but leaves it
  to the follow-up task's design, not this document.
- **Web and extension clients** must both gain v1/v2 dual-read and v2-only
  write support before v2 traffic appears on the wire; this is a bounded
  `packages/sdk`/`apps/web`/`apps/extension` follow-up, not a `crypto-core`-
  only change, since `assertMonotonicPut`'s new check and the seal call sites
  live in TypeScript, not Rust.
- **The backend stays opaque to `revision`/`deleted` inside the envelope**,
  exactly as today: it never needs to parse AAD, and this proposal does not
  ask it to. The backend's own `revision`/`deleted` columns
  (`apps/backend/src/sync/store.mjs`) remain the source of the plaintext
  metadata the client checks its ciphertext's AAD against; the backend does
  not gain any new trust or capability from this change, which is the point.

### Option B: client-side trusted high-water-mark (real, but does not close the gap for a fresh device)

**Mechanism.** Extend `assertMonotonicPut`'s existing per-`(vaultId, itemId)`
revision check with a durable, never-decreasing "peak revision ever observed"
value, persisted locally independently of whatever the server currently
claims is `existing.revision` (e.g. even across a local delete-and-resync,
or an explicit tombstone-then-recreate at the same server-visible id). This
requires no crypto-core or contract change at all — it is a pure
`packages/sdk`/local-storage change, and superficially looks attractive
because it needs no ADR-gated envelope work.

**Why it does not actually close issue #8's gap.** The watermark only
protects a device that has *already synced past* the real revision the
attacker is trying to roll back — exactly the same shape of residual
ADR-0011's G1 named for key-bundle publication: "a malicious server can
replay a previously valid bundle to a fresh extension profile... this
online-only first slice has no trusted persistent high-water mark and cannot
guarantee first-enrollment freshness." A **new device**, a **freshly
re-installed client**, or a client that has never seen this particular item
before has no watermark to check against, and a dishonest server can hand it
a self-consistent, entirely stale snapshot (old ciphertext, old-but-internally-
coherent `revision`/`deleted` labels it invented) that the watermark cannot
distinguish from the truth, because the watermark only remembers what *this
device* has already seen. This is a structurally weaker fix than Option A:
Option A cryptographically ties `revision`/`deleted` to ciphertext the
attacker cannot forge; Option B only makes a *returning* device harder to
roll back and offers nothing to a first-time observer.

**Recommendation on Option B.** Worth adopting *in addition to* Option A
(defense in depth, no crypto-core change, catches the returning-device case
even for still-v1 items during the migration window described above), but
not worth adopting *instead of* Option A, because it leaves the core issue
(#8's literal fresh-observation replay) fully open. This mirrors how
ADR-0011 recommended accepting a bounded residual for C04's first slice
rather than pretending a local-only mechanism closes a trust gap that
requires either cryptographic binding or a genuinely global transparency
mechanism.

**A heavier alternative considered and not recommended for this bounded
ADR.** A server-attested, independently-signed monotonic counter (a
transparency-log-style scheme, e.g. one append-only, publicly-verifiable log
of revision assignments the client checks a signed inclusion/consistency
proof against) would close even the fresh-device case without relying on
"the device has seen this before." It is not proposed as a candidate here
because it is a materially larger project — a new trust root, a new signing
key the client must verify out-of-band, log infrastructure, and its own
threat model and ADR — not a bounded crypto-core/client change, and would
still not obviously beat Option A's cost/benefit for this codebase's current
scale. Naming it here is in the same spirit as this ADR's instruction not to
force a false second option: Option A is the honest, bounded answer; a
transparency log is a real but disproportionate alternative that a future,
separately-scoped ADR could revisit if the threat model's trust assumptions
about the server ever need to tighten further than "detects tampering,
cannot yet prove global freshness to a first-time observer."

## Recommendation

Adopt **Option A** (AAD extension to `crypto-envelope/v2`, keys `7:
revision`, `8: deleted`, client seals with its predicted next revision per
the `baseRevision + 1` argument above) as the bounded fix for issue #8,
paired with Option B's local high-water-mark as a defense-in-depth addition
that costs nothing extra in `packages/sdk`. This is a recommendation, not a
decision: the human security reviewer decides whether to approve it, request
a different byte-level encoding for `deleted`, require the opportunistic
re-encryption-on-decrypt step as mandatory rather than optional, or reject
the proposal outright and request a different design.

## Scope boundary

Approval of this ADR, if granted, authorizes only:

1. A `crypto-envelope/v2` contract revision in `docs/contracts/` adding keys
   `7`/`8` to the AAD map as described, with new language-neutral fixtures
   (positive v2 vectors, v1-still-valid-for-existing-data vectors,
   tampered-revision/tampered-deleted negative vectors) alongside — never
   replacing — the existing `crypto-envelope-v1.md` and its fixtures.
2. The corresponding bounded `crates/crypto-core` change (new `Context`
   fields, new `canon.rs` boolean/sentinel encoding, updated `seal_envelope`/
   `open_envelope`, new tests mirroring the existing ones in
   `crates/crypto-core/src/envelope.rs:331-520`) and its WASM/UniFFI binding
   updates.
3. The corresponding bounded `packages/sdk` change: `assertMonotonicPut`'s
   doc comment update, the new revision/deleted-authenticity check at
   whichever decrypt-time call site the follow-up task identifies, and v1/v2
   dual-read support.
4. The corresponding bounded `apps/web`/`apps/extension` wiring so both
   clients seal v2 and can still read v1.

It does **not** authorize: a blanket `crates/crypto-core` rewrite; changes to
OPAQUE, Argon2id, key hierarchy, or recovery semantics (all untouched by this
proposal); a forced re-encryption sweep of existing data unless the reviewer
explicitly requires it as part of the follow-up task; or any change to
`docs/contracts/api-v1.md`'s change-feed/mutation shapes beyond what's needed
to keep `revision`/`deleted` visible as plaintext metadata exactly as today.
Mirroring ADR-0011's discipline: direction approval here must not, by itself,
mark a follow-up implementation task `READY` — the integrator still creates a
bounded task with an explicit `Allowed paths` list, preserves the v1 contract
and fixture files unmodified, and requires the listed fixtures and tests to
pass before merge.

## Residual risks accepted either way

Even under the recommended Option A:

- **Pre-migration v1 items remain exposed** for as long as they are not
  re-encrypted, as described above. This is a time-bounded, honestly-scoped
  residual, not a claim of full closure on day one.
- **A never-decrypted, freshly-stored v2 item is not yet protected.** Because
  the revision/deleted check requires `open_envelope` with the item key, an
  item written locally via `putItem` but not yet displayed/decrypted has had
  only `assertMonotonicPut`'s existing metadata checks applied, not the new
  cryptographic one. A relabeled-replay of a genuinely-v2-sealed old envelope
  could sit locally undetected until the item is actually opened. Whether
  this is acceptable, or whether the follow-up task must move the check
  earlier (e.g. into the sync pull path itself, which would require handing
  `LocalRepository` a key it currently and deliberately never receives — a
  meaningful architecture change of its own) is a question this ADR poses to
  the reviewer rather than resolving.
- **No global freshness guarantee for a first-time observer**, exactly as
  ADR-0011's G1 already accepted for key-bundle publication: Option A proves
  a given ciphertext's *own claimed* revision/deleted are self-consistent and
  unforgeable, but a server that is dishonest from the very first sync a
  device ever performs can still hand that device an entirely self-consistent
  but stale *complete* history (every envelope's internal revision matching
  its wrapper metadata, just all older than the true present state) with no
  cryptographic tell distinguishing it from truth. Closing that would require
  the transparency-log-style mechanism explicitly not recommended above.
- **`keyVersion` rotation and this fix are independent.** Nothing here changes
  how key rotation is authenticated; a rotated key's envelopes get their own
  fresh `revision`/`deleted` binding under the new `keyVersion`, same as
  today.

## Human decision record

| Field | Value |
|---|---|
| Reviewer / date | *(pending)* |
| Decision | *(pending: approve Option A as specified / approve with modifications / reject / request different design)* |
| Byte-level encoding of `deleted` (CBOR boolean vs. fixed-width integer sentinel) | *(pending)* |
| Opportunistic re-encryption-on-decrypt: mandatory in follow-up task or optional | *(pending)* |
| Revision/deleted authenticity check placement (decrypt-time only vs. moving key access into the sync/pull path) | *(pending)* |
| Option B (local high-water-mark) adopted as defense-in-depth alongside Option A | *(pending)* |
| Residual risks (pre-migration v1 exposure; undecrypted-item window; no first-observer freshness guarantee) explicitly accepted | *(pending)* |

This table is left blank for the actual human security reviewer. No
signature or attestation is recorded here; this document does not authorize
any code, contract, or fixture change until it is filled in and GitHub issue
#8 is updated accordingly by a human, not by an agent.
