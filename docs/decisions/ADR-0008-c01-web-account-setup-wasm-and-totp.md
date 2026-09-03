# ADR-0008: C01 account-setup/recovery-kit WASM exports and client-side TOTP

Status: **approved by integrator decision — 2026-09-04.** Bounded
implementation decision, same spirit as ADR-0005/0006/0007. No new
cryptographic primitive, no `crates/crypto-core` change, no contract
change.

## Context

C01 (web vault) must implement registration (create AccountKey/VaultKey,
wrap the AccountKey under both the password-derived UnlockKey *and*
independently under a fresh RecoveryKey, per `docs/ux/flows.md`
"Registration") and TOTP display for TOTP-enabled login items (per C01's
required implementation list). Neither has an exposed WASM binding today:

- `packages/crypto-wasm`'s `create_item_session_for_setup` generates fresh
  keys and a password wrapper only; there is no export for the
  independent recovery-key wrap (`crypto_core::keys::wrap_account_key_with_recovery`,
  `crypto_core::recovery::RecoveryKit`) or for opening a recovery kit
  (`open_account_key_with_recovery`) — both already exist in
  `crates/crypto-core`, unused outside it.
- Nothing implements TOTP (RFC 6238) code generation anywhere in the
  repository.
- C01's declared allowed paths are `apps/web/` only.

## Decision

1. **C01's allowed paths are amended** to add `packages/crypto-wasm/` and
   `packages/crypto-worker/`, narrowly: adding new exports/message types
   for account-setup (fresh key generation + password wrap + recovery
   wrap, mirroring `create_item_session_for_setup`'s existing shape) and
   recovery-kit opening (`open_account_key_with_recovery`), all mechanical
   wraps of functions `crates/crypto-core` already implements and already
   unit-tests. C01 must not modify B03's existing exports
   (`unlock_item_session`, `seal_item_payload`, `open_item_payload`,
   `inspect_envelope`, `close_session`) or C02's OPAQUE client exports
   (ADR-0007) — additive only. `docs/tasks/C01.md` is updated accordingly.
2. **Recovery-key display encoding remains unresolved (G-10)** —
   `docs/security/H01-RECOVERY-ENCODING-WORKSHEET.md` is deliberately
   unsigned. C01 must not invent a "final" display encoding. It may show
   the raw recovery key bytes as a plain, explicitly-labeled provisional
   hex string (e.g. "Provisional format — pending final display-encoding
   decision (G-10); the underlying key is unaffected") so the
   onboarding flow is testable end-to-end, but must not present it as the
   shipped format, and must not add any grouping/checksum/word-list
   scheme of its own invention (`docs/security/H01-RECOVERY-ENCODING-WORKSHEET.md`
   §3.2 OQ-1..OQ-9 are explicitly reserved for the human H01 reviewer).
3. **Client-side TOTP (RFC 6238) may be implemented directly in
   `apps/web/`** using only the browser's native Web Crypto API
   (`crypto.subtle.sign` with HMAC) for the underlying HMAC-SHA1/256/512 —
   never a hand-rolled HMAC or hash implementation. This is a
   display-only derivation over an already-decrypted TOTP secret (the
   user's own item data, decrypted client-side after unlock); it carries
   no vault-confidentiality guarantee the way AEAD/KDF/OPAQUE do, so it
   does not require `crates/crypto-core` residency the way those
   primitives do. TOTP secrets themselves remain opaque ciphertext at
   rest and in transit exactly like any other item field — this decision
   only concerns the *display* computation after decryption.

## Consequences

- C01 can implement a complete, testable registration flow (including
  the recovery-kit reveal/confirm step from `docs/ux/flows.md`) and TOTP
  code display without inventing cryptography or waiting on G-10.
- The shipped recovery-code display format is **not** finalized by this
  ADR and remains an explicit open item; C01's onboarding UI must carry
  the provisional labeling described in §2 until a human H01 reviewer
  records a G-10 decision.
- `packages/crypto-wasm` and `packages/crypto-worker`'s existing,
  already-merged/tested surfaces (B03, ADR-0007) are unaffected — this is
  additive only, verified by requiring C01's changes not to touch any
  existing export.
