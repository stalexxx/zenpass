# ADR-0007: Browser OPAQUE client binding location for C02

Status: **approved by integrator decision — 2026-09-04.** Bounded
implementation decision, same spirit as ADR-0005/ADR-0006. No new
cryptographic primitive, no `crates/crypto-core` change, no contract
change.

## Context

`crates/crypto-core::opaque` implements the full approved OPAQUE-3DH
Ristretto255 suite (RFC 9807, ADR-0003) including client-side registration
and login helpers, but `packages/crypto-wasm` (B03) never exposed them —
B03 explicitly scoped OPAQUE transport out (see
`packages/crypto-wasm/ARCHITECTURE-GAPS.md`) and B04/ADR-0006 only added a
*server*-side binding (`packages/crypto-server`), plus a `test_client`
module explicitly labeled as test-only, not the production browser client,
with production browser integration deferred to "a later web-client task
(C01/C02)".

C02 (shared TypeScript SDK) is that task: it cannot implement the OPAQUE
register/login HTTP flow against `/auth/opaque/register` and
`/auth/opaque/login` without a real client-side OPAQUE binding, and C02's
declared allowed paths (`packages/sdk/`, `packages/importers/`,
`packages/domain/`) have nowhere to put one.

## Decision

1. **`packages/crypto-wasm/src/lib.rs` gains four client-side OPAQUE
   exports**, mechanically wrapping the existing
   `crypto_core::opaque::{client_registration_start, client_registration_finish,
   client_login_start, client_login_finish}` functions — the same
   byte-in/byte-out pattern `packages/crypto-server`'s (test-only)
   `test_client` module already uses, now promoted to the real production
   binding. No new cryptography; state (`ClientRegistration`/`ClientLogin`)
   is passed back to the caller as opaque bytes between calls, exactly as
   the server-side binding does.
2. **C02's allowed paths are amended** to add `packages/crypto-wasm/`
   (client-OPAQUE-export addition only — not envelope/session code, which
   stays B03's already-merged, already-tested surface) alongside its
   existing `packages/sdk/`, `packages/importers/`, `packages/domain/`.
   `docs/tasks/C02.md` is updated accordingly.
3. The SDK (`packages/sdk`) owns the actual register/login HTTP
   choreography (two-leg dispatch per ADR-0006 §4, using `@pass/contracts`
   types for request/response shapes) and session-token storage/refresh
   logic; `packages/crypto-wasm` only ever returns/consumes protocol
   message bytes and opaque state bytes, never makes an HTTP call itself.
4. Password bytes passed into these new exports follow the same handling
   already established in `packages/crypto-wasm`'s `unlock_item_session`:
   zeroized on the Rust side after use; the caller-owned JS buffer cannot
   be wiped across the wasm boundary (documented there already, applies
   identically here).

## Consequences

- C02 can implement a real, testable OPAQUE client against the live
  backend (B04) without inventing cryptography or duplicating
  `crypto_core::opaque`'s logic in TypeScript.
- `packages/crypto-wasm`'s golden-vector test (B03) and its existing
  exports are unaffected; this is a pure addition.
- WebAuthn MFA and `/account/recovery-reset` remain out of scope here too
  (ADR-0006 Consequences still apply — both need a separate human-approved
  decision before any client or server work targets them).
