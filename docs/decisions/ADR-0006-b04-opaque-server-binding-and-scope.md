# ADR-0006: B04 OPAQUE server binding, session/rate-limit implementation, and scope split

Status: **approved by integrator decision — 2026-09-04.** This is a bounded
B04 implementation decision, in the same spirit as ADR-0005. It introduces no
new cryptographic primitive, does not modify `crates/crypto-core`, and does
not change the frozen `api-v1` or `crypto-envelope-v1` contracts.

## Context

`crates/crypto-core::opaque` already implements the full approved OPAQUE-3DH
Ristretto255 suite (RFC 9807, ADR-0003), including the server-side
registration and login helper functions, but nothing exposes them outside
Rust. B03 only shipped a browser WASM binding for client-side envelope
operations (`packages/crypto-wasm`); it explicitly declined to touch OPAQUE
server transport (see `packages/crypto-wasm/ARCHITECTURE-GAPS.md`).
`apps/backend` runs on Bun and has no Rust binding of any kind. B04's task
file declares allowed paths of `apps/backend/src/auth/`,
`apps/backend/src/devices/`, `apps/backend/test/auth/`, and `db/migrations/`
only — none of which can host a crypto binding.

B03 already proved that a `wasm-bindgen --target web` module builds
correctly and loads under Bun (`packages/crypto-worker`'s tests import
`packages/crypto-wasm/pkg/crypto_wasm.js` directly and pass under `bun test`).
The backend can use the same mechanism.

## Decision

1. **New package `packages/crypto-server/`.** A standalone Rust `cdylib`
   compiled with `wasm-bindgen` (`--target web`), mirroring
   `packages/crypto-wasm`'s build (`[workspace]` self-contained, same pinned
   `wasm-bindgen`/`js-sys`/`zeroize`/`getrandom` versions). It exports a
   mechanical, byte-oriented wrapper around the *existing*
   `crypto_core::opaque` functions used server-side
   (`ServerSetupHandle::generate/serialize/deserialize`,
   `server_registration_start`, `server_registration_finish`,
   `server_login_start`, `server_login_finish`). No new cryptography is
   added; every exported function calls straight into the already-approved
   helper. This is the same pattern B03 used for client operations.
2. **B04's allowed paths are amended** to add `packages/crypto-server/`, plus
   the integration-only root files `Cargo.toml`, `Cargo.lock`, and
   `bun.lock` for workspace/lockfile registration only — the same
   integration-only allowance B03 received. `docs/tasks/B04.md` is updated
   accordingly.
3. **Server setup material.** `ServerSetup` (private key + OPRF seed) is
   process-wide singleton secret material, not per-account. It is loaded
   from `OPAQUE_SERVER_SETUP` (base64), required in `production`; in
   `development`/`test` it is generated fresh in-process if unset (never
   persisted, logged once as a dev-only warning). Rotating it invalidates
   every stored `opaque_credentials` row — that operational procedure is a
   follow-up runbook item, not implemented here.
4. **Protocol-step dispatch.** `OpaqueRegisterRequest`/`OpaqueLoginRequest`
   carry only `accountId` and `clientMessage` — the frozen contract has no
   explicit step field. Registration's two legs (`RegistrationRequest` then
   `RegistrationUpload`) are distinguished by exact serialized byte length,
   which differs deterministically for the pinned suite (32 bytes vs. 192
   bytes for Ristretto255) — `RegistrationRequest::deserialize` validates
   only its own fixed prefix and does not reject trailing bytes, so a
   naive try-then-fallback dispatch would misclassify a `RegistrationUpload`
   as a `RegistrationRequest`; the length check avoids that. This is
   entirely inside the new binding crate — it changes no contract byte
   format. Login's two legs are not disambiguated this way at all: the
   backend calls `login_start` or `login_finish` explicitly based on
   whether it already holds pending login state for the account (§6).
5. **Registration is stateless server-side** between its two legs (the
   `opaque_ke` API requires no carried state to go from
   `server_registration_start` to `server_registration_finish`), so no
   extra storage is introduced for it.
6. **Login server-state.** `server_login_start` produces `ServerLogin` state
   that must survive until the matching KE3 call. Because the contract
   carries no login-attempt id, the backend keeps an in-process
   `Map<accountId, { stateBytes, expiresAt }>` with a 60-second TTL and
   eager cleanup on every access. This is a known limitation if the backend
   is ever horizontally scaled (state is not shared across instances); the
   current deployment is single-instance (see `infra/docker-compose.yml`).
   A durable/shared store is a follow-up if that changes.
7. **Session tokens.** A successful final login issues a fresh 256-bit
   `OsRng` token, base64url-encoded as `Session.accessToken`. Only
   `SHA-256(token)` is stored in the existing `sessions.token_hash` column;
   the raw token is never persisted or logged. Sessions are short-lived
   (15-minute default, configurable); `/auth/refresh` rotates the token
   (issues a new one, revokes the old `session_id`) and rejects an
   expired/revoked session or one bound to a revoked device.
8. **Migration.** One forward-only migration,
   `db/migrations/002_auth_sessions_and_rate_limit.sql`, adds
   `sessions.device_id` (per ADR-0005 §2) and a bounded
   `auth_rate_limits(account_id, scope, window_start, count)` fixed-window
   counter table (per ADR-0005 §3). It stores no IP address, password,
   token, or OPAQUE message.
9. **Enumeration-resistance limitation (residual, not a regression).**
   `crypto_core::opaque::server_login_start` requires a real
   `password_file`/`ServerRegistration`; the underlying `opaque_ke` library
   supports an oblivious "unknown account" response via `None`, but
   `crypto-core`'s current public helper does not surface that parameter.
   Widening that helper's signature is a protocol-surface change to
   already-frozen, H01-approved code and requires H01 re-review under the
   security invariants ("Protocol/crypto changes require a new version, ADR,
   human review..."), so it is explicitly out of scope here. B04 instead
   returns the same generically shaped 401 for an unknown `accountId` as for
   a wrong password, without a real OPRF exchange. Full OPRF-level
   indistinguishability remains open and is folded into the existing
   ADR-0003 F-2/F-3 follow-up track (T17).
10. **No new third-party dependency.** `packages/crypto-server` reuses
    exactly the dependency set and pinned versions already approved for
    `packages/crypto-wasm`. No new runtime dependency is added to
    `apps/backend`.

## Consequences

- B04 may now implement `/auth/opaque/register`, `/auth/opaque/login`,
  `/auth/refresh`, `/auth/logout`, `/devices`, `/devices/{id}`,
  `/devices/{id}/revoke`, and durable login throttling, fully within the
  existing frozen `api-v1` contract.
- **WebAuthn MFA is explicitly out of this slice.** `packages/contracts/openapi.yaml`
  defines no `/auth/webauthn/*` paths or schemas at all — only the prose in
  `docs/contracts/api-v1.md` mentions the group. Adding it is a contract
  change (new paths/schemas) and MFA is security-sensitive, so it requires
  its own ADR and human security approval before implementation, per
  `AGENTS.md` ("Do not edit a `docs/contracts/*/v1` contract without an ADR
  and human security approval") and the threat-model human-review gate.
- **`/account/recovery-reset` is explicitly out of this slice.** The
  `RecoveryResetRequest.recoveryProof` format depends on the still-unsigned
  recovery-code display-encoding decision
  (`docs/security/H01-RECOVERY-ENCODING-WORKSHEET.md`, gap G-10) — that
  worksheet is deliberately unsigned pending the human H01 reviewer.
  Implementing recovery-reset verification before that decision would mean
  inventing the missing crypto/encoding decision, which `AGENTS.md`
  forbids ("do not make unstated architectural decisions").
- Both gaps are tracked in `STATUS.md` as an open B04 follow-up, not folded
  silently into "done."
