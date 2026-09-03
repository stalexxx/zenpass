# ADR-0005: Auth session delivery, device binding, and durable rate limiting

Status: **approved by integrator decision — 2026-09-03.** This records the
bounded B04 implementation decision requested by maintainer `stalexxx` in the
integration session. It does not alter the cryptographic envelope, OPAQUE
suite, recovery proof format, or the H01 findings and release gates.

## Context

`api/v1` provides an OPAQUE login endpoint and a `Session` response schema,
but did not state how a successful final OPAQUE step yields that session.
The initial schema also had no durable session-to-device relationship, while
the threat model requires revoked devices to lose their sessions. Finally,
B04 requires login throttling but no durable storage choice was recorded.

## Decision

1. A successful **final** OPAQUE login response is a JSON `Session` body
   (`accessToken`, `expiresAt`). Incomplete OPAQUE exchanges continue to return
   `OpaqueMessage`. The access token is never embedded in an OPAQUE message,
   logged, or placed in a URL. The OpenAPI response is an explicit `oneOf` to
   represent those two protocol states.
2. Sessions have an optional server-side `device_id` foreign key. A newly
   authenticated session is initially device-unbound and may use only its
   short-lived access token. Explicit device registration binds the current
   session; only a non-revoked device-bound session can refresh. Revoking a
   device transactionally revokes all sessions bearing that `device_id`.
   Recovery reset transactionally revokes every session and device for the
   account. No client-controlled token claim substitutes for the database
   binding.
3. Login throttling is durable PostgreSQL state keyed by `account_id` and an
   operation scope. It stores no IP address, password, token, OPAQUE message,
   or vault material. The implementation uses a fixed-window counter with an
   atomic increment/check and bounded cleanup. Configuration values and reject
   responses reveal neither account existence nor the reason for failure.

## Consequences

- B04 is permitted to add one forward-only migration under `db/migrations/`
  for `sessions.device_id` and the bounded auth-rate-limit table, along with
  its allowed auth/device code and tests. It may not alter existing migrations.
- The API change is additive at the response-schema level and preserves the
  existing `OpaqueMessage` flow for non-final steps.
- Device metadata remains server-visible; B04 must validate `devices.name` and
  must not place vault data in it.
- A public release still requires H02 and the unresolved ADR-0003 F-2/F-3
  follow-ups. Any change to OPAQUE messages, recovery proof, session-token
  cryptography, or this data model requires a new ADR and security review.
