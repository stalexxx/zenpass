# SEC-07: unauthenticated login creates unbounded account and rate-limit rows

Source: GitHub issue #7 (audit 2026-09-05, commit `95846a9`). Severity: Medium.
Threats: T17.

Goal: the login route (`apps/backend/src/auth/routes.mjs`) calls
`ensureAccount` (which `INSERT`s into `accounts`) and `checkAndIncrement`
(which inserts an `auth_rate_limits` row) before validating the request body's
`clientMessage` length/shape. The rate limiter keys only on `accountId`, which
is entirely client-supplied, so each new synthetic `accountId` gets its own
fresh limit. An unauthenticated remote client can send arbitrarily many
malformed logins with distinct `accountId`s and create unbounded persistent
rows with no OPAQUE exchange, password, or successful registration required.
Registration has an analogous path.

Dependencies: none. Owner: B04/B02 via integrator.

Allowed paths: `apps/backend/src/auth/`, `apps/backend/test/auth/`,
`docs/tasks/SEC-07.md`. If a migration is genuinely required (e.g. a TTL/
cleanup column), propose it in the completion report as a blocker rather than
writing it yourself, unless it is a straightforward additive, backward-
compatible migration consistent with existing forward-only migration style —
in that case you may add it under `db/migrations/`.

Forbidden paths: `crates/crypto-core/`, `docs/contracts/` (no OPAQUE/protocol
change), `packages/sdk/`, web/extension.

Required fix:

- Validate the request's `accountId` type/length/grammar and the OPAQUE
  protocol message's expected length/shape *before* any persistent write
  (`ensureAccount`, rate-limit row creation), for both login and registration.
- Do not create a persistent `accounts` row on an unrecognized/malformed
  login attempt — only on a real, well-formed protocol attempt (this must
  not weaken existing account-enumeration resistance: the error shape for a
  malformed request, an unknown-but-well-formed account, and a known account
  must remain indistinguishable to the caller).
- Add a bounded, cheap admission check (e.g. a coarse IP-scoped or global
  request-shape rate limit) ahead of any per-account limiter/persistent
  write, so volume alone can't be used to inflate the accounts/rate-limit
  tables — without introducing a new way to enumerate real accounts.
- Bound the lifetime/count of rate-limit and incomplete-registration rows
  (a cleanup mechanism), consistent with existing migration/cleanup patterns
  if any exist in this codebase.

Required tests (PostgreSQL-backed, real `TEST_DATABASE_URL`): a malformed
login does not create an `accounts` row; a flood of distinct malformed
`accountId`s is bounded rather than each getting its own limiter row; cleanup
behavior; known-account and unknown-account error responses remain
identically shaped.

Verification: `TEST_DATABASE_URL=postgres://pass:pass@127.0.0.1:5434/pass bun
test apps/backend/test/auth`, `bun run check:boundaries`. If you add a
migration, also run the repeatable-migration test.

Completion report format: Standard completion report (`docs/plan/INTEGRATOR.md`).
Reference GitHub issue #7; do not close it yourself.
