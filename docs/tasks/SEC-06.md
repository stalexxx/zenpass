# SEC-06: concurrent refresh reuses one bearer session to issue multiple successors

Source: GitHub issue #6 (audit 2026-09-05, commit `95846a9`). Severity: Medium.
Threats: T09, ADR-0005.

Goal: `rotateSession` (`apps/backend/src/auth/sessions.mjs`) does an
unconditional `UPDATE ... revoked_at`, then a separate `INSERT` for the
successor, without `revoked_at IS NULL`/`RETURNING` or checking the update's
affected-row count. Two concurrent refresh calls against the same session can
both pass `requireSession`'s earlier liveness check and each mint a distinct
successor token before either `UPDATE` lands.

Dependencies: none. Owner: B04 via integrator.

Allowed paths: `apps/backend/src/auth/`, `apps/backend/test/auth/`,
`docs/tasks/SEC-06.md`.

Forbidden paths: `crates/crypto-core/`, `docs/contracts/`, migrations schema
changes beyond what's strictly needed for the fix (if you determine a
migration is required, stop and report it as a blocker for integrator review
rather than writing one yourself — this task should be achievable via
transaction/locking changes to existing tables), `packages/sdk/`, web/extension.

Required fix:

- Make `rotateSession` atomically consume only the still-live original session
  and create its device-bound successor in one transaction on a single
  connection (e.g. `UPDATE ... SET revoked_at = now() WHERE id = $1 AND
  revoked_at IS NULL AND expires_at > now() RETURNING *`, then only insert the
  successor if that update actually affected a row).
- Re-check expiry/revocation/device-binding state inside the transaction
  under a row lock (`SELECT ... FOR UPDATE` or equivalent), not only in the
  earlier `requireSession` check.
- Exactly one concurrent refresh call must win; every other concurrent caller
  gets a generic unauthorized response, not a second successor token.
- Roll back the successor `INSERT` if anything in the transaction fails.
- Never log or fixture real token values.

Required tests: a PostgreSQL-backed (real `TEST_DATABASE_URL`) HTTP/route-level
race test using a barrier so two refresh requests for the same session start
concurrently after initial authentication, asserting exactly one 200 with a
successor and the other unauthorized, and exactly one new `sessions` row
descends from the original. Also: refresh racing logout/revoke, and rollback
behavior when the successor `INSERT` fails.

Verification: `TEST_DATABASE_URL=postgres://pass:pass@127.0.0.1:5434/pass bun
test apps/backend/test/auth`, `bun run check:boundaries`.

Completion report format: Standard completion report (`docs/plan/INTEGRATOR.md`).
Reference GitHub issue #6; do not close it yourself.
