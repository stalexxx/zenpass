# B02 integration escalation

The task allows changes in `apps/api/`, `infra/`, and `db/`, but the existing
service, its tests, and its package metadata are in `apps/backend/` with the
package name `@zkpm/backend`. No `apps/api/` package exists.

This prevents completion of the required health and logging-redaction tests
without choosing one of the following architectural changes outside the stated
scope:

1. Rename/move `apps/backend/` to `apps/api/` and update workspace metadata;
   or
2. Amend B02's allowed paths and verification commands to use
   `apps/backend/` / `@zkpm/backend`.

The specified commands are also not valid pnpm package filters as written:
`pnpm test --filter api` passes `--filter` to the root `test` script. The
package-scoped form is `pnpm --filter <package> test`.

The checked-in `pnpm-lock.yaml` does not contain `fastify` or `pg` for
`apps/backend`, so a frozen install fails. Updating that root lockfile is
outside B02's allowed paths. The integrator should regenerate and review the
lockfile with the path decision.

Within B02's permitted `infra/` scope, the image layout now preserves the
relative path expected by the existing migration runner and Compose runs
migrations before the API. Compose also checks `/health/ready`, which verifies
database readiness rather than only process liveness.

The container uses the repository's pinned Bun runtime and frozen `bun.lock`;
it does not create or modify package-manager metadata.

Schema inspection: `db/migrations/001_initial.sql` stores opaque fields only
for vault content (`ciphertext`), key material (`bundle`), and OPAQUE records
(`credential_record`). It defines no columns for vault plaintext, passwords,
TOTP secrets, or raw encryption keys. The existing logger serializes requests
without request bodies and declares redaction for bodies, credentials, and
ciphertext; behavior-level redaction tests remain blocked by the path decision.

`devices.name` is intentional server-visible device metadata, but it is a free
text column. It must not be repurposed for vault content; the owner of the
device API should define validation and the metadata-leakage disclosure before
that endpoint is implemented.
