# B02 integration note

The `apps/api/` versus `apps/backend/` path mismatch is resolved by main
commit `4d18633`. B02 is now explicitly allowed to change `apps/backend/`, and
its verification commands use Bun with `@zkpm/backend`.

Within B02's permitted `infra/` scope, the image layout now preserves the
relative path expected by the existing migration runner and Compose runs
migrations before the API. Compose also checks `/health/ready`, which verifies
database readiness rather than only process liveness.

The container uses the repository's pinned Bun runtime and frozen `bun.lock`;
it does not create or modify package-manager metadata.

Schema inspection: `db/migrations/001_initial.sql` stores opaque fields only
for vault content (`ciphertext`), key material (`bundle`), and OPAQUE records
(`credential_record`). It defines no columns for vault plaintext, passwords,
TOTP secrets, or raw encryption keys. Behavior-level log tests confirm that
request body, authorization, cookie, ciphertext, and recovery markers are not
present in emitted structured logs.

`devices.name` is intentional server-visible device metadata, but it is a free
text column. It must not be repurposed for vault content; the owner of the
device API should define validation and the metadata-leakage disclosure before
that endpoint is implemented.
