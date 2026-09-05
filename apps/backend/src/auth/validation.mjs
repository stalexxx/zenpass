// SEC-07: shared request-shape validation for the OPAQUE auth routes.
// These checks run before any persistent write (`ensureAccount`,
// `auth_rate_limits`), so a malformed or oversized request can never touch
// the database at all -- only a bounded, well-formed request reaches it.
//
// Matches the `accounts.account_id varchar(128)` column
// (db/migrations/001_initial.sql) and the web client's own generated
// identifiers (32 lowercase hex characters,
// apps/web/src/crypto/account-id.ts), while staying permissive enough for
// other bounded, opaque client-chosen identifiers (e.g. this backend's own
// test fixtures, which use an `acct-<uuid>` convention). Never used to
// distinguish a malformed accountId from an unknown-but-well-formed one in
// the response shape -- callers must still route every rejection through
// the same generic response helpers (see routes.mjs / responses.mjs) so
// enumeration resistance (T09) is unaffected.
const ACCOUNT_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

export function isValidAccountId(accountId) {
  return typeof accountId === 'string' && ACCOUNT_ID_PATTERN.test(accountId);
}
