// SEC-07: bounds the lifetime/count of `auth_rate_limits` windows and of
// accounts created (`ensureAccount`) for a registration or login attempt
// that never completed ("incomplete-registration rows"). This codebase has
// no scheduled/cron job anywhere (sessions.mjs's `resolveSession`, for
// example, checks expiry lazily at read time rather than deleting expired
// rows on a timer) -- consistent with that, this is an opportunistic sweep
// invoked inline with ordinary traffic (see rate-limit.mjs), not a new
// background job.
const DEFAULT_RATE_LIMIT_RETENTION_MS = 24 * 60 * 60 * 1000; // 1 day of fixed windows
const DEFAULT_STALE_ACCOUNT_RETENTION_MS = 24 * 60 * 60 * 1000; // 1 day

/**
 * Deletes expired `auth_rate_limits` windows, then deletes any account
 * that is older than `staleAccountRetentionMs`, was never issued
 * credentials (registration never completed its second leg), and is not
 * referenced by any other table -- i.e. it never did anything besides
 * exist. The `NOT EXISTS` guards make this safe to run concurrently with
 * ordinary traffic: a real account always fails at least one of them.
 */
export async function cleanupStaleAuthState(
  pool,
  {
    rateLimitRetentionMs = DEFAULT_RATE_LIMIT_RETENTION_MS,
    staleAccountRetentionMs = DEFAULT_STALE_ACCOUNT_RETENTION_MS
  } = {}
) {
  const now = Date.now();
  await pool.query('DELETE FROM auth_rate_limits WHERE window_start < $1', [
    new Date(now - rateLimitRetentionMs)
  ]);
  await pool.query(
    `DELETE FROM accounts a
     WHERE a.created_at < $1
       AND NOT EXISTS (SELECT 1 FROM opaque_credentials c WHERE c.account_id = a.account_id)
       AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.account_id = a.account_id)
       AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.account_id = a.account_id)
       AND NOT EXISTS (SELECT 1 FROM key_bundles k WHERE k.account_id = a.account_id)
       AND NOT EXISTS (SELECT 1 FROM vaults v WHERE v.account_id = a.account_id)
       AND NOT EXISTS (SELECT 1 FROM mutation_outcomes m WHERE m.account_id = a.account_id)
       AND NOT EXISTS (SELECT 1 FROM auth_rate_limits r WHERE r.account_id = a.account_id)`,
    [new Date(now - staleAccountRetentionMs)]
  );
}
