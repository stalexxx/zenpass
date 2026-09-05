// SEC-07: a coarse, cheap admission control that runs ahead of the durable
// per-account limiter (rate-limit.mjs) and ahead of any persistent write
// (`ensureAccount`, `auth_rate_limits`). Its only job is to stop
// unauthenticated request *volume* -- independent of accountId, message
// validity, or account existence -- from inflating those tables with one
// row per synthetic accountId. A flood of distinct malformed accountIds
// from one source is bounded here before it ever reaches the database,
// rather than each getting its own durable limiter row.
//
// Purely in-memory, like login-state.mjs's pending-login map: this does
// not survive horizontal scale-out (see ADR-0006 SS6's identical
// limitation for login state, for the same "single backend process"
// reason). A scaled-out deployment would need a shared store instead --
// noted as a follow-up, not a blocker for a single-process deployment.
//
// Keyed only by network origin (IP), never by accountId: it must not add
// a new way to enumerate real accounts by observing how the admission
// check behaves for a given identifier.
const DEFAULT_MAX = 20;
const DEFAULT_WINDOW_MS = 60_000;

export function createAdmissionLimiter({ max = DEFAULT_MAX, windowMs = DEFAULT_WINDOW_MS } = {}) {
  const buckets = new Map();

  function evictExpired(now) {
    for (const [key, bucket] of buckets) {
      if (bucket.windowEnd <= now) buckets.delete(key);
    }
  }

  return {
    /**
     * Returns true iff `key`'s coarse admission bucket is still within
     * bound for this window; always records the attempt (even a rejected
     * one still consumes its bucket slot), so persistent retrying cannot
     * reset the window early.
     */
    allow(key) {
      const now = Date.now();
      evictExpired(now);
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = { count: 0, windowEnd: now + windowMs };
        buckets.set(key, bucket);
      }
      bucket.count += 1;
      return bucket.count <= max;
    }
  };
}

/**
 * Best-effort, coarse key for the admission limiter: the request's network
 * origin. Never the accountId (see module doc). Falls back to a single
 * shared bucket if the runtime cannot supply one, which still bounds total
 * unauthenticated volume (conservatively, across every caller) rather than
 * admitting it unconditionally.
 */
export function admissionKey(request) {
  return request?.ip || 'unknown';
}
