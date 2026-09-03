// Short-lived server-side OPAQUE login state, kept in-process because the
// frozen api-v1 contract carries no login-attempt id to key a durable store
// by (ADR-0006 §6). A known limitation if the backend is ever horizontally
// scaled; see the ADR.
const DEFAULT_TTL_MS = 60_000;

export function createLoginStateStore(ttlMs = DEFAULT_TTL_MS) {
  const pending = new Map();

  function evictExpired(now) {
    for (const [accountId, entry] of pending) {
      if (entry.expiresAt <= now) pending.delete(accountId);
    }
  }

  return {
    /** Records pending state for either a real or a decoy login attempt. */
    setReal(accountId, stateBytes) {
      evictExpired(Date.now());
      pending.set(accountId, { kind: 'real', stateBytes, expiresAt: Date.now() + ttlMs });
    },
    setFake(accountId) {
      evictExpired(Date.now());
      pending.set(accountId, { kind: 'fake', expiresAt: Date.now() + ttlMs });
    },
    hasPending(accountId) {
      evictExpired(Date.now());
      return pending.has(accountId);
    },
    /** One-shot: an entry is consumed the first time it's read. */
    take(accountId) {
      evictExpired(Date.now());
      const entry = pending.get(accountId);
      if (!entry) return null;
      pending.delete(accountId);
      return entry;
    }
  };
}
