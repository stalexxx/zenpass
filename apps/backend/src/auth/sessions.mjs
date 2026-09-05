import { createHash, randomBytes, randomUUID } from 'node:crypto';

function hashToken(token) {
  return createHash('sha256').update(token).digest();
}

/**
 * Issues a fresh, device-unbound session. The raw token is never stored.
 *
 * `issuedVia` records durable provenance (ADR-0011 G2): `'opaque-login'`
 * (the default) marks a session that just completed the OPAQUE login
 * dance — the only kind eligible for bearer-session-v1 device enrollment.
 * `rotateSession` below passes `'refresh'` for its internal reissue, which
 * is never eligible regardless of any future device-binding change.
 */
export async function issueSession(pool, accountId, ttlSeconds, issuedVia = 'opaque-login') {
  const token = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
  const sessionId = randomUUID();
  await pool.query(
    'INSERT INTO sessions (session_id, account_id, token_hash, expires_at, issued_via) VALUES ($1, $2, $3, $4, $5)',
    [sessionId, accountId, hashToken(token), expiresAt, issuedVia]
  );
  return { sessionId, accountId, accessToken: token, expiresAt: expiresAt.toISOString() };
}

/**
 * Resolves a bearer token to a live session, or null if it doesn't exist,
 * is expired/revoked, or is bound to a revoked device. Never distinguishes
 * these cases to the caller (T09, generic auth errors).
 */
export async function resolveSession(pool, token) {
  const { rows } = await pool.query(
    `SELECT s.session_id, s.account_id, s.device_id, s.expires_at, s.revoked_at, s.issued_via,
            d.revoked_at AS device_revoked_at
     FROM sessions s LEFT JOIN devices d ON d.device_id = s.device_id
     WHERE s.token_hash = $1`,
    [hashToken(token)]
  );
  const session = rows[0];
  if (!session) return null;
  if (session.revoked_at) return null;
  if (session.device_id && session.device_revoked_at) return null;
  if (new Date(session.expires_at).getTime() <= Date.now()) return null;
  return session;
}

export async function bindSessionToDevice(pool, sessionId, deviceId) {
  await pool.query('UPDATE sessions SET device_id = $1 WHERE session_id = $2', [deviceId, sessionId]);
}

/**
 * Rotates a device-bound session: revokes it and issues a replacement bound
 * to the same device. Per ADR-0005, only a non-revoked device-bound session
 * may refresh; callers must check `session.device_id` before calling this.
 */
export async function rotateSession(pool, session, ttlSeconds) {
  await pool.query('UPDATE sessions SET revoked_at = now() WHERE session_id = $1', [session.session_id]);
  const next = await issueSession(pool, session.account_id, ttlSeconds, 'refresh');
  await bindSessionToDevice(pool, next.sessionId, session.device_id);
  return next;
}

export async function revokeSession(pool, sessionId) {
  await pool.query('UPDATE sessions SET revoked_at = now() WHERE session_id = $1', [sessionId]);
}

/**
 * Revokes every session for an account. Exposed for a future recovery-reset
 * implementation (docs/security/RECOVERY.md: "every recovery reset revokes
 * existing sessions and devices"); this task does not itself implement
 * recovery-reset's proof verification (ADR-0006, blocked on the unsigned
 * G-10 recovery-code decision).
 */
export async function revokeAllSessionsForAccount(pool, accountId) {
  await pool.query('UPDATE sessions SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL', [
    accountId
  ]);
}
