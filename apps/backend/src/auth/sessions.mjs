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
 *
 * SEC-06 (GitHub issue #6): the revoke-then-insert used to be two separate
 * statements with no affected-row check, so two concurrent refresh calls for
 * the same bearer session could both pass `requireSession`'s earlier
 * liveness check and each mint a distinct successor before either `UPDATE`
 * landed. This now runs as a single atomic `UPDATE ... WHERE revoked_at IS
 * NULL AND expires_at > now() ... RETURNING` on one connection (one
 * transaction, one pooled client), joined against `devices` to re-check
 * device-binding/revocation state at the same instant rather than relying
 * only on the caller's earlier read. Postgres holds the row lock for the
 * statement's duration, so a second concurrent call for the same session
 * blocks until the first commits or rolls back, then re-evaluates the
 * `WHERE` against the now-revoked row and affects zero rows — exactly one
 * caller ever gets a successor. Every other caller gets `null` back; route
 * handlers must turn that into a generic unauthorized response, never a
 * second token. If the successor `INSERT` throws, the whole transaction
 * rolls back, so no session is left revoked without a live successor.
 */
export async function rotateSession(pool, session, ttlSeconds) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `UPDATE sessions s
       SET revoked_at = now()
       FROM devices d
       WHERE s.session_id = $1
         AND s.revoked_at IS NULL
         AND s.expires_at > now()
         AND s.device_id IS NOT NULL
         AND s.device_id = d.device_id
         AND d.revoked_at IS NULL
       RETURNING s.session_id, s.account_id, s.device_id`,
      [session.session_id]
    );
    const revoked = rows[0];
    if (!revoked) {
      await client.query('ROLLBACK');
      return null;
    }

    const token = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
    const sessionId = randomUUID();
    await client.query(
      'INSERT INTO sessions (session_id, account_id, token_hash, expires_at, issued_via, device_id) VALUES ($1, $2, $3, $4, $5, $6)',
      [sessionId, revoked.account_id, hashToken(token), expiresAt, 'refresh', revoked.device_id]
    );
    await client.query('COMMIT');
    return { sessionId, accountId: revoked.account_id, accessToken: token, expiresAt: expiresAt.toISOString() };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
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
