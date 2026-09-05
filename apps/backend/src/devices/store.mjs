import { randomUUID } from 'node:crypto';

export async function listDevices(pool, accountId) {
  const { rows } = await pool.query(
    'SELECT device_id, name, created_at, last_seen_at, revoked_at FROM devices WHERE account_id = $1 ORDER BY created_at',
    [accountId]
  );
  return rows;
}

export async function createDevice(pool, accountId, { name, publicKey }) {
  const deviceId = randomUUID();
  const { rows } = await pool.query(
    `INSERT INTO devices (device_id, account_id, name, public_key, enrollment_mode)
     VALUES ($1, $2, $3, $4, 'legacy-public-key')
     RETURNING device_id, name, created_at, last_seen_at, revoked_at`,
    [deviceId, accountId, name, publicKey]
  );
  return rows[0];
}

/**
 * ADR-0011 G2: enrolls a device with no proof-of-possession, using only
 * the caller's bearer session as authorization ("bearer-authenticated,
 * revocable enrollment without proof-of-possession", explicitly disclosed
 * as such — not disguised as a public-key device). Locks the session row
 * for the duration of the transaction so a concurrent second enrollment
 * attempt on the same session blocks, then sees the now-bound `device_id`
 * and fails instead of racing to rebind it.
 *
 * Returns `{ device }` on success, or `{ error: 'session_invalid' |
 * 'already_bound' | 'not_freshly_issued' }` — all three are surfaced to
 * the client as a generic 400, never distinguished (T09: no
 * session-existence/binding-state oracle).
 */
export async function enrollBearerSessionDevice(pool, sessionId, name) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: sessionRows } = await client.query(
      'SELECT session_id, account_id, device_id, expires_at, revoked_at, issued_via FROM sessions WHERE session_id = $1 FOR UPDATE',
      [sessionId]
    );
    const session = sessionRows[0];
    if (!session || session.revoked_at || new Date(session.expires_at).getTime() <= Date.now()) {
      await client.query('ROLLBACK');
      return { error: 'session_invalid' };
    }
    if (session.device_id) {
      await client.query('ROLLBACK');
      return { error: 'already_bound' };
    }
    // ADR-0011 G2: "a valid, device-unbound, freshly OPAQUE-issued
    // session" — checked against the durable `issued_via` provenance
    // recorded at issuance (see db/migrations/005), not inferred from
    // device_id alone.
    if (session.issued_via !== 'opaque-login') {
      await client.query('ROLLBACK');
      return { error: 'not_freshly_issued' };
    }
    const deviceId = randomUUID();
    const { rows } = await client.query(
      `INSERT INTO devices (device_id, account_id, name, public_key, enrollment_mode)
       VALUES ($1, $2, $3, NULL, 'bearer-session-v1')
       RETURNING device_id, name, created_at, last_seen_at, revoked_at`,
      [deviceId, session.account_id, name]
    );
    await client.query('UPDATE sessions SET device_id = $1 WHERE session_id = $2', [deviceId, sessionId]);
    await client.query('COMMIT');
    return { device: rows[0] };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Revokes a device and, in the same transaction, every session bound to it
 * (ADR-0005 §2). Returns false if the device doesn't exist or isn't owned
 * by `accountId` (a generic not-found, not an authorization-detail leak).
 */
export async function revokeDevice(pool, accountId, deviceId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `UPDATE devices SET revoked_at = now()
       WHERE device_id = $1 AND account_id = $2 AND revoked_at IS NULL
       RETURNING device_id`,
      [deviceId, accountId]
    );
    if (rows.length === 0) {
      await client.query('ROLLBACK');
      return false;
    }
    await client.query(
      'UPDATE sessions SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL',
      [deviceId]
    );
    await client.query('COMMIT');
    return true;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
