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
    `INSERT INTO devices (device_id, account_id, name, public_key)
     VALUES ($1, $2, $3, $4)
     RETURNING device_id, name, created_at, last_seen_at, revoked_at`,
    [deviceId, accountId, name, publicKey]
  );
  return rows[0];
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
