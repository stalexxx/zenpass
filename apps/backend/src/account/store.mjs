// ADR-0011 G1: compare-and-swap publication over the existing
// `key_bundles(account_id PRIMARY KEY, bundle, version, updated_at)` table
// (db/migrations/001_initial.sql) — no new storage, no migration.

export async function getKeyBundle(pool, accountId) {
  const { rows } = await pool.query('SELECT bundle, version FROM key_bundles WHERE account_id = $1', [accountId]);
  return rows[0] ?? null;
}

/**
 * Applies one publish attempt inside a single transaction. `bytes` is the
 * raw decoded (already codec-validated) bundle; the caller must never pass
 * unvalidated input here. Returns exactly one of:
 *
 *   { outcome: 'created' }                     first publish (attemptedVersion === 1)
 *   { outcome: 'idempotent' }                  identical bytes replayed at the current revision
 *   { outcome: 'replaced' }                    attemptedVersion === current + 1, bytes committed
 *   { outcome: 'conflict', currentVersion }     any other case (currentVersion is null if no row exists)
 *
 * On the no-row path, a concurrent first publish can race between this
 * transaction's `SELECT ... FOR UPDATE` (which locks nothing — there is no
 * row yet) and its `INSERT`. That race is detected as a Postgres unique-
 * violation (23505) on the existing `PRIMARY KEY(account_id)`, not
 * prevented by locking; the losing attempt re-reads and retries under the
 * now-existing row's lock instead of assuming failure.
 */
export async function publishKeyBundle(pool, accountId, bytes, attemptedVersion) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        'SELECT bundle, version FROM key_bundles WHERE account_id = $1 FOR UPDATE',
        [accountId]
      );
      const existing = rows[0];

      if (!existing) {
        if (attemptedVersion !== 1) {
          await client.query('ROLLBACK');
          return { outcome: 'conflict', currentVersion: null };
        }
        try {
          await client.query('INSERT INTO key_bundles (account_id, bundle, version) VALUES ($1, $2, $3)', [
            accountId,
            bytes,
            attemptedVersion
          ]);
        } catch (error) {
          if (error && error.code === '23505') {
            await client.query('ROLLBACK');
            continue; // retry: a concurrent first-publish committed first
          }
          throw error;
        }
        await client.query('COMMIT');
        return { outcome: 'created' };
      }

      if (existing.version === attemptedVersion) {
        const same = Buffer.compare(existing.bundle, bytes) === 0;
        await client.query('ROLLBACK');
        return same ? { outcome: 'idempotent' } : { outcome: 'conflict', currentVersion: existing.version };
      }

      if (attemptedVersion !== existing.version + 1) {
        await client.query('ROLLBACK');
        return { outcome: 'conflict', currentVersion: existing.version };
      }

      await client.query(
        'UPDATE key_bundles SET bundle = $1, version = $2, updated_at = now() WHERE account_id = $3',
        [bytes, attemptedVersion, accountId]
      );
      await client.query('COMMIT');
      return { outcome: 'replaced' };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
  throw new Error('publishKeyBundle: exhausted retries on a repeated unique-key race');
}
