import { encodeB64 } from '../auth/codec.mjs';

/** Maps a `vault_items` row to the `ItemRecord` wire shape (sync-v1). The
 * `ciphertext` bytea is carried through as an opaque `b64:` blob; nothing
 * here inspects, decrypts, or merges it. */
export function toItemRecord(row) {
  return {
    itemId: row.item_id,
    vaultId: row.vault_id,
    ciphertext: encodeB64(row.ciphertext),
    envelopeVersion: row.envelope_version,
    revision: Number(row.revision),
    deleted: row.deleted,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString()
  };
}

/**
 * Runs `fn(client)` inside a single dedicated connection wrapped in a
 * transaction. Unlike issuing `pool.query('BEGIN')` / `pool.query('COMMIT')`
 * directly (each `pool.query` call may be served by a different pooled
 * connection, since node-pg checks a client in and back out per call), this
 * checks out one client for the whole transaction so BEGIN/COMMIT/ROLLBACK
 * are guaranteed to apply to the same backend session.
 */
export async function withTransaction(pool, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Serializes concurrent mutation attempts sharing the same (account,
 * mutationId) so a true double-submit race can't both observe "no recorded
 * outcome yet" and both proceed to write. The lock is released
 * automatically at transaction end (`pg_advisory_xact_lock`); a losing
 * transaction blocks here until the winner commits, then its own
 * `findMutationOutcome` call sees the winner's committed row and takes the
 * replay short-circuit instead of writing again.
 */
export async function acquireMutationLock(client, accountId, mutationId) {
  await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`${accountId}:${mutationId}`]);
}

/**
 * Ensures `vaultId` is owned by `accountId`, auto-creating the vault
 * (owned by the caller) on first write — sync-v1 has no separate "create
 * vault" endpoint, so implicit-create-on-first-write is the only way a
 * client can ever populate one. Returns true iff the caller owns the
 * vault (pre-existing or freshly created this call).
 */
export async function ensureVaultOwnership(client, accountId, vaultId) {
  await client.query(
    'INSERT INTO vaults (vault_id, account_id) VALUES ($1, $2) ON CONFLICT (vault_id) DO NOTHING',
    [vaultId, accountId]
  );
  const { rows } = await client.query('SELECT account_id FROM vaults WHERE vault_id = $1', [vaultId]);
  return rows[0]?.account_id === accountId;
}

/** Read-only ownership check (no auto-create) for the change feed: reading
 * a vault that doesn't exist yet must never create it. */
export async function vaultOwnedBy(pool, accountId, vaultId) {
  const { rows } = await pool.query('SELECT account_id FROM vaults WHERE vault_id = $1', [vaultId]);
  return rows[0]?.account_id === accountId;
}

export async function findMutationOutcome(queryable, accountId, mutationId) {
  const { rows } = await queryable.query(
    'SELECT status_code, response_body FROM mutation_outcomes WHERE account_id = $1 AND mutation_id = $2',
    [accountId, mutationId]
  );
  return rows[0] ? { statusCode: rows[0].status_code, body: rows[0].response_body } : null;
}

export async function recordMutationOutcome(client, accountId, mutationId, vaultId, statusCode, body) {
  await client.query(
    'INSERT INTO mutation_outcomes (account_id, mutation_id, vault_id, status_code, response_body) VALUES ($1,$2,$3,$4,$5)',
    [accountId, mutationId, vaultId, statusCode, JSON.stringify(body)]
  );
}

/** Locks the item row (if any) for the duration of the caller's
 * transaction, so a concurrent mutation to the same item can't read a
 * stale revision and both "win" a baseRevision check. */
export async function getItemForUpdate(client, vaultId, itemId) {
  const { rows } = await client.query(
    'SELECT * FROM vault_items WHERE vault_id = $1 AND item_id = $2 FOR UPDATE',
    [vaultId, itemId]
  );
  return rows[0] ?? null;
}

export async function upsertItem(client, { vaultId, itemId, ciphertext, envelopeVersion, revision, deleted }) {
  const { rows } = await client.query(
    `INSERT INTO vault_items (vault_id, item_id, ciphertext, envelope_version, revision, deleted, sequence)
     VALUES ($1, $2, $3, $4, $5, $6, nextval('vault_change_sequence'))
     ON CONFLICT (vault_id, item_id) DO UPDATE SET
       ciphertext = EXCLUDED.ciphertext,
       envelope_version = EXCLUDED.envelope_version,
       revision = EXCLUDED.revision,
       deleted = EXCLUDED.deleted,
       updated_at = now(),
       sequence = nextval('vault_change_sequence')
     RETURNING *`,
    [vaultId, itemId, ciphertext, envelopeVersion, revision, deleted]
  );
  return rows[0];
}

/** Change feed page: tombstones (deleted = true) are never filtered out
 * here, so they stay visible for retention (sync-state-machine.md:
 * "Tombstones remain in the feed for the retention period and are never
 * silently converted to missing records"). No expiry/purge is implemented
 * — see the completion report's Known limitations. */
export async function listChanges(pool, vaultId, afterSequence, limit) {
  const { rows } = await pool.query(
    'SELECT * FROM vault_items WHERE vault_id = $1 AND sequence > $2::bigint ORDER BY sequence ASC LIMIT $3',
    [vaultId, afterSequence, limit]
  );
  return rows;
}
