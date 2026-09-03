export async function ensureAccount(pool, accountId) {
  await pool.query('INSERT INTO accounts (account_id) VALUES ($1) ON CONFLICT DO NOTHING', [accountId]);
}

export async function getCredentialRecord(pool, accountId) {
  const { rows } = await pool.query(
    'SELECT credential_record FROM opaque_credentials WHERE account_id = $1',
    [accountId]
  );
  return rows[0]?.credential_record ?? null;
}

/**
 * Stores the credential record the first time an account registers.
 * Re-registration is a silent no-op (the existing record is kept) so the
 * response shape never reveals whether an account already had credentials.
 */
export async function saveCredentialRecordIfAbsent(pool, accountId, record) {
  await pool.query(
    `INSERT INTO opaque_credentials (account_id, credential_record)
     VALUES ($1, $2)
     ON CONFLICT (account_id) DO NOTHING`,
    [accountId, record]
  );
}
