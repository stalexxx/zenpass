// Durable, atomic fixed-window login throttling (ADR-0005 §3). No IP
// address, password, token, or OPAQUE message is stored.
export async function checkAndIncrement(pool, accountId, scope, { max, windowSeconds }) {
  const windowMs = windowSeconds * 1000;
  const windowStart = new Date(Math.floor(Date.now() / windowMs) * windowMs);
  const { rows } = await pool.query(
    `INSERT INTO auth_rate_limits (account_id, scope, window_start, count)
     VALUES ($1, $2, $3, 1)
     ON CONFLICT (account_id, scope, window_start)
     DO UPDATE SET count = auth_rate_limits.count + 1
     RETURNING count`,
    [accountId, scope, windowStart]
  );
  return rows[0].count <= max;
}
