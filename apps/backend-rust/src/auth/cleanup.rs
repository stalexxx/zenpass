//! SEC-07: bounds the lifetime of `auth_rate_limits` windows and of
//! never-completed registration/login accounts. Ported unchanged from the
//! Bun reference's `auth/cleanup.mjs`: an opportunistic sweep run inline
//! with ordinary traffic, never a scheduled job.

use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

const DEFAULT_RATE_LIMIT_RETENTION: Duration = Duration::hours(24);
const DEFAULT_STALE_ACCOUNT_RETENTION: Duration = Duration::hours(24);

pub async fn cleanup_stale_auth_state(pool: &PgPool) -> Result<(), sqlx::Error> {
    cleanup_stale_auth_state_with_retention(
        pool,
        DEFAULT_RATE_LIMIT_RETENTION,
        DEFAULT_STALE_ACCOUNT_RETENTION,
    )
    .await
}

pub async fn cleanup_stale_auth_state_with_retention(
    pool: &PgPool,
    rate_limit_retention: Duration,
    stale_account_retention: Duration,
) -> Result<(), sqlx::Error> {
    let now = OffsetDateTime::now_utc();
    sqlx::query("DELETE FROM auth_rate_limits WHERE window_start < $1")
        .bind(now - rate_limit_retention)
        .execute(pool)
        .await?;
    sqlx::query(
        "DELETE FROM accounts a \
         WHERE a.created_at < $1 \
           AND NOT EXISTS (SELECT 1 FROM opaque_credentials c WHERE c.account_id = a.account_id) \
           AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.account_id = a.account_id) \
           AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.account_id = a.account_id) \
           AND NOT EXISTS (SELECT 1 FROM key_bundles k WHERE k.account_id = a.account_id) \
           AND NOT EXISTS (SELECT 1 FROM vaults v WHERE v.account_id = a.account_id) \
           AND NOT EXISTS (SELECT 1 FROM mutation_outcomes m WHERE m.account_id = a.account_id) \
           AND NOT EXISTS (SELECT 1 FROM auth_rate_limits r WHERE r.account_id = a.account_id)",
    )
    .bind(now - stale_account_retention)
    .execute(pool)
    .await?;
    Ok(())
}
