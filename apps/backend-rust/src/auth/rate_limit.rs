//! Durable, atomic fixed-window login throttling (ADR-0005 §3). Ported
//! unchanged from the Bun reference's `auth/rate-limit.mjs`. No IP address,
//! password, token, or OPAQUE message is stored.

use rand::{Rng, rngs::OsRng};
use sqlx::PgPool;
use time::OffsetDateTime;

/// SEC-07: opportunistic, low-probability sweep run inline with ordinary
/// traffic; a best-effort side effect whose failure must never fail the
/// caller's real rate-limit check.
const CLEANUP_PROBABILITY: f64 = 0.02;

pub async fn check_and_increment(
    pool: &PgPool,
    account_id: &str,
    scope: &str,
    max: u32,
    window: time::Duration,
) -> Result<bool, sqlx::Error> {
    let window_ms: i64 = window.whole_milliseconds().max(1) as i64;
    let now_ms: i64 = (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
    let window_start_ms = (now_ms / window_ms) * window_ms;
    let window_start = OffsetDateTime::from_unix_timestamp(window_start_ms / 1000)
        .expect("valid window start")
        + time::Duration::milliseconds(window_start_ms % 1000);

    let (count,): (i32,) = sqlx::query_as(
        "INSERT INTO auth_rate_limits (account_id, scope, window_start, count) \
         VALUES ($1, $2, $3, 1) \
         ON CONFLICT (account_id, scope, window_start) \
         DO UPDATE SET count = auth_rate_limits.count + 1 \
         RETURNING count",
    )
    .bind(account_id)
    .bind(scope)
    .bind(window_start)
    .fetch_one(pool)
    .await?;

    // `OsRng` rather than `ThreadRng` here: this crate never installs a
    // custom `log` logger, so RUSTSEC-2026-0097's unsoundness scenario
    // (inherited, unfixed, from the frozen `rand` 0.8.5 pin) cannot apply
    // regardless, but avoiding `ThreadRng` entirely keeps this call site
    // unambiguously outside that advisory's precondition set.
    if OsRng.gen_bool(CLEANUP_PROBABILITY) {
        let pool = pool.clone();
        tokio::spawn(async move {
            let _ = super::cleanup::cleanup_stale_auth_state(&pool).await;
        });
    }

    Ok(count as u32 <= max)
}
