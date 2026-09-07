//! Session issue/resolve/rotate/revoke. Ported from the Bun reference's
//! `auth/sessions.mjs`, including SEC-06's single-statement atomic rotation.
//!
//! Session tokens and their at-rest hash are bearer-session bookkeeping,
//! explicitly outside the `crypto-envelope-v1` boundary crypto-core owns
//! (see the RUST-03 report): the raw token is 32 fresh OS-CSPRNG bytes from
//! the already ADR-0003-approved, exact-pinned `rand` crate, and its at-rest
//! hash is `sha2::Sha256` at the exact ADR-0003-approved pin. Neither
//! primitive is implemented here.

use base64::Engine;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::{Executor, PgPool, Postgres, Row};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const OPAQUE_LOGIN: &str = "opaque-login";
pub const REFRESH: &str = "refresh";

fn hash_token(token: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}

fn generate_token() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*bytes))
}

#[derive(Debug, Clone)]
pub struct IssuedSession {
    #[allow(dead_code)] // exposed for future callers (e.g. audit logging); not read today
    pub session_id: Uuid,
    #[allow(dead_code)]
    pub account_id: String,
    pub access_token: Zeroizing<String>,
    pub expires_at: OffsetDateTime,
}

impl IssuedSession {
    pub fn expires_at_rfc3339(&self) -> String {
        self.expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .expect("valid RFC 3339 timestamp")
    }
}

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub session_id: Uuid,
    pub account_id: String,
    pub device_id: Option<String>,
    pub issued_via: String,
}

/// Issues a fresh, device-unbound session. The raw token is never stored.
pub async fn issue_session(
    pool: &PgPool,
    account_id: &str,
    ttl: time::Duration,
    issued_via: &str,
) -> Result<IssuedSession, sqlx::Error> {
    let token = generate_token();
    let expires_at = OffsetDateTime::now_utc() + ttl;
    let session_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sessions (session_id, account_id, token_hash, expires_at, issued_via) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(session_id)
    .bind(account_id)
    .bind(hash_token(&token))
    .bind(expires_at)
    .bind(issued_via)
    .execute(pool)
    .await?;
    Ok(IssuedSession {
        session_id,
        account_id: account_id.to_owned(),
        access_token: token,
        expires_at,
    })
}

/// Resolves a bearer token to a live session, or `None` if it doesn't
/// exist, is expired/revoked, or is bound to a revoked device. Never
/// distinguishes these cases to the caller (T09, generic auth errors).
pub async fn resolve_session(
    pool: &PgPool,
    token: &str,
) -> Result<Option<AuthSession>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT s.session_id, s.account_id, s.device_id, s.expires_at, s.revoked_at, \
                s.issued_via, d.revoked_at AS device_revoked_at \
         FROM sessions s LEFT JOIN devices d ON d.device_id = s.device_id \
         WHERE s.token_hash = $1",
    )
    .bind(hash_token(token))
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let revoked_at: Option<OffsetDateTime> = row.try_get("revoked_at")?;
    if revoked_at.is_some() {
        return Ok(None);
    }
    let device_id: Option<String> = row.try_get("device_id")?;
    let device_revoked_at: Option<OffsetDateTime> = row.try_get("device_revoked_at")?;
    if device_id.is_some() && device_revoked_at.is_some() {
        return Ok(None);
    }
    let expires_at: OffsetDateTime = row.try_get("expires_at")?;
    if expires_at <= OffsetDateTime::now_utc() {
        return Ok(None);
    }
    Ok(Some(AuthSession {
        session_id: row.try_get("session_id")?,
        account_id: row.try_get("account_id")?,
        device_id,
        issued_via: row.try_get("issued_via")?,
    }))
}

pub async fn bind_session_to_device<'e, E>(
    executor: E,
    session_id: Uuid,
    device_id: &str,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("UPDATE sessions SET device_id = $1 WHERE session_id = $2")
        .bind(device_id)
        .bind(session_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Rotates a device-bound session: revokes it and issues a replacement
/// bound to the same device, atomically (SEC-06). Only a non-revoked
/// device-bound session may refresh (ADR-0005 §2); callers must check
/// `session.device_id` before calling this. Returns `None` if the session
/// lost the race (already rotated/revoked/expired, or its device was
/// revoked concurrently) -- never a second successor for the same original
/// session.
pub async fn rotate_session(
    pool: &PgPool,
    session: &AuthSession,
    ttl: time::Duration,
) -> Result<Option<IssuedSession>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let revoked = sqlx::query(
        "UPDATE sessions s SET revoked_at = now() \
         FROM devices d \
         WHERE s.session_id = $1 \
           AND s.revoked_at IS NULL \
           AND s.expires_at > now() \
           AND s.device_id IS NOT NULL \
           AND s.device_id = d.device_id \
           AND d.revoked_at IS NULL \
         RETURNING s.session_id, s.account_id, s.device_id",
    )
    .bind(session.session_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(revoked) = revoked else {
        tx.rollback().await?;
        return Ok(None);
    };
    let account_id: String = revoked.try_get("account_id")?;
    let device_id: String = revoked.try_get("device_id")?;

    let token = generate_token();
    let expires_at = OffsetDateTime::now_utc() + ttl;
    let session_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sessions (session_id, account_id, token_hash, expires_at, issued_via, device_id) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(session_id)
    .bind(&account_id)
    .bind(hash_token(&token))
    .bind(expires_at)
    .bind(REFRESH)
    .bind(&device_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(IssuedSession {
        session_id,
        account_id,
        access_token: token,
        expires_at,
    }))
}

pub async fn revoke_session(pool: &PgPool, session_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE session_id = $1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Revokes every session for an account. Exposed for a future
/// recovery-reset implementation (out of RUST-03's scope; not itself wired
/// to any route).
#[allow(dead_code)]
pub async fn revoke_all_sessions_for_account(
    pool: &PgPool,
    account_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL",
    )
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(())
}
