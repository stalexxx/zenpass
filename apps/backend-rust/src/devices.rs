//! `/devices` — enroll, list, revoke. Parity port of the Bun reference's
//! `apps/backend/src/devices/{routes,store}.mjs`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::Value;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AppState;
use crate::auth::{Authenticated, decode_b64};
use crate::dto::Device;

const NAME_MAX_LENGTH: usize = 128;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/devices", get(list).post(create))
        .route("/devices/{deviceId}/revoke", post(revoke))
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && name.chars().count() <= NAME_MAX_LENGTH
}

/// `DeviceCreate` is a disjoint union of the legacy (`name`, `publicKey`)
/// branch and the new (`name`, `enrollmentMode:"bearer-session-v1"`) branch
/// -- never both, never neither, and no unknown fields in either
/// (ADR-0011 G2). We deserialize the raw JSON `Value` ourselves (rather
/// than relying on serde's untagged enum) so an invalid shape maps to the
/// exact same generic 400 as every other rejection, with no serde error
/// text ever reaching the client.
enum Classified {
    Legacy { name: String, public_key: String },
    Bearer { name: String },
}

fn classify(body: &Value) -> Option<Classified> {
    let obj = body.as_object()?;
    let has_public_key = obj.contains_key("publicKey");
    let has_mode = obj.contains_key("enrollmentMode");
    if has_public_key == has_mode {
        return None; // both or neither: reject
    }
    if has_mode {
        let allowed: std::collections::HashSet<&str> =
            std::collections::HashSet::from(["name", "enrollmentMode"]);
        if !obj.keys().all(|k: &String| allowed.contains(k.as_str())) {
            return None;
        }
        if obj.get("enrollmentMode")?.as_str()? != "bearer-session-v1" {
            return None;
        }
        let name = obj.get("name")?.as_str()?.to_owned();
        Some(Classified::Bearer { name })
    } else {
        let allowed: std::collections::HashSet<&str> =
            std::collections::HashSet::from(["name", "publicKey"]);
        if !obj.keys().all(|k: &String| allowed.contains(k.as_str())) {
            return None;
        }
        let name = obj.get("name")?.as_str()?.to_owned();
        let public_key = obj.get("publicKey")?.as_str()?.to_owned();
        Some(Classified::Legacy { name, public_key })
    }
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    device_id: String,
    name: String,
    created_at: OffsetDateTime,
    last_seen_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
}

fn to_api_device(row: DeviceRow) -> Device {
    Device {
        device_id: row.device_id,
        name: row.name,
        created_at: rfc3339(row.created_at),
        last_seen_at: row.last_seen_at.map(rfc3339),
        revoked_at: row.revoked_at.map(rfc3339),
    }
}

fn rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .expect("valid RFC 3339 timestamp")
}

async fn list(State(state): State<AppState>, Authenticated(session): Authenticated) -> Response {
    let rows: Result<Vec<DeviceRow>, _> = sqlx::query_as(
        "SELECT device_id, name, created_at, last_seen_at, revoked_at FROM devices \
         WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(&session.account_id)
    .fetch_all(state.pool())
    .await;
    match rows {
        Ok(rows) => (
            StatusCode::OK,
            Json(crate::dto::DeviceList {
                devices: rows.into_iter().map(to_api_device).collect(),
            }),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "list_devices_failed");
            crate::error::AppError::DatabaseUnavailable.into_response()
        }
    }
}

async fn create(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Json(body): Json<Value>,
) -> Response {
    let Some(classified) = classify(&body) else {
        return crate::auth::responses_bad_request();
    };
    match classified {
        Classified::Legacy { name, public_key } if is_valid_name(&name) => {
            let Some(key) = decode_b64(&public_key) else {
                return crate::auth::responses_bad_request();
            };
            match create_legacy_device(state.pool(), &session.account_id, &name, &key).await {
                Ok(row) => {
                    if let Err(err) = crate::auth::bind_session_to_device(
                        state.pool(),
                        session.session_id,
                        &row.device_id,
                    )
                    .await
                    {
                        tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "bind_session_failed");
                        return crate::error::AppError::DatabaseUnavailable.into_response();
                    }
                    (StatusCode::CREATED, Json(to_api_device(row))).into_response()
                }
                Err(err) => {
                    tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "create_device_failed");
                    crate::error::AppError::DatabaseUnavailable.into_response()
                }
            }
        }
        Classified::Bearer { name } if is_valid_name(&name) => {
            match enroll_bearer_session_device(state.pool(), session.session_id, &name).await {
                Ok(Some(row)) => (StatusCode::CREATED, Json(to_api_device(row))).into_response(),
                Ok(None) => crate::auth::responses_bad_request(),
                Err(err) => {
                    tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "enroll_bearer_device_failed");
                    crate::error::AppError::DatabaseUnavailable.into_response()
                }
            }
        }
        _ => crate::auth::responses_bad_request(),
    }
}

#[derive(Deserialize)]
struct RevokePath {
    #[serde(rename = "deviceId")]
    device_id: String,
}

async fn revoke(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Path(RevokePath { device_id }): Path<RevokePath>,
) -> Response {
    match revoke_device(state.pool(), &session.account_id, &device_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => crate::auth::responses_not_found(),
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "revoke_device_failed");
            crate::error::AppError::DatabaseUnavailable.into_response()
        }
    }
}

async fn create_legacy_device(
    pool: &PgPool,
    account_id: &str,
    name: &str,
    public_key: &[u8],
) -> Result<DeviceRow, sqlx::Error> {
    let device_id = Uuid::new_v4().to_string();
    sqlx::query_as(
        "INSERT INTO devices (device_id, account_id, name, public_key, enrollment_mode) \
         VALUES ($1, $2, $3, $4, 'legacy-public-key') \
         RETURNING device_id, name, created_at, last_seen_at, revoked_at",
    )
    .bind(&device_id)
    .bind(account_id)
    .bind(name)
    .bind(public_key)
    .fetch_one(pool)
    .await
}

/// ADR-0011 G2: enrolls a device with no proof-of-possession, using only
/// the caller's bearer session as authorization. Locks the session row for
/// the transaction so a concurrent second enrollment attempt on the same
/// session blocks, then sees the now-bound `device_id` and fails instead of
/// racing to rebind it. Returns `Ok(None)` for any of `session_invalid`,
/// `already_bound`, or `not_freshly_issued` -- all three surfaced to the
/// client as a generic 400 (T09: no session-existence/binding-state
/// oracle).
async fn enroll_bearer_session_device(
    pool: &PgPool,
    session_id: Uuid,
    name: &str,
) -> Result<Option<DeviceRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let session = sqlx::query(
        "SELECT session_id, account_id, device_id, expires_at, revoked_at, issued_via \
         FROM sessions WHERE session_id = $1 FOR UPDATE",
    )
    .bind(session_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(session) = session else {
        tx.rollback().await?;
        return Ok(None);
    };
    let revoked_at: Option<OffsetDateTime> = session.try_get("revoked_at")?;
    let expires_at: OffsetDateTime = session.try_get("expires_at")?;
    if revoked_at.is_some() || expires_at <= OffsetDateTime::now_utc() {
        tx.rollback().await?;
        return Ok(None);
    }
    let device_id: Option<String> = session.try_get("device_id")?;
    if device_id.is_some() {
        tx.rollback().await?;
        return Ok(None);
    }
    let issued_via: String = session.try_get("issued_via")?;
    if issued_via != crate::auth::OPAQUE_LOGIN {
        tx.rollback().await?;
        return Ok(None);
    }
    let account_id: String = session.try_get("account_id")?;
    let new_device_id = Uuid::new_v4().to_string();
    let row: DeviceRow = sqlx::query_as(
        "INSERT INTO devices (device_id, account_id, name, public_key, enrollment_mode) \
         VALUES ($1, $2, $3, NULL, 'bearer-session-v1') \
         RETURNING device_id, name, created_at, last_seen_at, revoked_at",
    )
    .bind(&new_device_id)
    .bind(&account_id)
    .bind(name)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE sessions SET device_id = $1 WHERE session_id = $2")
        .bind(&new_device_id)
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(row))
}

/// Revokes a device and, in the same transaction, every session bound to
/// it (ADR-0005 §2). Returns `false` if the device doesn't exist or isn't
/// owned by `account_id` (a generic not-found, not an
/// authorization-detail leak).
async fn revoke_device(
    pool: &PgPool,
    account_id: &str,
    device_id: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "UPDATE devices SET revoked_at = now() \
         WHERE device_id = $1 AND account_id = $2 AND revoked_at IS NULL \
         RETURNING device_id",
    )
    .bind(device_id)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;
    if row.is_none() {
        tx.rollback().await?;
        return Ok(false);
    }
    sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL",
    )
    .bind(device_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}
