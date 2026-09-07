//! `/account/key-bundle` — authenticated account key-bundle GET/PUT with
//! compare-and-swap publication (ADR-0011 G1). Parity port of the Bun
//! reference's `apps/backend/src/account/{routes,store,bundle-codec}.mjs`.
//! Ownership is derived exclusively from the bearer session, never from a
//! client-supplied `accountId`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use sqlx::PgPool;

use crate::AppState;
use crate::auth::{
    Authenticated, decode_b64, encode_b64, responses_bad_request, responses_not_found,
};
use crate::dto::{KeyBundle, KeyBundleConflict};

pub const ACCOUNT_BUNDLE_FORMAT: &str = "c04-account-bundle/1";
const ACCOUNT_BUNDLE_FIELDS: [&str; 9] = [
    "format",
    "accountId",
    "vaultId",
    "itemId",
    "kdfParametersCbor",
    "wrappedAccountKey",
    "wrappedVaultKey",
    "wrappedItemKey",
    "wrappedRecoveryKey",
];
const WRAPPER_FIELDS: [&str; 4] = [
    "wrappedAccountKey",
    "wrappedVaultKey",
    "wrappedItemKey",
    "wrappedRecoveryKey",
];

pub const MAX_OUTER_BYTES: usize = 512 * 1024;
const MAX_WRAPPER_BYTES: usize = 64 * 1024;
const MAX_KDF_PARAMS_BYTES: usize = 512;
const MAX_OUTER_B64_LENGTH: usize = MAX_OUTER_BYTES.div_ceil(3) * 4 + 16;
const MAX_VERSION: i64 = 2_147_483_647;

fn is_valid_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && value.len() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_valid_b64_field(value: &str) -> bool {
    value.starts_with("b64:")
        && value[4..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        && value[4..].bytes().rev().take_while(|&b| b == b'=').count() <= 2
}

struct ValidatedBundle {
    account_id: String,
}

/// Validates `outer_bytes` (the raw bytes obtained by decoding a
/// `KeyBundle.bundle` string's `b64:` prefix) as a canonical
/// `c04-account-bundle/1` record. Returns `None` for any malformed,
/// oversized, non-canonical, or unrecognized-format input; never panics on
/// attacker-controlled input.
fn validate_account_bundle_bytes(outer_bytes: &[u8]) -> Option<ValidatedBundle> {
    if outer_bytes.is_empty() || outer_bytes.len() > MAX_OUTER_BYTES {
        return None;
    }
    let text = std::str::from_utf8(outer_bytes).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(text).ok()?;
    let obj = parsed.as_object()?;
    if obj.len() != ACCOUNT_BUNDLE_FIELDS.len() {
        return None;
    }
    let mut strings = std::collections::HashMap::new();
    for field in ACCOUNT_BUNDLE_FIELDS {
        let value = obj.get(field)?.as_str()?;
        strings.insert(field, value.to_owned());
    }

    if strings["format"] != ACCOUNT_BUNDLE_FORMAT {
        return None;
    }
    if !is_valid_id(&strings["accountId"])
        || !is_valid_id(&strings["vaultId"])
        || !is_valid_id(&strings["itemId"])
    {
        return None;
    }
    if !is_valid_b64_field(&strings["kdfParametersCbor"]) {
        return None;
    }
    let kdf_bytes = decode_b64(&strings["kdfParametersCbor"])?;
    if kdf_bytes.is_empty() || kdf_bytes.len() > MAX_KDF_PARAMS_BYTES {
        return None;
    }
    for field in WRAPPER_FIELDS {
        if !is_valid_b64_field(&strings[field]) {
            return None;
        }
        let bytes = decode_b64(&strings[field])?;
        if bytes.is_empty() || bytes.len() > MAX_WRAPPER_BYTES {
            return None;
        }
    }

    // Canonical reproduction: an exact byte match against the fixed field
    // order rejects reordered/duplicate keys, non-canonical base64 padding
    // variants, and stray whitespace without a bespoke check for each.
    // Built as a plain string (not via `serde_json::Map`, whose default
    // `BTreeMap` backing would silently re-sort keys alphabetically) so the
    // fixed `ACCOUNT_BUNDLE_FIELDS` order is reproduced exactly, matching
    // the Bun reference's `JSON.stringify` over a fixed-insertion-order
    // object.
    let mut canonical = String::from("{");
    for (i, field) in ACCOUNT_BUNDLE_FIELDS.iter().enumerate() {
        if i > 0 {
            canonical.push(',');
        }
        canonical.push('"');
        canonical.push_str(field);
        canonical.push_str("\":");
        canonical.push_str(&serde_json::to_string(&strings[field]).ok()?);
    }
    canonical.push('}');
    if canonical.into_bytes() != outer_bytes {
        return None;
    }

    Some(ValidatedBundle {
        account_id: strings["accountId"].clone(),
    })
}

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/account/key-bundle",
        get(get_key_bundle).put(put_key_bundle),
    )
}

#[derive(sqlx::FromRow)]
struct BundleRow {
    bundle: Vec<u8>,
    version: i32,
}

async fn get_key_bundle(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> Response {
    let row: Result<Option<BundleRow>, _> =
        sqlx::query_as("SELECT bundle, version FROM key_bundles WHERE account_id = $1")
            .bind(&session.account_id)
            .fetch_optional(state.pool())
            .await;
    match row {
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(KeyBundle {
                bundle: encode_b64(&row.bundle),
                version: row.version,
            }),
        )
            .into_response(),
        Ok(None) => responses_not_found(),
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "get_key_bundle_failed");
            crate::error::AppError::DatabaseUnavailable.into_response()
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutKeyBundleBody {
    bundle: String,
    version: i64,
}

async fn put_key_bundle(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    body: axum::extract::Request,
) -> Response {
    let bytes = match axum::body::to_bytes(body.into_body(), MAX_OUTER_B64_LENGTH + 4096).await {
        Ok(bytes) => bytes,
        Err(_) => return responses_bad_request(),
    };
    let Ok(payload) = serde_json::from_slice::<PutKeyBundleBody>(&bytes) else {
        return responses_bad_request();
    };
    if payload.bundle.is_empty() || payload.bundle.len() > MAX_OUTER_B64_LENGTH {
        return responses_bad_request();
    }
    if payload.version < 1 || payload.version > MAX_VERSION {
        return responses_bad_request();
    }
    let Some(decoded) = decode_b64(&payload.bundle) else {
        return responses_bad_request();
    };
    let Some(validated) = validate_account_bundle_bytes(&decoded) else {
        return responses_bad_request();
    };
    if validated.account_id != session.account_id {
        return responses_bad_request();
    }

    match publish_key_bundle(
        state.pool(),
        &session.account_id,
        &decoded,
        payload.version as i32,
    )
    .await
    {
        Ok(Outcome::Conflict { current_version }) => (
            StatusCode::CONFLICT,
            Json(KeyBundleConflict {
                error: "key_bundle_conflict".to_owned(),
                current_version,
                attempted_version: payload.version as i32,
            }),
        )
            .into_response(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "publish_key_bundle_failed");
            crate::error::AppError::DatabaseUnavailable.into_response()
        }
    }
}

enum Outcome {
    Created,
    Idempotent,
    Replaced,
    Conflict { current_version: Option<i32> },
}

/// Applies one publish attempt inside a single transaction (ADR-0011 G1).
/// On the no-row path, a concurrent first publish can race between this
/// transaction's `SELECT ... FOR UPDATE` (which locks nothing -- there is
/// no row yet) and its `INSERT`; that race surfaces as a Postgres
/// unique-violation (`23505`), and the losing attempt retries under the
/// now-existing row's lock instead of assuming failure.
async fn publish_key_bundle(
    pool: &PgPool,
    account_id: &str,
    bytes: &[u8],
    attempted_version: i32,
) -> Result<Outcome, sqlx::Error> {
    for _ in 0..5 {
        let mut tx = pool.begin().await?;
        let existing: Option<BundleRow> = sqlx::query_as(
            "SELECT bundle, version FROM key_bundles WHERE account_id = $1 FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(existing) = existing else {
            if attempted_version != 1 {
                tx.rollback().await?;
                return Ok(Outcome::Conflict {
                    current_version: None,
                });
            }
            let insert = sqlx::query(
                "INSERT INTO key_bundles (account_id, bundle, version) VALUES ($1, $2, $3)",
            )
            .bind(account_id)
            .bind(bytes)
            .bind(attempted_version)
            .execute(&mut *tx)
            .await;
            match insert {
                Ok(_) => {
                    tx.commit().await?;
                    return Ok(Outcome::Created);
                }
                Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
                    tx.rollback().await?;
                    continue; // retry: a concurrent first-publish committed first
                }
                Err(err) => return Err(err),
            }
        };

        if existing.version == attempted_version {
            let same = existing.bundle == bytes;
            tx.rollback().await?;
            return Ok(if same {
                Outcome::Idempotent
            } else {
                Outcome::Conflict {
                    current_version: Some(existing.version),
                }
            });
        }

        if attempted_version != existing.version + 1 {
            tx.rollback().await?;
            return Ok(Outcome::Conflict {
                current_version: Some(existing.version),
            });
        }

        sqlx::query(
            "UPDATE key_bundles SET bundle = $1, version = $2, updated_at = now() WHERE account_id = $3",
        )
        .bind(bytes)
        .bind(attempted_version)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(Outcome::Replaced);
    }
    // Matches the Bun reference: exhausting retries on a repeated
    // unique-key race is treated as a database error, not a client error.
    Err(sqlx::Error::RowNotFound)
}
