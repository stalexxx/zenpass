//! `/vaults/{vaultId}/items` and `/vaults/{vaultId}/changes`. Parity port of
//! the Bun reference's `apps/backend/src/sync/{routes,store}.mjs`: ownership,
//! `baseRevision` optimistic concurrency, `mutationId` idempotency/replay,
//! tombstone retention, and a monotonic per-vault change feed with an
//! opaque cursor.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::AppState;
use crate::auth::{
    Authenticated, decode_b64, encode_b64, responses_bad_request, responses_not_found,
};
use crate::dto::{ChangePage, Conflict, ItemRecord, Mutation};

const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/vaults/{vaultId}/items", post(post_item))
        .route("/vaults/{vaultId}/changes", get(get_changes))
}

fn is_valid_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && value.len() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_valid_ciphertext(value: &str) -> bool {
    let Some(body) = value.strip_prefix("b64:") else {
        return false;
    };
    let core = body.trim_end_matches('=');
    let padding = body.len() - core.len();
    !core.is_empty()
        && padding <= 2
        && core
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

fn is_valid_mutation(mutation: &Mutation) -> bool {
    is_valid_id(&mutation.mutation_id)
        && is_valid_id(&mutation.item_id)
        && is_valid_id(&mutation.vault_id)
        && mutation.base_revision >= 0
        && is_valid_ciphertext(&mutation.ciphertext)
        && mutation.envelope_version == crate::dto::ENVELOPE_VERSION
}

fn encode_cursor(sequence: i64) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sequence.to_string())
}

/// Returns the decoded non-negative integer sequence, or `None` if `cursor`
/// isn't a well-formed opaque cursor.
fn decode_cursor(cursor: &str) -> Option<i64> {
    if cursor.is_empty() {
        return None;
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[derive(sqlx::FromRow)]
struct ItemRow {
    vault_id: String,
    item_id: String,
    ciphertext: Vec<u8>,
    envelope_version: String,
    revision: i64,
    deleted: bool,
    created_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
    sequence: i64,
}

fn to_item_record(row: &ItemRow) -> ItemRecord {
    ItemRecord {
        item_id: row.item_id.clone(),
        vault_id: row.vault_id.clone(),
        ciphertext: encode_b64(&row.ciphertext),
        envelope_version: row.envelope_version.clone(),
        revision: row.revision,
        deleted: row.deleted,
        created_at: rfc3339(row.created_at),
        updated_at: rfc3339(row.updated_at),
    }
}

fn rfc3339(value: time::OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .expect("valid RFC 3339 timestamp")
}

async fn find_mutation_outcome(
    pool: &PgPool,
    account_id: &str,
    mutation_id: &str,
) -> Result<Option<(i32, serde_json::Value)>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT status_code, response_body FROM mutation_outcomes WHERE account_id = $1 AND mutation_id = $2",
    )
    .bind(account_id)
    .bind(mutation_id)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(row) => Ok(Some((
            row.try_get("status_code")?,
            row.try_get("response_body")?,
        ))),
        None => Ok(None),
    }
}

async fn post_item(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Path(vault_id_param): Path<String>,
    body: axum::extract::Request,
) -> Response {
    let account_id = session.account_id.clone();
    let bytes = match axum::body::to_bytes(body.into_body(), MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return responses_bad_request(),
    };
    let Ok(mutation) = serde_json::from_slice::<Mutation>(&bytes) else {
        return responses_bad_request();
    };
    if !is_valid_id(&vault_id_param)
        || !is_valid_mutation(&mutation)
        || mutation.vault_id != vault_id_param
    {
        return responses_bad_request();
    }
    let Some(ciphertext) = decode_b64(&mutation.ciphertext) else {
        return responses_bad_request();
    };

    // Idempotency fast path: most replays arrive after the original
    // mutation already committed, so this point read (no lock, no
    // transaction) avoids the lock/transaction overhead below entirely.
    match find_mutation_outcome(state.pool(), &account_id, &mutation.mutation_id).await {
        Ok(Some((status_code, body))) => {
            return (status_from_i32(status_code), Json(body)).into_response();
        }
        Ok(None) => {}
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "find_mutation_outcome_failed");
            return crate::error::AppError::DatabaseUnavailable.into_response();
        }
    }

    match apply_mutation(
        state.pool(),
        &account_id,
        &vault_id_param,
        &mutation,
        &ciphertext,
    )
    .await
    {
        Ok(ApplyOutcome::NotFound) => responses_not_found(),
        Ok(ApplyOutcome::BadRequest) => responses_bad_request(),
        Ok(ApplyOutcome::Response(status_code, body)) => {
            (status_from_i32(status_code), Json(body)).into_response()
        }
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "apply_mutation_failed");
            crate::error::AppError::DatabaseUnavailable.into_response()
        }
    }
}

fn status_from_i32(code: i32) -> StatusCode {
    StatusCode::from_u16(code as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

enum ApplyOutcome {
    NotFound,
    BadRequest,
    Response(i32, serde_json::Value),
}

/// Applies one mutation inside a single transaction.
async fn apply_mutation(
    pool: &PgPool,
    account_id: &str,
    vault_id: &str,
    mutation: &Mutation,
    ciphertext: &[u8],
) -> Result<ApplyOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Serializes concurrent mutation attempts sharing the same (account,
    // mutationId) so a true double-submit race can't both observe "no
    // recorded outcome yet" and both proceed to write. Released
    // automatically at transaction end.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(format!("{account_id}:{}", mutation.mutation_id))
        .execute(&mut *tx)
        .await?;

    // Re-check idempotency after acquiring the lock: a concurrent request
    // carrying the same mutationId may have committed while this
    // transaction waited on the lock above.
    if let Some((status_code, body)) =
        find_mutation_outcome_tx(&mut tx, account_id, &mutation.mutation_id).await?
    {
        tx.commit().await?;
        return Ok(ApplyOutcome::Response(status_code, body));
    }

    if !ensure_vault_ownership(&mut tx, account_id, vault_id).await? {
        tx.rollback().await?;
        return Ok(ApplyOutcome::NotFound);
    }

    let existing = get_item_for_update(&mut tx, vault_id, &mutation.item_id).await?;
    let current_revision = existing.as_ref().map(|row| row.revision).unwrap_or(0);

    if mutation.base_revision != current_revision {
        let Some(existing) = existing else {
            // No item exists yet, so there is no ItemRecord to embed in a
            // Conflict response's `current` (required, non-null). A
            // non-zero baseRevision against a nonexistent item is a
            // client-side bug, not a recoverable conflict.
            tx.rollback().await?;
            return Ok(ApplyOutcome::BadRequest);
        };
        let body = serde_json::to_value(Conflict {
            error: "conflict".to_owned(),
            mutation_id: mutation.mutation_id.clone(),
            current: to_item_record(&existing),
            attempted: mutation.clone(),
        })
        .expect("Conflict serializes");
        record_mutation_outcome(
            &mut tx,
            account_id,
            &mutation.mutation_id,
            vault_id,
            409,
            &body,
        )
        .await?;
        tx.commit().await?;
        return Ok(ApplyOutcome::Response(409, body));
    }

    let row = upsert_item(
        &mut tx,
        vault_id,
        &mutation.item_id,
        ciphertext,
        &mutation.envelope_version,
        current_revision + 1,
        mutation.deleted,
    )
    .await?;
    let body = serde_json::to_value(to_item_record(&row)).expect("ItemRecord serializes");
    record_mutation_outcome(
        &mut tx,
        account_id,
        &mutation.mutation_id,
        vault_id,
        201,
        &body,
    )
    .await?;
    tx.commit().await?;
    Ok(ApplyOutcome::Response(201, body))
}

async fn find_mutation_outcome_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    mutation_id: &str,
) -> Result<Option<(i32, serde_json::Value)>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT status_code, response_body FROM mutation_outcomes WHERE account_id = $1 AND mutation_id = $2",
    )
    .bind(account_id)
    .bind(mutation_id)
    .fetch_optional(&mut **tx)
    .await?;
    match row {
        Some(row) => Ok(Some((
            row.try_get("status_code")?,
            row.try_get("response_body")?,
        ))),
        None => Ok(None),
    }
}

/// Ensures `vault_id` is owned by `account_id`, auto-creating the vault
/// (owned by the caller) on first write -- sync-v1 has no separate "create
/// vault" endpoint. Returns true iff the caller owns the vault
/// (pre-existing or freshly created this call).
async fn ensure_vault_ownership(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    vault_id: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query("INSERT INTO vaults (vault_id, account_id) VALUES ($1, $2) ON CONFLICT (vault_id) DO NOTHING")
        .bind(vault_id)
        .bind(account_id)
        .execute(&mut **tx)
        .await?;
    let row: Option<(String,)> =
        sqlx::query_as("SELECT account_id FROM vaults WHERE vault_id = $1")
            .bind(vault_id)
            .fetch_optional(&mut **tx)
            .await?;
    Ok(row.map(|(owner,)| owner == account_id).unwrap_or(false))
}

/// Read-only ownership check (no auto-create) for the change feed: reading
/// a vault that doesn't exist yet must never create it.
async fn vault_owned_by(
    pool: &PgPool,
    account_id: &str,
    vault_id: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT account_id FROM vaults WHERE vault_id = $1")
            .bind(vault_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(owner,)| owner == account_id).unwrap_or(false))
}

/// Locks the item row (if any) for the duration of the caller's
/// transaction, so a concurrent mutation to the same item can't read a
/// stale revision and both "win" a `baseRevision` check.
async fn get_item_for_update(
    tx: &mut Transaction<'_, Postgres>,
    vault_id: &str,
    item_id: &str,
) -> Result<Option<ItemRow>, sqlx::Error> {
    sqlx::query_as("SELECT * FROM vault_items WHERE vault_id = $1 AND item_id = $2 FOR UPDATE")
        .bind(vault_id)
        .bind(item_id)
        .fetch_optional(&mut **tx)
        .await
}

#[allow(clippy::too_many_arguments)]
async fn upsert_item(
    tx: &mut Transaction<'_, Postgres>,
    vault_id: &str,
    item_id: &str,
    ciphertext: &[u8],
    envelope_version: &str,
    revision: i64,
    deleted: bool,
) -> Result<ItemRow, sqlx::Error> {
    sqlx::query_as(
        "INSERT INTO vault_items (vault_id, item_id, ciphertext, envelope_version, revision, deleted, sequence) \
         VALUES ($1, $2, $3, $4, $5, $6, nextval('vault_change_sequence')) \
         ON CONFLICT (vault_id, item_id) DO UPDATE SET \
           ciphertext = EXCLUDED.ciphertext, \
           envelope_version = EXCLUDED.envelope_version, \
           revision = EXCLUDED.revision, \
           deleted = EXCLUDED.deleted, \
           updated_at = now(), \
           sequence = nextval('vault_change_sequence') \
         RETURNING *",
    )
    .bind(vault_id)
    .bind(item_id)
    .bind(ciphertext)
    .bind(envelope_version)
    .bind(revision)
    .bind(deleted)
    .fetch_one(&mut **tx)
    .await
}

async fn record_mutation_outcome(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    mutation_id: &str,
    vault_id: &str,
    status_code: i32,
    body: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO mutation_outcomes (account_id, mutation_id, vault_id, status_code, response_body) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(account_id)
    .bind(mutation_id)
    .bind(vault_id)
    .bind(status_code)
    .bind(body)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Change feed page: tombstones (`deleted = true`) are never filtered out
/// here, so they stay visible for retention (sync-state-machine.md). No
/// expiry/purge is implemented -- see the RUST-03 report's Known
/// limitations, matching the Bun reference's own documented limitation.
async fn list_changes(
    pool: &PgPool,
    vault_id: &str,
    after_sequence: i64,
    limit: i64,
) -> Result<Vec<ItemRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT * FROM vault_items WHERE vault_id = $1 AND sequence > $2::bigint ORDER BY sequence ASC LIMIT $3",
    )
    .bind(vault_id)
    .bind(after_sequence)
    .bind(limit)
    .fetch_all(pool)
    .await
}

#[derive(Deserialize)]
struct ChangesQuery {
    cursor: Option<String>,
    limit: Option<String>,
}

async fn get_changes(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Path(vault_id): Path<String>,
    Query(query): Query<ChangesQuery>,
) -> Response {
    if !is_valid_id(&vault_id) {
        return responses_bad_request();
    }

    let mut after_sequence: i64 = 0;
    if let Some(cursor) = &query.cursor {
        match decode_cursor(cursor) {
            Some(decoded) => after_sequence = decoded,
            None => return responses_bad_request(),
        }
    }

    let mut limit: i64 = 100;
    if let Some(raw) = &query.limit {
        match raw.parse::<i64>() {
            Ok(value) if (1..=200).contains(&value) && raw.bytes().all(|b| b.is_ascii_digit()) => {
                limit = value;
            }
            _ => return responses_bad_request(),
        }
    }

    match vault_owned_by(state.pool(), &session.account_id, &vault_id).await {
        Ok(true) => {}
        Ok(false) => return responses_not_found(),
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "vault_owned_by_failed");
            return crate::error::AppError::DatabaseUnavailable.into_response();
        }
    }

    let rows = match list_changes(state.pool(), &vault_id, after_sequence, limit).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "list_changes_failed");
            return crate::error::AppError::DatabaseUnavailable.into_response();
        }
    };
    let next_cursor = if let Some(last) = rows.last() {
        encode_cursor(last.sequence)
    } else {
        query.cursor.clone().unwrap_or_else(|| encode_cursor(0))
    };
    let changes = rows.iter().map(to_item_record).collect();
    (
        StatusCode::OK,
        Json(ChangePage {
            changes,
            next_cursor: Some(next_cursor),
        }),
    )
        .into_response()
}
