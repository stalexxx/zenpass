//! `/auth/opaque/register`, `/auth/opaque/login`, `/auth/refresh`,
//! `/auth/logout`. Parity port of the Bun reference's `auth/routes.mjs`.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use rand::RngCore;
use rand::rngs::OsRng;

use crate::AppState;
use crate::dto::{OpaqueLoginRequest, OpaqueMessage, OpaqueRegisterRequest, Session};

use super::{
    AuthState, Authenticated, KE1_LEN, KE2_LEN, OPAQUE_CONTEXT, REGISTRATION_ACK,
    REGISTRATION_REQUEST_LEN, admission_key, codec, credentials, login_state::PendingLogin,
    rate_limit, responses, sessions, validation,
};

const MAX_BODY_BYTES: usize = 64 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/opaque/register", post(register))
        .route("/auth/opaque/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
}

async fn parse_json<T: serde::de::DeserializeOwned>(request: Request) -> Option<T> {
    let body = axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES)
        .await
        .ok()?;
    serde_json::from_slice(&body).ok()
}

async fn register(State(state): State<AppState>, request: Request) -> Response {
    let key = admission_key(request.extensions());
    let Some(payload) = parse_json::<OpaqueRegisterRequest>(request).await else {
        return responses::bad_request();
    };
    let Some(message) = codec::decode_b64(&payload.client_message) else {
        return responses::bad_request();
    };
    if !validation::is_valid_account_id(&payload.account_id) {
        return responses::bad_request();
    }
    if !state.auth.admission.allow(&key) {
        return responses::bad_request();
    }

    let auth = Arc::clone(&state.auth);
    let step = registration_step(auth, payload.account_id.clone(), message).await;
    let step = match step {
        Ok(step) => step,
        Err(()) => return responses::bad_request(),
    };

    if let Err(err) = credentials::ensure_account(state.pool(), &payload.account_id).await {
        tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "ensure_account_failed");
        return responses::bad_request();
    }
    let within_limit = match rate_limit::check_and_increment(
        state.pool(),
        &payload.account_id,
        "register",
        state.auth.rate_limit_max,
        state.auth.rate_limit_window,
    )
    .await
    {
        Ok(within_limit) => within_limit,
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "rate_limit_failed");
            return responses::bad_request();
        }
    };
    if !within_limit {
        return responses::bad_request();
    }

    match step {
        RegistrationStep::Response(message) => (
            StatusCode::CREATED,
            Json(OpaqueMessage {
                message: codec::encode_b64(&message),
            }),
        )
            .into_response(),
        RegistrationStep::Record(record) => {
            if let Err(err) = credentials::save_credential_record_if_absent(
                state.pool(),
                &payload.account_id,
                &record,
            )
            .await
            {
                tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "save_credential_failed");
                return responses::bad_request();
            }
            tracing::info!(target: crate::LOG_TARGET, event = "auth.register.completed");
            (
                StatusCode::CREATED,
                Json(OpaqueMessage {
                    message: codec::encode_b64(&REGISTRATION_ACK),
                }),
            )
                .into_response()
        }
    }
}

enum RegistrationStep {
    Response(Vec<u8>),
    Record(Vec<u8>),
}

/// Runs one OPAQUE registration step on the bounded blocking pool. Mirrors
/// the Bun reference's `opaque.registrationStep`, which distinguishes "the
/// client sent a `RegistrationRequest`" from "the client sent a
/// `RegistrationUpload`" by message length; the native core instead exposes
/// these as two distinct functions, dispatched on the same fixed-length
/// check (see `REGISTRATION_REQUEST_LEN`).
async fn registration_step(
    auth: Arc<AuthState>,
    account_id: String,
    message: Vec<u8>,
) -> Result<RegistrationStep, ()> {
    let auth_for_task = Arc::clone(&auth);
    auth.run_blocking(move || {
        if message.len() == REGISTRATION_REQUEST_LEN {
            crypto_core::opaque::server_registration_start(
                &auth_for_task.setup,
                &message,
                account_id.as_bytes(),
            )
            .map(|result| RegistrationStep::Response(result.message))
            .map_err(|_| ())
        } else {
            crypto_core::opaque::server_registration_finish(&message)
                .map(|record| RegistrationStep::Record(record.to_vec()))
                .map_err(|_| ())
        }
    })
    .await
}

async fn login(State(state): State<AppState>, request: Request) -> Response {
    let key = admission_key(request.extensions());
    let Some(payload) = parse_json::<OpaqueLoginRequest>(request).await else {
        return responses::unauthorized();
    };
    let Some(message) = codec::decode_b64(&payload.client_message) else {
        return responses::unauthorized();
    };
    if !validation::is_valid_account_id(&payload.account_id) {
        return responses::unauthorized();
    }
    let account_id = payload.account_id;
    let auth = Arc::clone(&state.auth);

    let has_pending = auth.login_states.has_pending(&account_id);
    if !has_pending && message.len() != KE1_LEN {
        return responses::unauthorized();
    }
    if !auth.admission.allow(&key) {
        return responses::unauthorized();
    }

    if let Err(err) = credentials::ensure_account(state.pool(), &account_id).await {
        tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "ensure_account_failed");
        return responses::unauthorized();
    }
    let within_limit = match rate_limit::check_and_increment(
        state.pool(),
        &account_id,
        "login",
        auth.rate_limit_max,
        auth.rate_limit_window,
    )
    .await
    {
        Ok(within_limit) => within_limit,
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "rate_limit_failed");
            return responses::unauthorized();
        }
    };
    if !within_limit {
        return responses::unauthorized();
    }

    if !has_pending {
        return login_leg1(state.pool(), auth, account_id, message).await;
    }
    login_leg2(state.pool(), auth, account_id, message).await
}

async fn login_leg1(
    pool: &sqlx::PgPool,
    auth: Arc<AuthState>,
    account_id: String,
    message: Vec<u8>,
) -> Response {
    let credential_record = match credentials::get_credential_record(pool, &account_id).await {
        Ok(record) => record,
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "get_credential_failed");
            return responses::unauthorized();
        }
    };
    let Some(credential_record) = credential_record else {
        // Unknown account: same-shaped decoy KE2 (ADR-0006 §9 residual).
        auth.login_states.set_fake(&account_id);
        let mut decoy = vec![0u8; KE2_LEN];
        OsRng.fill_bytes(&mut decoy);
        return (
            StatusCode::OK,
            Json(OpaqueMessage {
                message: codec::encode_b64(&decoy),
            }),
        )
            .into_response();
    };

    let account_id_for_task = account_id.clone();
    let auth_for_task = Arc::clone(&auth);
    let started = auth
        .run_blocking(move || {
            crypto_core::opaque::server_login_start(
                &auth_for_task.setup,
                &credential_record,
                account_id_for_task.as_bytes(),
                &message,
                OPAQUE_CONTEXT,
            )
        })
        .await;
    let started = match started {
        Ok(started) => started,
        Err(_) => return responses::unauthorized(),
    };
    auth.login_states
        .set_real(&account_id, started.state_bytes());
    (
        StatusCode::OK,
        Json(OpaqueMessage {
            message: codec::encode_b64(&started.message),
        }),
    )
        .into_response()
}

async fn login_leg2(
    pool: &sqlx::PgPool,
    auth: Arc<AuthState>,
    account_id: String,
    message: Vec<u8>,
) -> Response {
    let pending = auth.login_states.take(&account_id);
    let Some(PendingLogin::Real(state_bytes)) = pending else {
        return responses::unauthorized();
    };

    let finish_result = auth
        .run_blocking(move || {
            let server_state = crypto_core::opaque::server_login_state(&state_bytes)?;
            crypto_core::opaque::server_login_finish(server_state, &message, OPAQUE_CONTEXT)
        })
        .await;
    if finish_result.is_err() {
        return responses::unauthorized();
    }

    let session = match sessions::issue_session(
        pool,
        &account_id,
        auth.session_ttl,
        sessions::OPAQUE_LOGIN,
    )
    .await
    {
        Ok(session) => session,
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "issue_session_failed");
            return responses::unauthorized();
        }
    };
    tracing::info!(target: crate::LOG_TARGET, event = "auth.login.succeeded");
    (
        StatusCode::OK,
        Json(Session {
            access_token: session.access_token.as_str().to_owned(),
            expires_at: session.expires_at_rfc3339(),
        }),
    )
        .into_response()
}

async fn refresh(State(state): State<AppState>, Authenticated(session): Authenticated) -> Response {
    // ADR-0005 §2: only a non-revoked device-bound session may refresh.
    if session.device_id.is_none() {
        return responses::unauthorized();
    }
    match sessions::rotate_session(state.pool(), &session, state.auth.session_ttl).await {
        Ok(Some(issued)) => (
            StatusCode::OK,
            Json(Session {
                access_token: issued.access_token.as_str().to_owned(),
                expires_at: issued.expires_at_rfc3339(),
            }),
        )
            .into_response(),
        Ok(None) => responses::unauthorized(),
        Err(err) => {
            tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "rotate_session_failed");
            responses::unauthorized()
        }
    }
}

async fn logout(State(state): State<AppState>, Authenticated(session): Authenticated) -> Response {
    if let Err(err) = sessions::revoke_session(state.pool(), session.session_id).await {
        tracing::error!(target: crate::LOG_TARGET, code = "db_error", error = %err, "revoke_session_failed");
    }
    StatusCode::NO_CONTENT.into_response()
}
