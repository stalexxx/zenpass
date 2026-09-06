//! Application error mapping: internal failures map to fixed generic HTTP
//! bodies (`ApiError`) carrying only a server-generated request ID. Raw
//! database/driver errors are logged under an allowlisted code and never
//! serialized to clients.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::dto::ApiError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("request body too large")]
    BodyTooLarge,
    #[error("request timed out")]
    Timeout,
    #[error("too many concurrent requests")]
    Overloaded,
    #[error("database unavailable")]
    DatabaseUnavailable,
}

impl AppError {
    fn parts(&self) -> (StatusCode, &'static str, &'static str) {
        match self {
            AppError::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "request body exceeds the configured limit",
            ),
            AppError::Timeout => (StatusCode::REQUEST_TIMEOUT, "timeout", "request timed out"),
            AppError::Overloaded => (
                StatusCode::SERVICE_UNAVAILABLE,
                "overloaded",
                "server is at maximum concurrency",
            ),
            AppError::DatabaseUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "service is temporarily unavailable",
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // The `request_log` middleware already records status/route/timing for
        // every response, including this one; logging here too would duplicate
        // that record and break the one-record-per-request invariant.
        let (status, error, message) = self.parts();
        let request_id = crate::request_id::current();
        (
            status,
            Json(ApiError {
                error,
                message,
                request_id,
            }),
        )
            .into_response()
    }
}
