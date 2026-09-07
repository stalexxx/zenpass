//! Fixed, generic error bodies (T09/T17): no distinguishing detail leaks
//! whether a credential, account, or rate limit was the reason for failure.

use axum::{Json, http::StatusCode, response::Response};

use crate::dto::ApiError;

fn body(status: StatusCode, error: &'static str, message: &'static str) -> Response {
    use axum::response::IntoResponse;
    (
        status,
        Json(ApiError {
            error,
            message,
            request_id: crate::request_id::current(),
        }),
    )
        .into_response()
}

pub fn unauthorized() -> Response {
    body(
        StatusCode::UNAUTHORIZED,
        "authentication_failed",
        "Invalid credentials.",
    )
}

pub fn bad_request() -> Response {
    body(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "The request could not be processed.",
    )
}

pub fn not_found() -> Response {
    body(
        StatusCode::NOT_FOUND,
        "not_found",
        "The resource was not found.",
    )
}
