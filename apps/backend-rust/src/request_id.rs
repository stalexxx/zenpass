//! Server-generated correlation/request IDs.
//!
//! Incoming `x-request-id` values are untrusted and always ignored: the
//! server generates a fresh UUID v4 per request, attaches it as a task-local
//! for log/error correlation, and returns it in the response header.

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use uuid::Uuid;

use crate::REQUEST_ID_HEADER;

#[derive(Clone, PartialEq, Eq)]
pub struct RequestId(pub(crate) String);

impl RequestId {
    pub fn value(&self) -> &str {
        &self.0
    }
}

tokio::task_local! {
    static CURRENT: RequestId;
}

pub fn generate() -> RequestId {
    RequestId(Uuid::new_v4().to_string())
}

/// Value used when no request scope exists (for example logging during
/// startup); never derived from client input.
pub fn current() -> String {
    CURRENT
        .try_with(|id| id.0.clone())
        .unwrap_or_else(|_| "startup".to_owned())
}

pub async fn attach(mut request: Request, next: Next) -> Response {
    // Explicitly drop any untrusted client-supplied request ID first.
    request.headers_mut().remove(REQUEST_ID_HEADER);
    let id = generate();
    let mut response: Response = CURRENT.scope(id.clone(), next.run(request)).await;
    // HeaderValue::from_str of a UUID cannot fail; on impossible failure keep
    // the response without the header rather than surfacing an error.
    if let Ok(value) = HeaderValue::from_str(&id.0) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    } else {
        tracing::warn!(target: crate::LOG_TARGET, "request_id_header_invalid");
    }
    response
}
