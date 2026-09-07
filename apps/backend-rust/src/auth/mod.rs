//! Native auth: OPAQUE registration/login, refresh, logout. Parity port of
//! the Bun reference's `apps/backend/src/auth/*`.

mod admission;
mod cleanup;
mod codec;
mod credentials;
mod login_state;
mod rate_limit;
mod responses;
pub mod routes;
mod sessions;
mod validation;

pub use codec::{decode_b64, encode_b64};
pub use responses::bad_request as responses_bad_request;
pub use responses::not_found as responses_not_found;
pub use responses::unauthorized as responses_unauthorized;
pub use sessions::{AuthSession, OPAQUE_LOGIN, bind_session_to_device};

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::response::Response;

use crate::AppState;
use crate::config::Config;
use admission::AdmissionLimiter;
use crypto_core::opaque::ServerSetupHandle;
use login_state::LoginStateStore;

/// Fixed application-level context binding OPAQUE messages to this
/// deployment (ADR-0006). Distinct from any protocol-internal context.
pub const OPAQUE_CONTEXT: &[u8] = b"zkpm-opaque-v1";
/// Fixed by the pinned Ristretto255 suite (ADR-0003); used only to keep the
/// unknown-account decoy response the same shape as a real KE2 (ADR-0006
/// §9 residual gap: HTTP-shape parity, not full OPRF-level
/// indistinguishability).
pub const KE1_LEN: usize = 96;
pub const KE2_LEN: usize = 320;
/// Fixed by the pinned Ristretto255-SHA512 suite (ADR-0003): a
/// `RegistrationRequest` is exactly the 32-byte OPRF blinded element,
/// distinct from a `RegistrationUpload`'s fixed 192 bytes. `opaque-ke`'s
/// `RegistrationRequest::deserialize` does not itself reject trailing
/// bytes (it reads only the prefix it needs), so exact length is checked
/// here before choosing which native step to run -- otherwise a
/// `RegistrationUpload` would silently misparse as a fresh
/// `RegistrationRequest` and registration would never complete.
pub const REGISTRATION_REQUEST_LEN: usize = 32;
/// Non-empty placeholder for the registration-finish leg, which has nothing
/// meaningful to send back.
pub const REGISTRATION_ACK: [u8; 1] = [1];

/// Bound on concurrent blocking OPAQUE CPU work: a permit is acquired
/// before `spawn_blocking` and held until the blocking closure actually
/// completes (not merely until it is scheduled), so OPAQUE work cannot
/// unboundedly queue kernel threads under load.
const MAX_CONCURRENT_OPAQUE_WORK: usize = 16;

pub struct AuthState {
    pub(crate) setup: ServerSetupHandle,
    pub(crate) login_states: LoginStateStore,
    pub(crate) admission: AdmissionLimiter,
    pub session_ttl: time::Duration,
    pub rate_limit_max: u32,
    pub rate_limit_window: time::Duration,
    opaque_work: tokio::sync::Semaphore,
}

impl AuthState {
    pub fn new(config: &Config) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::build(config))
    }

    fn build(config: &Config) -> Self {
        let setup = match config.opaque_server_setup() {
            Some(bytes) => ServerSetupHandle::deserialize(bytes)
                .expect("OPAQUE server setup validated at configuration load"),
            None => {
                if config.is_production() {
                    // Matches the Bun reference's `loadOrGenerateServerSetup`,
                    // which throws (rather than generating ephemeral setup)
                    // once the auth context is actually built in production.
                    panic!("OPAQUE_SERVER_SETUP is required in production");
                }
                // Plain stderr, not the structured per-request `tracing`
                // pipeline (matching the Bun reference's plain
                // `console.warn`, which is likewise outside its Fastify
                // request logger): this is a one-time process-startup
                // operational notice, not a per-request log record subject
                // to the request-log allowlist invariant.
                eprintln!(
                    "generating an ephemeral OPAQUE server setup; unsafe outside production, will not survive a restart"
                );
                ServerSetupHandle::generate()
            }
        };
        Self {
            setup,
            login_states: LoginStateStore::new(),
            admission: AdmissionLimiter::new(),
            session_ttl: time::Duration::seconds(config.session_ttl.as_secs() as i64),
            rate_limit_max: config.auth_rate_limit_max,
            rate_limit_window: time::Duration::seconds(
                config.auth_rate_limit_window.as_secs() as i64
            ),
            opaque_work: tokio::sync::Semaphore::new(MAX_CONCURRENT_OPAQUE_WORK),
        }
    }

    /// Runs `f` (native, CPU-bound OPAQUE work) on the blocking thread pool,
    /// bounded by a permit held for the closure's actual duration.
    async fn run_blocking<T, F>(&self, f: F) -> T
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = self
            .opaque_work
            .acquire()
            .await
            .expect("opaque work semaphore is never closed");
        let result = tokio::task::spawn_blocking(f)
            .await
            .expect("OPAQUE blocking task must not panic");
        drop(permit);
        result
    }
}

/// Best-effort, coarse admission key: the caller's network origin. Never
/// the account id (see `admission` module doc).
pub(crate) fn admission_key(extensions: &axum::http::Extensions) -> String {
    extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Axum extractor equivalent of the Bun reference's `requireSession`
/// preHandler: resolves `Authorization: Bearer <token>` into a live
/// session, or fails the request with a generic 401.
pub struct Authenticated(pub AuthSession);

impl<S> FromRequestParts<S> for Authenticated
where
    AppState: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let Some(token) = header.strip_prefix("Bearer ").filter(|t| !t.is_empty()) else {
            return Err(responses::unauthorized());
        };
        match sessions::resolve_session(app_state.pool(), token).await {
            Ok(Some(session)) => Ok(Authenticated(session)),
            _ => Err(responses::unauthorized()),
        }
    }
}
