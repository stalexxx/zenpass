#![forbid(unsafe_code)]

pub mod config;
pub mod dto;
pub mod error;
pub mod migrate;
pub mod request_id;

use std::{sync::Arc, time::Instant};

use axum::{
    Json, Router,
    extract::{MatchedPath, Request, State},
    http::{HeaderName, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use config::{Config, LogLevel};
use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::sync::Semaphore;
use tracing_subscriber::{filter::Targets, layer::SubscriberExt};

pub const LOG_TARGET: &str = "zkpm_backend";
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone)]
pub struct AppState {
    pool: PgPool,
    concurrency: Arc<Semaphore>,
}

impl AppState {
    pub fn new(pool: PgPool, concurrency: usize) -> Self {
        Self {
            pool,
            concurrency: Arc::new(Semaphore::new(concurrency)),
        }
    }

    pub fn from_config(pool: PgPool, config: &Config) -> Self {
        Self::new(pool, config.limits.concurrency)
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

pub fn pool(config: &Config) -> Result<PgPool, config::ConfigError> {
    Ok(PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(config.database_acquire_timeout)
        .connect_lazy_with(config.connect_options()?))
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

pub fn app(pool: PgPool, config: &Config) -> Router {
    let state = AppState::from_config(pool, config);
    let router = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .with_state(state.clone());
    harden(router, config, state)
}

/// Apply the production middleware stack (request IDs, allowlisted logging,
/// CORS allowlist, timeout, concurrency admission, body limit) to a router.
/// Exposed so tests exercise the identical production stack.
pub fn harden(router: Router, config: &Config, state: AppState) -> Router {
    let cors = if config.cors_origins.is_empty() {
        tower_http::cors::CorsLayer::new()
    } else {
        let origins = config
            .cors_origins
            .iter()
            .map(|origin| origin.parse::<axum::http::HeaderValue>())
            .collect::<Result<Vec<_>, _>>()
            // Origins were structurally validated at configuration time.
            .expect("validated CORS origin");
        tower_http::cors::CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::list(origins))
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
            ])
            .allow_headers([header::CONTENT_TYPE])
    };
    let timeout = config.limits.request_timeout;
    router
        // Runs after routing, so MatchedPath is available: stamps the fixed
        // route name onto the response for the outer log middleware.
        .route_layer(middleware::from_fn(capture_route))
        .layer(axum::extract::DefaultBodyLimit::max(
            config.limits.body_limit_bytes,
        ))
        .layer(middleware::from_fn_with_state(state, concurrency_guard))
        .layer(middleware::from_fn_with_state(timeout, request_timeout))
        .layer(cors)
        .layer(middleware::from_fn(request_log))
        .layer(middleware::from_fn(request_id::attach))
}

async fn live() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn ready(State(state): State<AppState>) -> Result<Json<Health>, error::AppError> {
    // Compile-time checked constant query; no SQL parameter handling exists here.
    let query = sqlx::query_scalar!("SELECT 1").fetch_one(&state.pool);
    match tokio::time::timeout(config::Config::DATABASE_PROBE_TIMEOUT, query).await {
        Ok(Ok(Some(1))) => Ok(Json(Health { status: "ok" })),
        _ => Err(error::AppError::DatabaseUnavailable),
    }
}

#[derive(Clone)]
struct LoggedRoute(&'static str);

/// Inner layer: records the fixed route name on the response. Outer
/// middleware cannot observe MatchedPath directly, so the name travels on the
/// response extensions instead of touching request state.
async fn capture_route(request: Request, next: Next) -> Response {
    let route = match request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
    {
        Some("/health/live") => "/health/live",
        Some("/health/ready") => "/health/ready",
        _ => "unmatched",
    };
    let mut response = next.run(request).await;
    response.extensions_mut().insert(LoggedRoute(route));
    response
}

async fn request_log(request: Request, next: Next) -> Response {
    // Fixed route names only: never log the raw path, query string, method,
    // headers (including Authorization), or body content. The name is set by
    // the inner capture layer; unmatched requests have no name.
    let started = Instant::now();
    let response = next.run(request).await;
    let route = response
        .extensions()
        .get::<LoggedRoute>()
        .map(|name| name.0)
        .unwrap_or("unmatched");
    tracing::info!(
        target: LOG_TARGET,
        route,
        status = response.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        request_id = %request_id::current(),
        "request_complete"
    );
    response
}

async fn concurrency_guard(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Reject immediately instead of queueing: bounded admission, no unbounded
    // waiting-room growth under load.
    let Ok(permit) = state.concurrency.clone().try_acquire_owned() else {
        return error::AppError::Overloaded.into_response();
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

async fn request_timeout(
    State(limit): State<std::time::Duration>,
    request: Request,
    next: Next,
) -> Response {
    match tokio::time::timeout(limit, next.run(request)).await {
        Ok(response) => response,
        Err(_) => error::AppError::Timeout.into_response(),
    }
}

// Fixed target filter prevents verbose dependency/SQL logging even with
// RUST_LOG set; only the three allowlisted levels of this crate are recorded.
pub fn subscriber<W>(writer: W, level: LogLevel) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    use tracing::Level as L;
    let level = match level {
        LogLevel::Error => L::ERROR,
        LogLevel::Warn => L::WARN,
        LogLevel::Info => L::INFO,
    };
    tracing_subscriber::registry()
        .with(Targets::new().with_target(LOG_TARGET, level))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(writer)
                .with_ansi(false),
        )
}
