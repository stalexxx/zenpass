#![forbid(unsafe_code)]

pub mod config;

use axum::{
    Json, Router,
    extract::{MatchedPath, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use config::Config;
use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Instant;
use tracing_subscriber::{filter::Targets, layer::SubscriberExt};

pub fn pool(config: &Config) -> Result<PgPool, config::ConfigError> {
    Ok(PgPoolOptions::new()
        .max_connections(Config::MAX_CONNECTIONS)
        .acquire_timeout(Config::DATABASE_TIMEOUT)
        .connect_lazy_with(config.connect_options()?))
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

pub fn app(pool: PgPool) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .layer(middleware::from_fn(request_log))
        .with_state(pool)
}

async fn live() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn ready(State(pool): State<PgPool>) -> (StatusCode, Json<Health>) {
    let query = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&pool);
    if matches!(
        tokio::time::timeout(Config::DATABASE_TIMEOUT, query).await,
        Ok(Ok(1))
    ) {
        (StatusCode::OK, Json(Health { status: "ok" }))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Health {
                status: "not_ready",
            }),
        )
    }
}

async fn request_log(request: Request, next: Next) -> Response {
    // Never retain raw path/query/header/method/body; methods can be arbitrary tokens.
    let route = match request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
    {
        Some("/health/live") => "/health/live",
        Some("/health/ready") => "/health/ready",
        _ => "unmatched",
    };
    let started = Instant::now();
    let response = next.run(request).await;
    tracing::info!(target: "zkpm_backend_poc", route, status = response.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64, "request_complete");
    response
}

// Fixed target filter prevents verbose dependency/SQL logging even with RUST_LOG set.
pub fn subscriber<W>(writer: W) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::registry()
        .with(Targets::new().with_target("zkpm_backend_poc", tracing::Level::INFO))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(writer)
                .with_ansi(false),
        )
}
