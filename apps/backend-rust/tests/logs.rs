//! Log allowlist test in its own binary: tracing callsite interest is cached
//! process-wide, so a capturing test must not share a process with other
//! tests that fire the same callsites without a subscriber installed.

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use axum::{body::Body, http::Request};
use tower::ServiceExt;
use zkpm_backend::{
    app,
    config::{Config, Environment, LogLevel, Values},
    pool, subscriber,
};

fn config_with(mut values: Values) -> Config {
    values
        .database_url
        .get_or_insert_with(|| "postgres://postgres@127.0.0.1:1/rust02".into());
    Config::from_values(Environment::Development, values).unwrap()
}

fn state_for(config: &Config) -> zkpm_backend::AppState {
    zkpm_backend::AppState::from_config(pool(config).unwrap(), config)
}

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn logs_allowlist_only_safe_fields_and_no_sensitive_values() {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let sink = Capture(bytes.clone());
    let subscriber = subscriber(move || sink.clone(), LogLevel::Info);
    let _guard = tracing::subscriber::set_default(subscriber);
    let config = config_with(Values {
        cors_origins: Some("https://vault.example".into()),
        ..Values::default()
    });
    let state = state_for(&config);
    state.pool().close().await;
    let router = app(state.pool().clone(), &config);
    // (method, uri, expected fixed route): unmatched requests have no name.
    let cases = [
        ("GET", "/health/live?QUERY_MARKER", "/health/live"),
        (
            "POST",
            "/health/ready?password=QUERY_MARKER",
            "/health/ready",
        ),
        ("METHOD_MARKER", "/PATH_MARKER?QUERY_MARKER", "unmatched"),
    ];
    for (method, uri, _) in &cases {
        let request = Request::builder()
            .method(*method)
            .uri(*uri)
            .header("authorization", "Bearer HEADER_MARKER")
            .header("x-request-id", "REQUEST_ID_MARKER")
            .body(Body::from("BODY_MARKER"))
            .unwrap();
        router.clone().oneshot(request).await.unwrap();
    }
    tracing::info!(target: "sqlx::query", "DEPENDENCY_MARKER");
    tracing::info!(target: "hyper", "HYPER_MARKER");
    let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    assert!(
        !output.contains("MARKER"),
        "logs leaked a marker:\n{output}"
    );
    let records: Vec<serde_json::Value> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect();
    assert_eq!(records.len(), cases.len(), "unexpected records: {output}");
    for (record, (_, _, route)) in records.iter().zip(cases.iter()) {
        let fields = record["fields"].as_object().unwrap();
        assert_eq!(fields["message"], "request_complete");
        assert_eq!(fields["route"], *route);
        let request_id = fields["request_id"].as_str().unwrap();
        assert!(uuid::Uuid::parse_str(request_id).is_ok());
        assert!(fields.contains_key("status"));
        assert!(fields.contains_key("elapsed_ms"));
        assert_eq!(fields.len(), 5);
    }
}
