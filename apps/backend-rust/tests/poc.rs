use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use std::{
    io::Write,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;
use zkpm_backend_poc::{
    app,
    config::{Config, ConfigError},
    pool, subscriber,
};

fn local_config() -> Config {
    Config::from_values(
        None,
        Some("postgres://postgres@127.0.0.1:1/rust01_poc".into()),
    )
    .unwrap()
}

#[test]
fn configuration_is_typed_local_and_errors_do_not_echo_input() {
    let config = local_config();
    assert_eq!(config.bind.to_string(), "127.0.0.1:3100");
    assert!(matches!(
        Config::from_values(None, None),
        Err(ConfigError::MissingDatabase)
    ));
    for bind in [
        "0.0.0.0:3100",
        "[::]:3100",
        "remote.invalid:3100",
        "INPUT_MARKER",
        "https://127.0.0.1/poc",
        "postgres://postgres@127.0.0.1/poc?hostaddr=8.8.8.8",
        "postgres://postgres@127.0.0.1/poc?host=/tmp",
    ] {
        assert!(matches!(
            Config::from_values(Some(bind), Some("INPUT_MARKER".into())),
            Err(ConfigError::InvalidBind)
        ));
    }
    for url in [
        "INPUT_MARKER",
        "https://127.0.0.1/poc",
        "postgres://postgres@127.0.0.1/poc?hostaddr=8.8.8.8",
        "postgres://postgres@127.0.0.1/poc?host=/tmp",
        "postgres://postgres@remote.invalid/poc",
        "postgres://postgres@127.0.0.1/poc?host=remote.invalid",
    ] {
        let error = Config::from_values(None, Some(url.into())).err().unwrap();
        assert_eq!(error, ConfigError::InvalidDatabase);
        assert!(!error.to_string().contains("INPUT_MARKER"));
    }
    assert!(
        Config::from_values(
            Some("127.0.0.1:0"),
            Some("postgres://postgres@127.0.0.1/poc".into())
        )
        .is_ok()
    );
}

#[tokio::test]
async fn health_is_independent_of_database_and_no_product_routes_exist() {
    let pool = pool(&local_config()).unwrap();
    pool.close().await;
    let app = app(pool);
    for (path, expected, body) in [
        ("/health/live", StatusCode::OK, Some("ok")),
        (
            "/health/ready",
            StatusCode::SERVICE_UNAVAILABLE,
            Some("not_ready"),
        ),
        ("/v1/auth/opaque/login", StatusCode::NOT_FOUND, None),
        ("/v1/vaults/unused/items", StatusCode::NOT_FOUND, None),
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if let Some(status) = body {
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                serde_json::json!({"status": status})
            );
        }
    }
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn unreachable_database_returns_bounded_503() {
    let pool = pool(&local_config()).unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        app(pool.clone()).oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("readiness must be bounded")
    .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    pool.close().await;
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
async fn logs_allowlist_only_safe_fields() {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let sink = Capture(bytes.clone());
    let subscriber = subscriber(move || sink.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let pool = pool(&local_config()).unwrap();
    pool.close().await;
    let app = app(pool);
    // These are non-secret markers, not fixtures containing credentials/vault data.
    for uri in ["/health/live?QUERY_MARKER", "/PATH_MARKER?QUERY_MARKER"] {
        let request = Request::builder()
            .method("METHOD_MARKER")
            .uri(uri)
            .header("authorization", "HEADER_MARKER")
            .header("x-request-id", "REQUEST_ID_MARKER")
            .body(Body::from("BODY_MARKER"))
            .unwrap();
        app.clone().oneshot(request).await.unwrap();
    }
    tracing::info!(target: "sqlx::query", "DEPENDENCY_MARKER");
    let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    assert!(!output.contains("MARKER"));
    let records: Vec<serde_json::Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    for record in records {
        let fields = record["fields"].as_object().unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields["message"], "request_complete");
        assert!(fields.contains_key("route"));
        assert!(fields.contains_key("status"));
        assert!(fields.contains_key("elapsed_ms"));
    }
}
