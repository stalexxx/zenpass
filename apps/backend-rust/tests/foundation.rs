//! Unit tests for configuration, DTO mapping, logging allowlist, request
//! IDs, CORS allowlist, and body/timeout/concurrency limits. No database or
//! network is required: pools point at an unreachable loopback port.

use std::time::Duration;

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::State,
    http::{Request, StatusCode, header},
    routing::post,
};
use config::{Config, DatabaseTls, Environment, Values};
use http_body_util::BodyExt;
use tower::ServiceExt;
use zkpm_backend::{app, config, dto, harden, pool, request_id};

fn config_with(mut values: Values) -> Config {
    values
        .database_url
        .get_or_insert_with(|| "postgres://postgres@127.0.0.1:1/rust02".into());
    Config::from_values(Environment::Development, values).unwrap()
}

fn state_for(config: &Config) -> zkpm_backend::AppState {
    zkpm_backend::AppState::from_config(pool(config).unwrap(), config)
}

#[test]
fn configuration_is_typed_and_errors_do_not_echo_input() {
    let config = config_with(Values::default());
    assert_eq!(config.bind.to_string(), "127.0.0.1:8080");
    assert_eq!(config.database_tls, DatabaseTls::Disabled);
    assert_eq!(
        config.limits.body_limit_bytes,
        Config::DEFAULT_BODY_LIMIT_BYTES
    );

    // Missing database URL.
    assert_eq!(
        Config::from_values(Environment::Development, Values::default())
            .err()
            .unwrap(),
        config::ConfigError::MissingDatabase
    );
    // Non-loopback bind rejected outside production.
    for bind in ["0.0.0.0:8080", "[::]:8080"] {
        assert_eq!(
            Config::from_values(
                Environment::Development,
                Values {
                    bind: Some(bind.into()),
                    ..Values::default()
                }
            )
            .err()
            .unwrap(),
            config::ConfigError::BindNotLoopback,
            "bind {bind}"
        );
    }
    // Unparseable bind addresses.
    for bind in ["example.invalid:8080", "MARKER"] {
        assert_eq!(
            Config::from_values(
                Environment::Development,
                Values {
                    bind: Some(bind.into()),
                    ..Values::default()
                }
            )
            .err()
            .unwrap(),
            config::ConfigError::InvalidBind,
            "bind {bind}"
        );
    }
    // Non-loopback database host rejected outside production; no echo.
    for url in [
        "MARKER",
        "https://127.0.0.1/db",
        "postgres://postgres@remote.invalid/db",
        "postgres://postgres@127.0.0.1/db?hostaddr=8.8.8.8",
        "postgres://postgres@127.0.0.1/db?host=/tmp",
    ] {
        let error = Config::from_values(
            Environment::Development,
            Values {
                database_url: Some(url.into()),
                ..Values::default()
            },
        )
        .err()
        .unwrap();
        assert!(!error.to_string().contains("MARKER") && !error.to_string().contains(url));
    }
    // Invalid numeric options never echo their value.
    for (field, value) in [
        ("max-connections", "0"),
        ("max-connections", "MARKER"),
        ("acquire-timeout", "99999999"),
        ("body-limit", "MARKER"),
        ("request-timeout", "999999999"),
        ("concurrency", "0"),
        ("shutdown-timeout", "MARKER"),
    ] {
        let values = Values {
            database_max_connections: field.eq("max-connections").then(|| value.into()),
            database_acquire_timeout_ms: field.eq("acquire-timeout").then(|| value.into()),
            body_limit_bytes: field.eq("body-limit").then(|| value.into()),
            request_timeout_ms: field.eq("request-timeout").then(|| value.into()),
            concurrency: field.eq("concurrency").then(|| value.into()),
            shutdown_timeout_ms: field.eq("shutdown-timeout").then(|| value.into()),
            ..Values::default()
        };
        let error = Config::from_values(Environment::Development, values)
            .err()
            .unwrap();
        assert!(!error.to_string().contains("MARKER") && !error.to_string().contains("99999999"));
    }
}

#[test]
fn production_configuration_requires_tls_and_cors() {
    // Loopback database without TLS is allowed in production (sidecar), but
    // CORS must be configured explicitly.
    assert!(matches!(
        Config::from_values(
            Environment::Production,
            Values {
                database_url: Some("postgres://postgres@127.0.0.1:5432/pass".into()),
                ..Values::default()
            }
        ),
        Err(config::ConfigError::ProductionCorsRequired)
    ));
    let production = Config::from_values(
        Environment::Production,
        Values {
            database_url: Some("postgres://postgres@127.0.0.1:5432/pass".into()),
            cors_origins: Some("https://vault.example".into()),
            ..Values::default()
        },
    )
    .unwrap();
    assert_eq!(production.cors_origins, ["https://vault.example"]);

    // Non-loopback host without TLS is rejected even with CORS configured.
    let remote = Values {
        database_url: Some("postgres://postgres@db.internal:5432/pass".into()),
        cors_origins: Some("https://vault.example".into()),
        ..Values::default()
    };
    assert!(matches!(
        Config::from_values(Environment::Production, remote.clone()),
        Err(config::ConfigError::ProductionTlsRequired)
    ));
    // Non-loopback host outside production is rejected regardless of TLS.
    assert!(matches!(
        Config::from_values(Environment::Development, remote),
        Err(config::ConfigError::DatabaseHostNotLoopback)
    ));
    // TLS without a readable PEM CA fails closed without echoing the path.
    let missing_ca = Values {
        database_url: Some("postgres://postgres@127.0.0.1:5432/pass".into()),
        cors_origins: Some("https://vault.example".into()),
        database_tls: Some("verify-full".into()),
        database_tls_ca_file: Some("/nonexistent/MARKER.pem".into()),
        ..Values::default()
    };
    let error = Config::from_values(Environment::Production, missing_ca)
        .err()
        .unwrap();
    assert_eq!(error, config::ConfigError::InvalidCaFile);
    assert!(!error.to_string().contains("MARKER"));
    // A CA file that exists but is not PEM fails closed too.
    let bad_ca = std::env::temp_dir().join("rust02-not-a-cert.pem");
    std::fs::write(&bad_ca, b"MARKER not a certificate").unwrap();
    let error = Config::from_values(
        Environment::Production,
        Values {
            database_url: Some("postgres://postgres@127.0.0.1:5432/pass".into()),
            cors_origins: Some("https://vault.example".into()),
            database_tls: Some("verify-full".into()),
            database_tls_ca_file: Some(bad_ca.to_string_lossy().into()),
            ..Values::default()
        },
    )
    .err()
    .unwrap();
    assert_eq!(error, config::ConfigError::InvalidCaFile);
    // Wildcard/path/query origins are rejected.
    for origins in [
        "*",
        "https://*.example",
        "https://vault.example/path",
        "https://vault.example?q=1",
        "MARKER",
    ] {
        assert_eq!(
            Config::from_values(
                Environment::Development,
                Values {
                    database_url: Some("postgres://postgres@127.0.0.1:1/db".into()),
                    cors_origins: Some(origins.into()),
                    ..Values::default()
                }
            )
            .err()
            .unwrap(),
            config::ConfigError::InvalidCorsOrigin,
            "origins {origins}"
        );
    }
}

#[tokio::test]
async fn health_endpoints_and_no_product_routes() {
    let config = config_with(Values::default());
    let state = state_for(&config);
    state.pool().close().await;
    let router = app(state.pool().clone(), &config_with(Values::default()));
    for (method, path, expected) in [
        ("GET", "/health/live", StatusCode::OK),
        ("GET", "/health/ready", StatusCode::SERVICE_UNAVAILABLE),
        ("POST", "/v1/auth/opaque/login", StatusCode::NOT_FOUND),
        ("GET", "/v1/vaults/unused/items", StatusCode::NOT_FOUND),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{method} {path}");
    }
}

#[tokio::test]
async fn request_ids_are_server_generated_and_client_values_ignored() {
    let config = config_with(Values::default());
    let state = state_for(&config);
    state.pool().close().await;
    let router = app(state.pool().clone(), &config);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .header("x-request-id", "UNTRUSTED_MARKER")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_owned();
    assert_ne!(id, "UNTRUSTED_MARKER");
    assert!(uuid::Uuid::parse_str(&id).is_ok(), "id {id} must be a UUID");
}

#[tokio::test]
async fn cors_allowlist_reflects_only_configured_origins() {
    let config = config_with(Values {
        cors_origins: Some("https://vault.example".into()),
        ..Values::default()
    });
    let state = state_for(&config);
    state.pool().close().await;
    let router = app(state.pool().clone(), &config);
    let allowed = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .header(header::ORIGIN, "https://vault.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        allowed.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&"https://vault.example".parse().unwrap())
    );
    let disallowed = router
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .header(header::ORIGIN, "https://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        disallowed
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
}

/// Body-consuming probe route used only to exercise the production stack.
async fn probe(State(_): State<zkpm_backend::AppState>, body: Bytes) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "length": body.len() }))
}

async fn sleeper(State(_): State<zkpm_backend::AppState>) -> StatusCode {
    tokio::time::sleep(Duration::from_secs(3)).await;
    StatusCode::OK
}

fn probe_router(state: zkpm_backend::AppState) -> Router {
    Router::new()
        .route("/probe", post(probe).get(sleeper))
        .with_state(state)
}

#[tokio::test]
async fn body_limit_rejects_oversized_payloads() {
    let config = config_with(Values {
        body_limit_bytes: Some("1024".into()),
        ..Values::default()
    });
    let state = state_for(&config);
    let router = harden(probe_router(state.clone()), &config, state);
    let ok = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/probe")
                .body(Body::from(vec![0u8; 512]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let rejected = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/probe")
                .body(Body::from(vec![0u8; 2048]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn request_timeout_bounds_slow_handlers() {
    let config = config_with(Values {
        request_timeout_ms: Some("1000".into()),
        ..Values::default()
    });
    let state = state_for(&config);
    let router = harden(probe_router(state.clone()), &config, state);
    let started = std::time::Instant::now();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/probe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(started.elapsed() < Duration::from_millis(2_500));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"], "timeout");
    assert!(parsed["requestId"].as_str().is_some());
}

#[tokio::test]
async fn concurrency_limit_rejects_immediately_when_exhausted() {
    let config = config_with(Values {
        concurrency: Some("1".into()),
        ..Values::default()
    });
    let state = state_for(&config);
    let router = harden(probe_router(state.clone()), &config, state);
    let first = router.clone().oneshot(
        Request::builder()
            .uri("/probe")
            .body(Body::empty())
            .unwrap(),
    );
    let second = router.oneshot(
        Request::builder()
            .uri("/probe")
            .body(Body::empty())
            .unwrap(),
    );
    let (first, second) = tokio::join!(first, second);
    let statuses = [first.unwrap().status(), second.unwrap().status()];
    assert!(statuses.contains(&StatusCode::OK));
    assert!(statuses.contains(&StatusCode::SERVICE_UNAVAILABLE));
}

#[tokio::test]
async fn internal_errors_map_to_generic_api_error_bodies() {
    let config = config_with(Values::default());
    let state = state_for(&config);
    state.pool().close().await;
    // Closed pool => readiness fails with a generic ApiError body.
    let response = app(state.pool().clone(), &config)
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"], "unavailable");
    assert!(parsed["requestId"].as_str().is_some());
    assert!(parsed["message"].as_str().is_some());
}

// ---- DTO skeleton tests (OpenAPI shape parity) ----

#[test]
fn dto_validators_match_contract_patterns() {
    assert!(dto::validate_id("a"));
    assert!(dto::validate_id("A-b_9"));
    assert!(dto::validate_id(&"a".repeat(128)));
    for bad in ["", "-a", "_a", "a b", "a/b", &"a".repeat(129), "äg"] {
        assert!(!dto::validate_id(bad), "{bad:?}");
    }
    assert!(dto::validate_b64("b64:QUJD"));
    assert!(dto::validate_b64("b64:QUJDRA=="));
    assert!(dto::validate_b64("b64:QUJDREY="));
    for bad in [
        "",
        "QUJD",
        "b64:",
        "b64:QUJD=",
        "b64:QU_JD",
        "b64:QUJDRE==",
        "b64:QUJDREY",
        "b64:-_",
    ] {
        assert!(!dto::validate_b64(bad), "{bad:?}");
    }
    assert!(dto::validate_datetime("2026-09-06T12:00:00Z"));
    assert!(dto::validate_datetime("2026-09-06T12:00:00+03:00"));
    assert!(!dto::validate_datetime("2026-09-06"));
    assert!(!dto::validate_datetime("not-a-date"));
}

#[test]
fn dto_serialization_uses_contract_field_names() {
    let mutation = dto::Mutation {
        mutation_id: "m1".into(),
        item_id: "i1".into(),
        vault_id: "v1".into(),
        base_revision: 0,
        ciphertext: "b64:QUJD".into(),
        envelope_version: dto::ENVELOPE_VERSION.into(),
        deleted: false,
    };
    let value = serde_json::to_value(&mutation).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "mutationId": "m1", "itemId": "i1", "vaultId": "v1",
            "baseRevision": 0, "ciphertext": "b64:QUJD",
            "envelopeVersion": "crypto-envelope/v1", "deleted": false
        })
    );
}

#[test]
fn dto_deserialization_rejects_unknown_fields_and_bad_consts() {
    let legacy: Result<dto::DeviceCreate, _> =
        serde_json::from_str(r#"{"name":"n","publicKey":"b64:QUJD","extra":1}"#);
    assert!(legacy.is_err(), "unknown fields must be rejected");
    let legacy_ok: dto::DeviceCreate =
        serde_json::from_str(r#"{"name":"n","publicKey":"b64:QUJD"}"#).unwrap();
    assert!(matches!(legacy_ok, dto::DeviceCreate::LegacyPublicKey(_)));
    let bearer_ok: dto::DeviceCreate =
        serde_json::from_str(r#"{"name":"n","enrollmentMode":"bearer-session-v1"}"#).unwrap();
    assert!(matches!(bearer_ok, dto::DeviceCreate::BearerSession(_)));
    let bad_const: Result<dto::DeviceCreate, _> =
        serde_json::from_str(r#"{"name":"n","enrollmentMode":"legacy"}"#);
    assert!(
        bad_const.is_err(),
        "const value must be rejected: {bad_const:?}"
    );
    // A body carrying fields of both variants resolves to the legacy shape;
    // the bearer variant tolerates no extra keys of its own.
    let bearer_extra: Result<dto::DeviceCreate, _> =
        serde_json::from_str(r#"{"name":"n","enrollmentMode":"bearer-session-v1","other":1}"#);
    assert!(
        bearer_extra.is_err(),
        "unknown fields must be rejected: {bearer_extra:?}"
    );
    let bundle: Result<dto::KeyBundle, _> =
        serde_json::from_str(r#"{"bundle":"not-b64","version":1,"x":0}"#);
    assert!(bundle.is_err());
}

#[test]
fn request_id_generation_is_fresh_uuid_v4() {
    let first = request_id::generate();
    let second = request_id::generate();
    assert_ne!(first.value(), second.value());
    assert_eq!(
        uuid::Uuid::parse_str(first.value())
            .unwrap()
            .get_version_num(),
        4
    );
    assert_eq!(request_id::current(), "startup");
}
