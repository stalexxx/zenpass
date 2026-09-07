//! Real PostgreSQL 16 integration tests for the ported auth/devices/account/
//! sync product surface (RUST-03). Explicitly `--ignored`; run with
//! `RUST_TEST_DATABASE_URL` pointing at a dedicated disposable instance
//! (never production, never shared with the Bun backend's own database).
//!
//! Every test gets a fresh, isolated database (migrated from this crate's
//! own `migrations/`) and drives the HTTP surface exactly as a real client
//! would, including running the real OPAQUE protocol client-side via
//! `crypto_core` (never a mock/stub of the crypto).

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use zkpm_backend::config::{Config, Environment, Values};
use zkpm_backend::{app, migrate};

const BASE_URL_ENV: &str = "RUST_TEST_DATABASE_URL";
const OPAQUE_CONTEXT: &[u8] = b"zkpm-opaque-v1";

fn base_url() -> String {
    std::env::var(BASE_URL_ENV).unwrap_or_else(|_| {
        panic!("{BASE_URL_ENV} is required: dedicated disposable PostgreSQL only")
    })
}

fn rewrite_database(url: &str, database: &str) -> String {
    let (prefix, _) = url.rsplit_once('/').unwrap();
    format!("{prefix}/{database}")
}

struct TestDatabase {
    url: String,
    name: String,
}

impl TestDatabase {
    async fn create(prefix: &str) -> Self {
        let name = format!(
            "rust03_{prefix}_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&base_url())
            .await
            .expect("connect to disposable test server");
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&pool)
            .await
            .expect("create test database");
        pool.close().await;
        let url = rewrite_database(&base_url(), &name);
        let migrate_pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect to fresh test database");
        migrate::run(&migrate_pool).await.expect("run migrations");
        migrate_pool.close().await;
        Self { url, name }
    }

    async fn pool(&self) -> PgPool {
        PgPoolOptions::new()
            .max_connections(8)
            .connect(&self.url)
            .await
            .unwrap()
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let base = base_url();
        let name = self.name.clone();
        // Best-effort cleanup on a throwaway runtime: tests are `--ignored`
        // and run against a disposable container, so a leaked database on a
        // rare panic is acceptable and never touches production.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                if let Ok(pool) = PgPoolOptions::new().max_connections(1).connect(&base).await {
                    let _ = sqlx::query(&format!(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}' AND pid <> pg_backend_pid()"
                    ))
                    .execute(&pool)
                    .await;
                    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {name}"))
                        .execute(&pool)
                        .await;
                    pool.close().await;
                }
            });
        })
        .join()
        .ok();
    }
}

fn test_config(db_url: &str, values: Values) -> Config {
    let mut values = values;
    values.database_url = Some(db_url.to_owned());
    Config::from_values(Environment::Test, values).expect("valid test config")
}

fn b64(bytes: &[u8]) -> String {
    format!(
        "b64:{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

fn decode_b64(value: &str) -> Vec<u8> {
    let body = value.strip_prefix("b64:").expect("b64 prefix");
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("valid base64")
}

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&value).unwrap())
        }
        None => Body::empty(),
    };
    let response = router
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

/// Drives a full OPAQUE registration for `account_id`/`password` against the
/// real HTTP surface, using the real client-side protocol from crypto-core
/// (never a stub).
async fn register(router: &axum::Router, account_id: &str, password: &[u8]) {
    let start = crypto_core::opaque::client_registration_start(password).unwrap();
    let (status, body) = send(
        router,
        "POST",
        "/auth/opaque/register",
        None,
        Some(json!({"accountId": account_id, "clientMessage": b64(&start.message)})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let server_response = decode_b64(body["message"].as_str().unwrap());

    let state = crypto_core::opaque::client_registration_state(&start.state_bytes()).unwrap();
    let finish =
        crypto_core::opaque::client_registration_finish(state, password, &server_response).unwrap();
    let (status, _) = send(
        router,
        "POST",
        "/auth/opaque/register",
        None,
        Some(json!({"accountId": account_id, "clientMessage": b64(&finish.message)})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

/// Drives a full OPAQUE login, returning the issued bearer access token.
async fn login(router: &axum::Router, account_id: &str, password: &[u8]) -> String {
    let start = crypto_core::opaque::client_login_start(password).unwrap();
    let (status, body) = send(
        router,
        "POST",
        "/auth/opaque/login",
        None,
        Some(json!({"accountId": account_id, "clientMessage": b64(&start.message)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "leg1: {body}");
    let ke2 = decode_b64(body["message"].as_str().unwrap());

    let state = crypto_core::opaque::client_login_state(&start.state_bytes()).unwrap();
    let finish =
        crypto_core::opaque::client_login_finish(state, password, &ke2, OPAQUE_CONTEXT).unwrap();
    let (status, body) = send(
        router,
        "POST",
        "/auth/opaque/login",
        None,
        Some(json!({"accountId": account_id, "clientMessage": b64(&finish.message)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "leg2: {body}");
    body["accessToken"].as_str().unwrap().to_owned()
}

fn router_for(pool: PgPool, config: &Config) -> axum::Router {
    app(pool, config)
}

#[tokio::test]
#[ignore]
async fn registration_and_login_round_trip_then_refresh_and_logout() {
    let db = TestDatabase::create("auth1").await;
    let config = test_config(&db.url, Values::default());
    let router = router_for(db.pool().await, &config);

    register(&router, "acct-alice", b"CorrectHorseBatteryStaple").await;
    let token = login(&router, "acct-alice", b"CorrectHorseBatteryStaple").await;

    // A device-unbound session cannot refresh.
    let (status, _) = send(&router, "POST", "/auth/refresh", Some(&token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Enroll bearer-session-v1 device using the freshly issued session.
    let (status, device) = send(
        &router,
        "POST",
        "/devices",
        Some(&token),
        Some(json!({"name": "laptop", "enrollmentMode": "bearer-session-v1"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{device}");

    // Now refresh succeeds and rotates the token.
    let (status, refreshed) = send(&router, "POST", "/auth/refresh", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let new_token = refreshed["accessToken"].as_str().unwrap().to_owned();
    assert_ne!(new_token, token);

    // The original (pre-rotation) token is now dead.
    let (status, _) = send(&router, "GET", "/devices", Some(&token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The new token still works.
    let (status, _) = send(&router, "GET", "/devices", Some(&new_token), None).await;
    assert_eq!(status, StatusCode::OK);

    // Logout revokes it.
    let (status, _) = send(&router, "POST", "/auth/logout", Some(&new_token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&router, "GET", "/devices", Some(&new_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore]
async fn concurrent_refresh_produces_exactly_one_successor() {
    let db = TestDatabase::create("auth2").await;
    let config = test_config(&db.url, Values::default());
    let router = router_for(db.pool().await, &config);

    register(&router, "acct-race", b"CorrectHorseBatteryStaple").await;
    let token = login(&router, "acct-race", b"CorrectHorseBatteryStaple").await;
    let (status, _) = send(
        &router,
        "POST",
        "/devices",
        Some(&token),
        Some(json!({"name": "laptop", "enrollmentMode": "bearer-session-v1"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let mut handles = Vec::new();
    for _ in 0..5 {
        let router = router.clone();
        let token = token.clone();
        handles.push(tokio::spawn(async move {
            send(&router, "POST", "/auth/refresh", Some(&token), None).await
        }));
    }
    let mut ok_count = 0;
    for handle in handles {
        let (status, _) = handle.await.unwrap();
        if status == StatusCode::OK {
            ok_count += 1;
        } else {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }
    assert_eq!(ok_count, 1, "exactly one concurrent refresh must succeed");
}

#[tokio::test]
#[ignore]
async fn wrong_password_and_unknown_account_fail_generically() {
    let db = TestDatabase::create("auth3").await;
    let config = test_config(&db.url, Values::default());
    let router = router_for(db.pool().await, &config);

    register(&router, "acct-bob", b"CorrectHorseBatteryStaple").await;

    // Wrong password: leg1 succeeds (indistinguishable from real, since the
    // server hasn't seen the password yet). The real OPAQUE protocol then
    // detects a wrong password *client-side*, while verifying the server's
    // envelope during `client_login_finish` -- so a genuine client never
    // even sends a leg-2 request for a wrong password. That's a real
    // security property (the server never observes a failed guess this
    // way), and is asserted here directly.
    let start = crypto_core::opaque::client_login_start(b"WrongPassword").unwrap();
    let (status, body) = send(
        &router,
        "POST",
        "/auth/opaque/login",
        None,
        Some(json!({"accountId": "acct-bob", "clientMessage": b64(&start.message)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ke2 = decode_b64(body["message"].as_str().unwrap());
    let state = crypto_core::opaque::client_login_state(&start.state_bytes()).unwrap();
    assert_eq!(
        crypto_core::opaque::client_login_finish(state, b"WrongPassword", &ke2, OPAQUE_CONTEXT)
            .unwrap_err(),
        crypto_core::Error::AuthenticationFailed
    );

    // The aborted attempt above left real pending server state for
    // "acct-bob" (one login attempt at a time per account, TTL-bounded --
    // ADR-0006 §6, ported unchanged). Finishing it with a syntactically
    // valid-length but garbage KE3 (as a tampering/replay attacker would,
    // bypassing the real client) is a server-side generic failure, and
    // consumes the pending state.
    let garbage_ke3 = vec![0u8; 64];
    let (status, body) = send(
        &router,
        "POST",
        "/auth/opaque/login",
        None,
        Some(json!({"accountId": "acct-bob", "clientMessage": b64(&garbage_ke3)})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "authentication_failed");

    // The account still logs in normally afterward with the correct password.
    let token = login(&router, "acct-bob", b"CorrectHorseBatteryStaple").await;
    assert!(!token.is_empty());

    // Unknown account: same-shaped 200 decoy KE2, then generic 401 on leg2.
    let start = crypto_core::opaque::client_login_start(b"whatever").unwrap();
    let (status, body) = send(
        &router,
        "POST",
        "/auth/opaque/login",
        None,
        Some(json!({"accountId": "acct-does-not-exist", "clientMessage": b64(&start.message)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let decoy = decode_b64(body["message"].as_str().unwrap());
    assert_eq!(decoy.len(), 320);
    let (status, body) = send(
        &router,
        "POST",
        "/auth/opaque/login",
        None,
        Some(json!({"accountId": "acct-does-not-exist", "clientMessage": b64(&decoy)})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "authentication_failed");

    // Malformed request bodies are rejected generically too.
    let (status, body) = send(
        &router,
        "POST",
        "/auth/opaque/login",
        None,
        Some(json!({"accountId": "not valid!!", "clientMessage": "b64:???"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "authentication_failed");
}

#[tokio::test]
#[ignore]
async fn device_enrollment_and_revoke_cascades_sessions() {
    let db = TestDatabase::create("dev1").await;
    let config = test_config(&db.url, Values::default());
    let router = router_for(db.pool().await, &config);

    register(&router, "acct-carol", b"CorrectHorseBatteryStaple").await;
    let token = login(&router, "acct-carol", b"CorrectHorseBatteryStaple").await;

    let (status, device) = send(
        &router,
        "POST",
        "/devices",
        Some(&token),
        Some(json!({"name": "phone", "enrollmentMode": "bearer-session-v1"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let device_id = device["deviceId"].as_str().unwrap().to_owned();

    // A second enrollment attempt on the same (now-bound) session is rejected generically.
    let (status, _) = send(
        &router,
        "POST",
        "/devices",
        Some(&token),
        Some(json!({"name": "phone-2", "enrollmentMode": "bearer-session-v1"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, list) = send(&router, "GET", "/devices", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["devices"].as_array().unwrap().len(), 1);

    let (status, _) = send(
        &router,
        "POST",
        &format!("/devices/{device_id}/revoke"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Revoking the device revokes its (only) bound session too.
    let (status, _) = send(&router, "GET", "/devices", Some(&token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Revoking an already-revoked / unknown device is a generic 404.
    let token2 = login(&router, "acct-carol", b"CorrectHorseBatteryStaple").await;
    let (status, _) = send(
        &router,
        "POST",
        &format!("/devices/{device_id}/revoke"),
        Some(&token2),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore]
async fn cross_account_isolation_for_devices_and_key_bundle() {
    let db = TestDatabase::create("iso1").await;
    let config = test_config(&db.url, Values::default());
    let router = router_for(db.pool().await, &config);

    register(&router, "acct-dave", b"CorrectHorseBatteryStaple").await;
    register(&router, "acct-erin", b"CorrectHorseBatteryStaple").await;
    let dave = login(&router, "acct-dave", b"CorrectHorseBatteryStaple").await;
    let erin = login(&router, "acct-erin", b"CorrectHorseBatteryStaple").await;

    let (status, device) = send(
        &router,
        "POST",
        "/devices",
        Some(&dave),
        Some(json!({"name": "dave-laptop", "enrollmentMode": "bearer-session-v1"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let device_id = device["deviceId"].as_str().unwrap().to_owned();

    // Erin cannot see Dave's devices.
    let (status, list) = send(&router, "GET", "/devices", Some(&erin), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["devices"].as_array().unwrap().len(), 0);

    // Erin cannot revoke Dave's device (generic not-found, no ownership leak).
    let (status, _) = send(
        &router,
        "POST",
        &format!("/devices/{device_id}/revoke"),
        Some(&erin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Erin has no key bundle of her own yet.
    let (status, _) = send(&router, "GET", "/account/key-bundle", Some(&erin), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let bundle = bundle_json("acct-dave", "vault1", "item1");
    let (status, _) = send(
        &router,
        "PUT",
        "/account/key-bundle",
        Some(&dave),
        Some(json!({"bundle": b64(bundle.as_bytes()), "version": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Erin publishing a bundle whose embedded accountId is Dave's is rejected.
    let (status, _) = send(
        &router,
        "PUT",
        "/account/key-bundle",
        Some(&erin),
        Some(json!({"bundle": b64(bundle.as_bytes()), "version": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

fn bundle_json(account_id: &str, vault_id: &str, item_id: &str) -> String {
    let wrapper = b64(b"wrapper-bytes");
    let kdf = b64(b"kdf-bytes");
    format!(
        "{{\"format\":\"c04-account-bundle/1\",\"accountId\":\"{account_id}\",\"vaultId\":\"{vault_id}\",\"itemId\":\"{item_id}\",\"kdfParametersCbor\":\"{kdf}\",\"wrappedAccountKey\":\"{wrapper}\",\"wrappedVaultKey\":\"{wrapper}\",\"wrappedItemKey\":\"{wrapper}\",\"wrappedRecoveryKey\":\"{wrapper}\"}}"
    )
}

#[tokio::test]
#[ignore]
async fn key_bundle_compare_and_swap() {
    let db = TestDatabase::create("kb1").await;
    let config = test_config(&db.url, Values::default());
    let router = router_for(db.pool().await, &config);

    register(&router, "acct-frank", b"CorrectHorseBatteryStaple").await;
    let token = login(&router, "acct-frank", b"CorrectHorseBatteryStaple").await;

    let v1 = bundle_json("acct-frank", "vault1", "item1");
    let (status, _) = send(
        &router,
        "PUT",
        "/account/key-bundle",
        Some(&token),
        Some(json!({"bundle": b64(v1.as_bytes()), "version": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Idempotent replay of the exact same version+bytes.
    let (status, _) = send(
        &router,
        "PUT",
        "/account/key-bundle",
        Some(&token),
        Some(json!({"bundle": b64(v1.as_bytes()), "version": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = send(&router, "GET", "/account/key-bundle", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 1);

    // Stale version is a conflict, embedding the current version.
    let (status, body) = send(
        &router,
        "PUT",
        "/account/key-bundle",
        Some(&token),
        Some(json!({"bundle": b64(v1.as_bytes()), "version": 5})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["currentVersion"], 1);

    // version+1 with new bytes replaces.
    let v2 = bundle_json("acct-frank", "vault2", "item2");
    let (status, _) = send(
        &router,
        "PUT",
        "/account/key-bundle",
        Some(&token),
        Some(json!({"bundle": b64(v2.as_bytes()), "version": 2})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = send(&router, "GET", "/account/key-bundle", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 2);
}

#[tokio::test]
#[ignore]
async fn sync_mutation_conflict_replay_and_tombstones() {
    let db = TestDatabase::create("sync1").await;
    let config = test_config(&db.url, Values::default());
    let router = router_for(db.pool().await, &config);

    register(&router, "acct-grace", b"CorrectHorseBatteryStaple").await;
    let token = login(&router, "acct-grace", b"CorrectHorseBatteryStaple").await;

    // Reading a vault that doesn't exist yet is a 404, and must not create it.
    let (status, _) = send(&router, "GET", "/vaults/vaultA/changes", Some(&token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // First write auto-creates the vault (owned by the caller).
    let mutation1 = json!({
        "mutationId": "mut-1",
        "itemId": "item-1",
        "vaultId": "vaultA",
        "baseRevision": 0,
        "ciphertext": b64(b"ciphertext-v1"),
        "envelopeVersion": "crypto-envelope/v1",
        "deleted": false,
    });
    let (status, body) = send(
        &router,
        "POST",
        "/vaults/vaultA/items",
        Some(&token),
        Some(mutation1.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["revision"], 1);

    // Replaying the same mutationId returns the exact original response, not a
    // fresh write or a conflict.
    let (status, replay) = send(
        &router,
        "POST",
        "/vaults/vaultA/items",
        Some(&token),
        Some(mutation1.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(replay, body);

    // A stale baseRevision is a conflict embedding the current item.
    let stale = json!({
        "mutationId": "mut-2",
        "itemId": "item-1",
        "vaultId": "vaultA",
        "baseRevision": 0,
        "ciphertext": b64(b"ciphertext-v2"),
        "envelopeVersion": "crypto-envelope/v1",
        "deleted": false,
    });
    let (status, conflict) = send(
        &router,
        "POST",
        "/vaults/vaultA/items",
        Some(&token),
        Some(stale),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict["current"]["revision"], 1);

    // The correct next revision succeeds.
    let mutation2 = json!({
        "mutationId": "mut-3",
        "itemId": "item-1",
        "vaultId": "vaultA",
        "baseRevision": 1,
        "ciphertext": b64(b"ciphertext-v2"),
        "envelopeVersion": "crypto-envelope/v1",
        "deleted": false,
    });
    let (status, body) = send(
        &router,
        "POST",
        "/vaults/vaultA/items",
        Some(&token),
        Some(mutation2),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["revision"], 2);

    // Deleting (tombstoning) still increments revision and remains visible in
    // the change feed.
    let mutation3 = json!({
        "mutationId": "mut-4",
        "itemId": "item-1",
        "vaultId": "vaultA",
        "baseRevision": 2,
        "ciphertext": b64(b"tombstone"),
        "envelopeVersion": "crypto-envelope/v1",
        "deleted": true,
    });
    let (status, body) = send(
        &router,
        "POST",
        "/vaults/vaultA/items",
        Some(&token),
        Some(mutation3),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["revision"], 3);
    assert_eq!(body["deleted"], true);

    let (status, page) = send(&router, "GET", "/vaults/vaultA/changes", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let changes = page["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["deleted"], true);

    // Pagination: cursor from the first page, using limit=1, must terminate.
    let next_cursor = page["nextCursor"].as_str().unwrap().to_owned();
    let (status, page2) = send(
        &router,
        "GET",
        &format!("/vaults/vaultA/changes?cursor={next_cursor}&limit=1"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page2["changes"].as_array().unwrap().len(), 0);
    assert_eq!(page2["nextCursor"].as_str().unwrap(), next_cursor);
}

#[tokio::test]
#[ignore]
async fn sync_vault_ownership_is_first_write_wins_and_isolated() {
    let db = TestDatabase::create("sync2").await;
    let config = test_config(&db.url, Values::default());
    let router = router_for(db.pool().await, &config);

    register(&router, "acct-henry", b"CorrectHorseBatteryStaple").await;
    register(&router, "acct-iris", b"CorrectHorseBatteryStaple").await;
    let henry = login(&router, "acct-henry", b"CorrectHorseBatteryStaple").await;
    let iris = login(&router, "acct-iris", b"CorrectHorseBatteryStaple").await;

    let mutation = json!({
        "mutationId": "mut-a",
        "itemId": "item-1",
        "vaultId": "shared-vault",
        "baseRevision": 0,
        "ciphertext": b64(b"payload"),
        "envelopeVersion": "crypto-envelope/v1",
        "deleted": false,
    });
    let (status, _) = send(
        &router,
        "POST",
        "/vaults/shared-vault/items",
        Some(&henry),
        Some(mutation),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Iris cannot write into Henry's vault (first-write-wins ownership).
    let mutation2 = json!({
        "mutationId": "mut-b",
        "itemId": "item-2",
        "vaultId": "shared-vault",
        "baseRevision": 0,
        "ciphertext": b64(b"payload"),
        "envelopeVersion": "crypto-envelope/v1",
        "deleted": false,
    });
    let (status, _) = send(
        &router,
        "POST",
        "/vaults/shared-vault/items",
        Some(&iris),
        Some(mutation2),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // And cannot read its change feed either.
    let (status, _) = send(
        &router,
        "GET",
        "/vaults/shared-vault/changes",
        Some(&iris),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
