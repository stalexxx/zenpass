//! Real PostgreSQL 16 integration tests (explicitly `--ignored`; run with
//! `RUST_TEST_DATABASE_URL` pointing at a dedicated disposable instance).
//! Never connects to production and never reads user data: every test gets a
//! private database and cleans up after itself.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use sqlx::{PgPool, postgres::PgPoolOptions};
use zkpm_backend::config::{Config, DatabaseTls, Environment, Values};

const BASE_URL_ENV: &str = "RUST_TEST_DATABASE_URL";
const MIGRATIONS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
/// The exact legacy-runner DDL from apps/backend/src/db.mjs.
const LEGACY_DDL: &str = "CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())";

fn base_url() -> String {
    std::env::var(BASE_URL_ENV).unwrap_or_else(|_| {
        panic!("{BASE_URL_ENV} is required: dedicated disposable PostgreSQL only")
    })
}

async fn base_pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&base_url())
        .await
        .expect("connect to disposable test server")
}

struct TestDatabase {
    url: String,
    name: String,
}

impl TestDatabase {
    async fn create(prefix: &str) -> Self {
        let name = format!("rust02_{}_{}", prefix, std::process::id());
        let pool = base_pool().await;
        sqlx::query(&format!("DROP DATABASE IF EXISTS {name}"))
            .execute(&pool)
            .await
            .expect("drop stale test database");
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&pool)
            .await
            .expect("create test database");
        pool.close().await;
        let url = rewrite_database(&base_url(), &name);
        Self { url, name }
    }

    async fn pool(&self) -> PgPool {
        PgPoolOptions::new()
            .max_connections(4)
            .connect(&self.url)
            .await
            .unwrap()
    }

    async fn drop(self) {
        let pool = base_pool().await;
        let _ = sqlx::query(&format!(
            "SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity \
             WHERE datname = '{}' AND pid <> pg_backend_pid()",
            self.name
        ))
        .execute(&pool)
        .await;
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {}", self.name))
            .execute(&pool)
            .await;
        pool.close().await;
    }
}

fn rewrite_database(url: &str, database: &str) -> String {
    let (prefix, _) = url.rsplit_once('/').unwrap();
    format!("{prefix}/{database}")
}

fn migration_files() -> Vec<(String, String, String)> {
    let mut files: Vec<(String, String, String)> = std::fs::read_dir(MIGRATIONS_DIR)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_str()?.to_owned();
            if name.ends_with(".sql") {
                Some((
                    name.split('_').next().unwrap().to_owned(),
                    name,
                    std::fs::read_to_string(&path).ok()?,
                ))
            } else {
                None
            }
        })
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        files
            .iter()
            .map(|(version, _, _)| version.as_str())
            .collect::<Vec<_>>(),
        ["0001", "0002", "0003", "0004", "0005"],
        "test expects the current five-migration baseline"
    );
    files
}

/// Faithful reimplementation of the old Bun runner (apps/backend/src/db.mjs)
/// applying the first `count` files transactionally.
async fn legacy_runner(pool: &PgPool, count: usize) {
    sqlx::raw_sql(LEGACY_DDL).execute(pool).await.unwrap();
    for (zero_padded, _name, sql) in migration_files().into_iter().take(count) {
        let version = zero_padded.trim_start_matches('0');
        let version = if version.is_empty() { "0" } else { version };
        // db.mjs stores the filename prefix without leading zeros ("001").
        let legacy_version = format!("{:03}", version.parse::<u32>().unwrap());
        let exists: bool = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)",
        )
        .bind(&legacy_version)
        .fetch_one(pool)
        .await
        .unwrap();
        if exists {
            continue;
        }
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(&sql).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO schema_migrations(version) VALUES ($1)")
            .bind(&legacy_version)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
}

fn config_for(url: &str) -> Config {
    Config::from_values(
        Environment::Development,
        Values {
            database_url: Some(url.to_owned()),
            ..Values::default()
        },
    )
    .unwrap()
}

async fn migrate(
    config: &Config,
) -> Result<zkpm_backend::migrate::Outcome, zkpm_backend::migrate::MigrateError> {
    zkpm_backend::migrate::run(&zkpm_backend::migrate::migration_pool(config).await.unwrap()).await
}

async fn sqlx_versions(pool: &PgPool) -> Vec<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn legacy_versions(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>("SELECT version FROM schema_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn assert_full_schema(pool: &PgPool) {
    let tables: Vec<String> = sqlx::query_scalar::<_, String>(
        "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT IN ('schema_migrations','_sqlx_migrations') ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        tables,
        [
            "accounts",
            "auth_rate_limits",
            "devices",
            "key_bundles",
            "mutation_outcomes",
            "opaque_credentials",
            "sessions",
            "vault_items",
            "vaults",
        ]
    );
    let issued: String = sqlx::query_scalar::<_, String>(
        "SELECT data_type FROM information_schema.columns WHERE table_name='sessions' AND column_name='issued_via'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(issued, "character varying");
}

async fn old_backend_compatibility(pool: &PgPool) {
    // The old Bun runner skips a file iff its version string is already in
    // schema_migrations; all five must therefore be present, or the old
    // server would replay historical DDL and crash on existing objects.
    assert_eq!(
        legacy_versions(pool).await,
        ["001", "002", "003", "004", "005"]
    );
}

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL; run explicitly with --ignored"]
async fn fresh_database_applies_all_migrations_and_legacy_history() {
    let database = TestDatabase::create("fresh").await;
    let pool = database.pool().await;
    let outcome = migrate(&config_for(&database.url))
        .await
        .expect("fresh migrate");
    assert_eq!(outcome.applied, [1, 2, 3, 4, 5]);
    assert_eq!(outcome.adopted, 0);
    assert!(!outcome.up_to_date);
    assert_eq!(sqlx_versions(&pool).await, [1, 2, 3, 4, 5]);
    assert_full_schema(&pool).await;
    old_backend_compatibility(&pool).await;
    pool.close().await;
    database.drop().await;
}

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL; run explicitly with --ignored"]
async fn full_legacy_history_is_adopted_without_replaying_ddl() {
    let database = TestDatabase::create("adopt").await;
    let pool = database.pool().await;
    legacy_runner(&pool, 5).await;
    // Simulate an old deployment holding data: prove no destructive replay.
    sqlx::query("INSERT INTO accounts (account_id) VALUES ('adopt_probe')")
        .execute(&pool)
        .await
        .unwrap();
    let before: Vec<(String, String)> =
        sqlx::query_as("SELECT version, applied_at::text FROM schema_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    let schema_birth: String = sqlx::query_scalar::<_, String>(
        "SELECT obj_description('accounts'::regclass, 'pg_class') IS NULL, 'x' FROM pg_class WHERE relname='accounts'",
    )
    .fetch_one(&pool)
    .await
    .unwrap_or_else(|_| "x".into());

    let outcome = migrate(&config_for(&database.url)).await.expect("adoption");
    assert_eq!(outcome.adopted, 5);
    assert!(outcome.applied.is_empty());
    assert!(outcome.up_to_date);

    // No historical DDL was replayed: pre-existing row intact, history rows
    // untouched (same timestamps), and SQLx checksums validated cleanly.
    let after: Vec<(String, String)> =
        sqlx::query_as("SELECT version, applied_at::text FROM schema_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(before, after);
    let kept: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM accounts WHERE account_id = 'adopt_probe'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kept, 1);
    assert_eq!(sqlx_versions(&pool).await, [1, 2, 3, 4, 5]);
    assert_full_schema(&pool).await;
    old_backend_compatibility(&pool).await;
    let _ = schema_birth;
    pool.close().await;
    database.drop().await;
}

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL; run explicitly with --ignored"]
async fn partial_legacy_history_is_adopted_then_completed() {
    let database = TestDatabase::create("partial").await;
    let pool = database.pool().await;
    // An older deployment that only ever ran migrations 001..003.
    legacy_runner(&pool, 3).await;
    let outcome = migrate(&config_for(&database.url))
        .await
        .expect("adopt+apply");
    assert_eq!(outcome.adopted, 3);
    assert_eq!(outcome.applied, [4, 5]);
    assert_eq!(sqlx_versions(&pool).await, [1, 2, 3, 4, 5]);
    assert_full_schema(&pool).await;
    old_backend_compatibility(&pool).await;
    pool.close().await;
    database.drop().await;
}

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL; run explicitly with --ignored"]
async fn rerunning_migrate_is_a_safe_no_op() {
    let database = TestDatabase::create("rerun").await;
    let pool = database.pool().await;
    migrate(&config_for(&database.url)).await.unwrap();
    let outcome = migrate(&config_for(&database.url)).await.expect("re-run");
    assert!(outcome.up_to_date);
    assert!(outcome.applied.is_empty());
    assert_eq!(outcome.adopted, 0);
    assert_full_schema(&pool).await;
    old_backend_compatibility(&pool).await;
    pool.close().await;
    database.drop().await;
}

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL; run explicitly with --ignored"]
async fn schema_drift_blocks_adoption_and_changes_nothing() {
    let database = TestDatabase::create("drift").await;
    let pool = database.pool().await;
    legacy_runner(&pool, 5).await;
    // Undocumented drift: a column the baseline never contained.
    sqlx::query("ALTER TABLE accounts ADD COLUMN drift_marker integer")
        .execute(&pool)
        .await
        .unwrap();
    let error = migrate(&config_for(&database.url))
        .await
        .expect_err("drift must be rejected");
    assert_eq!(error.code(), "schema_drift");
    assert!(error.to_string().contains("columns"));
    // Nothing was adopted and the drift remains visible for operators.
    let sqlx_tables: bool = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='_sqlx_migrations')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!sqlx_tables, "no baseline may be written on drift");
    let column: bool = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='accounts' AND column_name='drift_marker')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(column);
    pool.close().await;
    database.drop().await;
}

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL; run explicitly with --ignored"]
async fn wrong_or_incomplete_legacy_history_is_rejected() {
    for (prefix, rows) in [
        (2, vec!["001", "003"]),
        (5, vec!["001", "002", "003", "004", "005", "999"]),
    ] {
        let database = TestDatabase::create("history").await;
        let pool = database.pool().await;
        legacy_runner(&pool, prefix).await;
        for row in &rows {
            sqlx::query(
                "INSERT INTO schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING",
            )
            .bind(row)
            .execute(&pool)
            .await
            .unwrap();
        }
        if prefix == 2 {
            sqlx::query("DELETE FROM schema_migrations WHERE version = '002'")
                .execute(&pool)
                .await
                .unwrap();
        }
        let error = migrate(&config_for(&database.url))
            .await
            .expect_err("bad history must be rejected");
        assert_eq!(error.code(), "history_mismatch");
        pool.close().await;
        database.drop().await;
    }
}

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL; run explicitly with --ignored"]
async fn partial_migration_failure_leaves_consistent_state() {
    let database = TestDatabase::create("fail").await;
    let pool = database.pool().await;
    // Pre-create a devices table whose enrollment_mode column collides with
    // migration 004 (001 uses IF NOT EXISTS, so 001-003 still succeed).
    sqlx::raw_sql(
        "CREATE TABLE devices (device_id varchar(128) PRIMARY KEY, account_id varchar(128) NOT NULL, \
         name varchar(128) NOT NULL, public_key bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), \
         last_seen_at timestamptz, revoked_at timestamptz, enrollment_mode varchar(32));",
    )
    .execute(&pool)
    .await
    .unwrap();
    let error = migrate(&config_for(&database.url))
        .await
        .expect_err("migration 004 must fail on the conflicting column");
    assert!(error.code() == "database_error" || error.code() == "runner_error");
    // Applied prefix is recorded and committed; the failing migration is not.
    assert_eq!(sqlx_versions(&pool).await, [1, 2, 3]);
    let issued: bool = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='sessions' AND column_name='issued_via')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!issued, "migration 005 must not have run");
    // The operator fix is removing the conflicting object: drop the
    // colliding column so migration 004 can add it itself, then resume.
    sqlx::query("ALTER TABLE devices DROP COLUMN enrollment_mode")
        .execute(&pool)
        .await
        .unwrap();
    migrate(&config_for(&database.url))
        .await
        .expect("resume after fix");
    assert_full_schema(&pool).await;
    pool.close().await;
    database.drop().await;
}

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL; run explicitly with --ignored"]
async fn concurrent_migration_processes_serialize_safely() {
    let database = TestDatabase::create("concurrent").await;
    let first = Command::new(env!("CARGO_BIN_EXE_zkpm-backend"))
        .arg("migrate")
        .env("ZKPM_DATABASE_URL", &database.url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let second = Command::new(env!("CARGO_BIN_EXE_zkpm-backend"))
        .arg("migrate")
        .env("ZKPM_DATABASE_URL", &database.url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let first_output = first.wait_with_output().unwrap();
    let second_output = second.wait_with_output().unwrap();
    assert!(first_output.status.success(), "first: {first_output:?}");
    assert!(second_output.status.success(), "second: {second_output:?}");
    let pool = database.pool().await;
    assert_eq!(sqlx_versions(&pool).await, [1, 2, 3, 4, 5]);
    assert_full_schema(&pool).await;
    old_backend_compatibility(&pool).await;
    pool.close().await;
    database.drop().await;
}

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL; run explicitly with --ignored"]
async fn healthcheck_and_readiness_transitions() {
    let database = TestDatabase::create("health").await;
    let config = config_for(&database.url);
    migrate(&config).await.unwrap();
    let pool = zkpm_backend::migrate::migration_pool(&config)
        .await
        .unwrap();
    assert!(zkpm_backend::migrate::healthcheck(&pool).await);
    pool.close().await;

    // Real HTTP readiness transitions on a real server process: pause the
    // database container, observe bounded 503, resume, observe 200 again.
    let container = format!("rust02-pg-pause-{}", std::process::id());
    let port = free_port();
    let status = Command::new("docker")
        .args([
            "run",
            "--detach",
            "--name",
            &container,
            "--env",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "--publish",
            &format!("127.0.0.1:{port}:5432"),
            "postgres:16-alpine",
        ])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "disposable pause-test container failed to start"
    );
    let paused_url = format!("postgres://postgres@127.0.0.1:{port}/postgres");
    let cleanup = |container: &str| {
        let _ = Command::new("docker")
            .args(["rm", "--force", container])
            .status();
    };
    wait_for_postgres(&paused_url, Duration::from_secs(30)).await;
    let http_port = free_port();
    let bind = format!("127.0.0.1:{http_port}");
    let server = Command::new(env!("CARGO_BIN_EXE_zkpm-backend"))
        .arg("serve")
        .env("ZKPM_BIND", &bind)
        .env("ZKPM_DATABASE_URL", &paused_url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn server");
    let guard = ProcessGuard(server);
    wait_for_http(&bind, Duration::from_secs(15));
    assert_eq!(http_status(&bind, "/health/ready"), Some(200));
    let paused = Command::new("docker")
        .args(["pause", &container])
        .status()
        .unwrap();
    assert!(paused.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_503 = false;
    while Instant::now() < deadline {
        if http_status(&bind, "/health/ready") == Some(503) {
            saw_503 = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let resumed = Command::new("docker")
        .args(["unpause", &container])
        .status()
        .unwrap();
    assert!(resumed.success());
    assert!(
        saw_503,
        "readiness must degrade while the database is paused"
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut recovered = false;
    while Instant::now() < deadline {
        if http_status(&bind, "/health/ready") == Some(200) {
            recovered = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(recovered, "readiness must recover after resume");
    drop(guard);
    cleanup(&container);
    database.drop().await;
}

struct ProcessGuard(Child);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_postgres(url: &str, bound: Duration) {
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        if PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(2))
            .connect(url)
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("postgres did not become ready");
}

fn wait_for_http(bind: &str, bound: Duration) {
    let addr: SocketAddr = bind.parse().unwrap();
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            if stream
                .write_all(
                    b"GET /health/live HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .is_ok()
            {
                let mut response = String::new();
                if stream.read_to_string(&mut response).is_ok() && response.contains("200") {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("server did not become ready");
}

fn http_status(bind: &str, path: &str) -> Option<u16> {
    let addr: SocketAddr = bind.parse().unwrap();
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    response.split_whitespace().nth(1)?.parse().ok()
}

// ---- TLS (production CA/hostname verification) ----

fn openssl(args: &[&str]) {
    let status = Command::new("openssl")
        .args(args)
        .status()
        .expect("openssl");
    assert!(status.success(), "openssl {args:?} failed");
}

/// A real CA plus a server certificate signed by it. Self-signed end-entity
/// certificates are not accepted as TLS trust anchors, so the two-step
/// issuance below mirrors production provisioning. Returns the server
/// certificate path; the matching CA is `<ca_name>-ca.crt` in the same dir.
fn generate_certificate(dir: &Path, ca_name: &str, name: &str, san: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    make_ca(dir, ca_name);
    sign_server(dir, ca_name, name, san)
}

fn make_ca(dir: &Path, ca_name: &str) {
    let ca_key = dir.join(format!("{ca_name}-ca.key"));
    let ca_cert = dir.join(format!("{ca_name}-ca.crt"));
    if ca_cert.exists() {
        return;
    }
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-keyout",
        ca_key.to_str().unwrap(),
        "-out",
        ca_cert.to_str().unwrap(),
        "-subj",
        "/CN=rust02-test-ca",
        "-addext",
        "basicConstraints=critical,CA:true",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ]);
}

fn sign_server(dir: &Path, ca_name: &str, name: &str, san: &str) -> PathBuf {
    let ca_key = dir.join(format!("{ca_name}-ca.key"));
    let ca_cert = dir.join(format!("{ca_name}-ca.crt"));
    let server_key = dir.join(format!("{name}.key"));
    let server_csr = dir.join(format!("{name}.csr"));
    let server_cert = dir.join(format!("{name}.crt"));
    openssl(&[
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        server_key.to_str().unwrap(),
        "-out",
        server_csr.to_str().unwrap(),
        "-subj",
        "/CN=localhost",
    ]);
    let extfile = dir.join(format!("{name}.ext"));
    std::fs::write(&extfile, format!("subjectAltName={san}\n")).unwrap();
    openssl(&[
        "x509",
        "-req",
        "-in",
        server_csr.to_str().unwrap(),
        "-CA",
        ca_cert.to_str().unwrap(),
        "-CAkey",
        ca_key.to_str().unwrap(),
        "-CAcreateserial",
        "-days",
        "2",
        "-extfile",
        extfile.to_str().unwrap(),
        "-out",
        server_cert.to_str().unwrap(),
    ]);
    server_cert
}

fn ca_certificate(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}-ca.crt"))
}

fn production_tls_config(url: &str, ca: &Path) -> Config {
    Config::from_values(
        Environment::Production,
        Values {
            database_url: Some(url.to_owned()),
            database_tls: Some("verify-full".into()),
            database_tls_ca_file: Some(ca.to_string_lossy().into()),
            cors_origins: Some("https://vault.example".into()),
            ..Values::default()
        },
    )
    .expect("production TLS config")
}

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL, docker and openssl; run explicitly with --ignored"]
async fn tls_verification_requires_matching_ca_and_hostname() {
    // Refusal first: verify-full against a server that never speaks TLS.
    let database = TestDatabase::create("tls_refuse").await;
    let dir = std::env::temp_dir().join(format!("rust02-tls-{}", std::process::id()));
    let _refusal = generate_certificate(&dir, "ca", "refusal", "IP:127.0.0.1");
    let config = production_tls_config(&database.url, &ca_certificate(&dir, "ca"));
    assert_eq!(config.database_tls, DatabaseTls::VerifyFull);
    let pool = zkpm_backend::migrate::migration_pool(&config)
        .await
        .unwrap();
    assert!(
        !zkpm_backend::migrate::healthcheck(&pool).await,
        "verify-full must refuse a plaintext server"
    );
    pool.close().await;
    database.drop().await;

    // Positive path: a TLS-enabled disposable PostgreSQL with a matching
    // certificate, plus hostname/wrong-CA negatives.
    let container = format!("rust02-pg-tls-{}", std::process::id());
    let port = free_port();
    let status = Command::new("docker")
        .args([
            "run",
            "--detach",
            "--name",
            &container,
            "--env",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "--publish",
            &format!("127.0.0.1:{port}:5432"),
            "postgres:16-alpine",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let cleanup = || {
        let _ = Command::new("docker")
            .args(["rm", "--force", &container])
            .status();
    };
    let server_cert = generate_certificate(&dir, "server", "server", "IP:127.0.0.1");
    let server_key = dir.join("server.key");
    for (local, remote) in [
        (server_cert.to_str().unwrap(), "server.crt"),
        (server_key.to_str().unwrap(), "server.key"),
    ] {
        let status = Command::new("docker")
            .args([
                "cp",
                local,
                &format!("{container}:/var/lib/postgresql/data/{remote}"),
            ])
            .status()
            .unwrap();
        assert!(status.success());
    }
    let chmod = Command::new("docker")
        .args([
            "exec", "-u", "root", &container, "sh", "-c",
            "chown postgres:postgres /var/lib/postgresql/data/server.* && chmod 600 /var/lib/postgresql/data/server.key",
        ])
        .status()
        .unwrap();
    assert!(chmod.success());
    let url = format!("postgres://postgres@127.0.0.1:{port}/postgres");
    wait_for_postgres(&url, Duration::from_secs(30)).await;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    // ALTER SYSTEM cannot run in a multi-statement batch: one statement each.
    for statement in [
        "ALTER SYSTEM SET ssl = on",
        "ALTER SYSTEM SET ssl_cert_file = '/var/lib/postgresql/data/server.crt'",
        "ALTER SYSTEM SET ssl_key_file = '/var/lib/postgresql/data/server.key'",
        "SELECT pg_reload_conf()",
    ] {
        sqlx::query(statement).execute(&admin).await.unwrap();
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let tls_on: bool = sqlx::query_scalar::<_, bool>("SHOW ssl")
        .fetch_one(&admin)
        .await
        .map(|_| true)
        .unwrap_or(true);
    let ssl_setting: String =
        sqlx::query_scalar::<_, String>("SELECT setting FROM pg_settings WHERE name='ssl'")
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(
        ssl_setting, "on",
        "tls container ssl setting (tls_on={tls_on})"
    );
    admin.close().await;

    // Matching CA + matching host: connection succeeds.
    let good = production_tls_config(&url, &ca_certificate(&dir, "server"));
    let pool = zkpm_backend::migrate::migration_pool(&good).await.unwrap();
    assert!(
        zkpm_backend::migrate::healthcheck(&pool).await,
        "verify-full with matching CA must succeed"
    );
    pool.close().await;

    // Wrong CA: refused.
    let _other = generate_certificate(&dir, "other", "other", "IP:127.0.0.1");
    let bad_ca = production_tls_config(&url, &ca_certificate(&dir, "other"));
    let pool = zkpm_backend::migrate::migration_pool(&bad_ca)
        .await
        .unwrap();
    assert!(
        !zkpm_backend::migrate::healthcheck(&pool).await,
        "unknown CA must be refused"
    );
    pool.close().await;

    // Same CA, certificate for a different address: hostname verification
    // must fail. The server certificate is swapped in place and reloaded so
    // the trust root stays identical and only the SAN differs.
    let wrong_cert = sign_server(&dir, "server", "server-wrong-host", "IP:127.0.0.2");
    let wrong_key = dir.join("server-wrong-host.key");
    for (local, remote) in [
        (wrong_cert.to_str().unwrap(), "server.crt"),
        (wrong_key.to_str().unwrap(), "server.key"),
    ] {
        let status = Command::new("docker")
            .args([
                "cp",
                local,
                &format!("{container}:/var/lib/postgresql/data/{remote}"),
            ])
            .status()
            .unwrap();
        assert!(status.success());
    }
    let chmod = Command::new("docker")
        .args([
            "exec", "-u", "root", &container, "sh", "-c",
            "chown postgres:postgres /var/lib/postgresql/data/server.* && chmod 600 /var/lib/postgresql/data/server.key && psql -U postgres -c 'SELECT pg_reload_conf();'",
        ])
        .status()
        .unwrap();
    assert!(chmod.success());
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mismatch = production_tls_config(&url, &ca_certificate(&dir, "server"));
    let pool = zkpm_backend::migrate::migration_pool(&mismatch)
        .await
        .unwrap();
    assert!(
        !zkpm_backend::migrate::healthcheck(&pool).await,
        "certificate for a different address must fail hostname verification"
    );
    pool.close().await;
    cleanup();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL; run explicitly with --ignored"]
async fn readiness_endpoint_transitions_with_pool_lifecycle() {
    // In-process readiness: ready when the database is reachable, degraded
    // once the pool is closed (server keeps answering live requests).
    let database = TestDatabase::create("ready").await;
    let config = config_for(&database.url);
    let pool = zkpm_backend::pool(&config).unwrap();
    use tower::ServiceExt;
    let router = zkpm_backend::app(pool.clone(), &config);
    let response = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/health/ready")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    pool.close().await;
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri("/health/ready")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let response = zkpm_backend::app(pool, &config)
        .oneshot(
            axum::http::Request::builder()
                .uri("/health/live")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    database.drop().await;
}
