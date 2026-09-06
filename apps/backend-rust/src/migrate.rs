//! Forward-only migration runner with exclusive locking and explicit adoption
//! of the legacy Bun backend's `schema_migrations` history.
//!
//! Principles (ADR-0013):
//! - Migrations never run implicitly at API startup; only the `migrate`
//!   command performs them, guarded by a session advisory lock so concurrent
//!   invocations serialize instead of racing.
//! - Historical DDL is never replayed against a live existing database. When
//!   the legacy table is present, its versions must form a prefix of the
//!   known history, and the *actual* schema is compared against a private
//!   scratch-schema replay of exactly that prefix inside a rolled-back
//!   transaction before any baseline row is written.
//! - Baseline rows are inserted into `_sqlx_migrations` with the real SQLx
//!   checksums of byte-identical copies of the original migration files, so
//!   `Migrator` afterwards validates history exactly as on a fresh install.
//! - The legacy `schema_migrations` table is preserved and kept in sync for
//!   the baseline set so the old Bun backend remains deployable (rollback
//!   compatibility).

use std::fmt;

use sqlx::{Connection, PgPool, Postgres, postgres::PgPoolOptions};

pub const MIGRATIONS_DIR: &str = "migrations";

/// Session advisory-lock key for the whole migration command (adoption plus
/// apply). Distinct from the lock SQLx uses internally.
const MIGRATION_LOCK_KEY: i64 = 0x5A4B_504D_3032_0001;

/// Legacy (`db/migrations`) ↔ SQLx version mapping. SQL bytes are identical
/// copies; only filenames differ (`001_x.sql` → `0001_x.sql`, version 1).
const LEGACY_HISTORY: [(i64, &str); 5] =
    [(1, "001"), (2, "002"), (3, "003"), (4, "004"), (5, "005")];

/// Migration-bookkeeping tables excluded from schema comparison.
const HISTORY_TABLES: [&str; 2] = ["schema_migrations", "_sqlx_migrations"];

/// Same DDL the old Bun runner creates, byte-for-byte compatible.
const LEGACY_HISTORY_DDL: &str = "CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())";

/// Same DDL SQLx 0.8.6 creates for its own history table.
const SQLX_HISTORY_DDL: &str = "CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
)";

const SQLX_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    #[error("embedded migrations do not match the known baseline set")]
    UnknownBaseline,
    #[error("legacy schema_migrations history is not a known prefix of the expected history")]
    HistoryMismatch,
    #[error("actual schema does not match the expected baseline schema: {first_difference}")]
    SchemaDrift { first_difference: String },
    #[error("database error during migration: {0}")]
    Database(#[from] sqlx::Error),
    #[error("migration runner error: {0}")]
    Runner(#[from] sqlx::migrate::MigrateError),
}

impl MigrateError {
    /// Stable, log-safe category used by the CLI.
    pub fn code(&self) -> &'static str {
        match self {
            MigrateError::UnknownBaseline => "unknown_baseline",
            MigrateError::HistoryMismatch => "history_mismatch",
            MigrateError::SchemaDrift { .. } => "schema_drift",
            MigrateError::Database(_) => "database_error",
            MigrateError::Runner(_) => "runner_error",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Number of legacy versions adopted into the SQLx history this run.
    pub adopted: usize,
    /// SQLx versions applied this run (adoption counts as applied-by-baseline).
    pub applied: Vec<i64>,
    pub up_to_date: bool,
}

pub async fn run(pool: &PgPool) -> Result<Outcome, MigrateError> {
    verify_embedded_baseline()?;
    // Exclusive session lock for the entire command (adoption + apply). The
    // connection is held until the guard drops, releasing the lock.
    let lock = LockGuard::acquire(pool).await?;
    let outcome = run_locked(pool, &lock).await?;
    lock.release().await?;
    Ok(outcome)
}

struct LockGuard {
    connection: sqlx::pool::PoolConnection<Postgres>,
}

impl LockGuard {
    async fn acquire(pool: &PgPool) -> Result<Self, MigrateError> {
        let mut connection = pool.acquire().await?;
        // Blocks until any concurrent migration invocation finishes.
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(MIGRATION_LOCK_KEY)
            .execute(&mut *connection)
            .await?;
        Ok(LockGuard { connection })
    }

    async fn release(self) -> Result<(), MigrateError> {
        let mut connection = self.connection;
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(MIGRATION_LOCK_KEY)
            .execute(&mut *connection)
            .await?;
        Ok(())
    }
}

async fn run_locked(pool: &PgPool, _lock: &LockGuard) -> Result<Outcome, MigrateError> {
    let mut adopted = 0;
    let sqlx_history_exists = table_exists(pool, "_sqlx_migrations").await?;
    let legacy_history_exists = table_exists(pool, "schema_migrations").await?;

    if legacy_history_exists && !sqlx_history_exists {
        adopted = adopt_legacy_baseline(pool).await?;
    }

    let before = applied_versions(pool).await?;
    SQLX_MIGRATOR.run(pool).await?;
    let after = applied_versions(pool).await?;
    let applied: Vec<i64> = after
        .iter()
        .filter(|version| !before.contains(version))
        .copied()
        .collect();
    let up_to_date = applied.is_empty();

    // Keep the legacy table present and complete for the baseline set so the
    // old Bun server and its migrate command still work against this database.
    sync_legacy_history(pool, &after).await?;

    Ok(Outcome {
        adopted,
        applied,
        up_to_date,
    })
}

fn verify_embedded_baseline() -> Result<(), MigrateError> {
    let mut versions: Vec<i64> = SQLX_MIGRATOR.iter().map(|m| m.version).collect();
    versions.sort_unstable();
    let expected: Vec<i64> = LEGACY_HISTORY.iter().map(|(v, _)| *v).collect();
    if versions != expected {
        return Err(MigrateError::UnknownBaseline);
    }
    Ok(())
}

async fn table_exists(pool: &PgPool, table: &str) -> Result<bool, MigrateError> {
    let exists = sqlx::query_scalar!(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = $1",
        table
    )
    .fetch_optional(pool)
    .await?
    .is_some();
    Ok(exists)
}

async fn applied_versions(pool: &PgPool) -> Result<Vec<i64>, MigrateError> {
    if !table_exists(pool, "_sqlx_migrations").await? {
        return Ok(Vec::new());
    }
    let versions =
        sqlx::query_scalar!("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
            .fetch_all(pool)
            .await?;
    Ok(versions)
}

/// Adopt an existing legacy history: validate it is a known prefix, prove
/// schema equivalence by replaying that prefix in a scratch schema inside a
/// rolled-back transaction, then write baseline rows with real SQLx
/// checksums. Returns the adopted prefix length.
async fn adopt_legacy_baseline(pool: &PgPool) -> Result<usize, MigrateError> {
    let applied: Vec<String> =
        sqlx::query_scalar!("SELECT version FROM schema_migrations ORDER BY version")
            .fetch_all(pool)
            .await?;
    // The applied set must be exactly a prefix of the known history.
    if applied.len() > LEGACY_HISTORY.len() {
        return Err(MigrateError::HistoryMismatch);
    }
    for (index, (_, expected)) in LEGACY_HISTORY.iter().enumerate() {
        match applied.get(index) {
            Some(actual) if actual == expected => {}
            None if applied.len() == index => break,
            _ => return Err(MigrateError::HistoryMismatch),
        }
    }
    let prefix = applied.len();

    verify_schema_equivalence(pool, prefix).await?;

    let mut transaction = pool.begin().await?;
    sqlx::raw_sql(SQLX_HISTORY_DDL)
        .execute(&mut *transaction)
        .await?;
    for migration in SQLX_MIGRATOR.iter().take(prefix) {
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES ($1, $2, TRUE, $3, 0)",
        )
        .bind(migration.version)
        .bind(&*migration.description)
        .bind(&*migration.checksum)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(prefix)
}

/// Replay the first `prefix` migrations into a private scratch schema inside
/// one rolled-back transaction (DDL is transactional in PostgreSQL; nothing
/// persists and the existing database is never modified) and compare the
/// resulting structure against the live schema.
async fn verify_schema_equivalence(pool: &PgPool, prefix: usize) -> Result<(), MigrateError> {
    const PROBE_SCHEMA: &str = "zkpm_baseline_probe";
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query(&format!("DROP SCHEMA IF EXISTS {PROBE_SCHEMA} CASCADE"))
        .execute(&mut *transaction)
        .await?;
    sqlx::query(&format!("CREATE SCHEMA {PROBE_SCHEMA}"))
        .execute(&mut *transaction)
        .await?;
    sqlx::query(&format!(
        "SET LOCAL search_path = {PROBE_SCHEMA}, pg_catalog"
    ))
    .execute(&mut *transaction)
    .await?;
    for migration in SQLX_MIGRATOR.iter().take(prefix) {
        sqlx::raw_sql(&migration.sql)
            .execute(&mut *transaction)
            .await?;
    }
    let probe = SchemaDump::capture(&mut transaction, PROBE_SCHEMA).await?;
    let live = SchemaDump::capture(&mut transaction, "public").await?;
    transaction.rollback().await?;

    if probe != live {
        return Err(MigrateError::SchemaDrift {
            first_difference: probe.first_difference(&live),
        });
    }
    Ok(())
}

/// Structural fingerprint of a schema: tables, columns (type/nullability/
/// normalized default), sequences, constraints and indexes. Data is never
/// read; only object metadata.
#[derive(Debug, PartialEq, Eq)]
struct SchemaDump {
    tables: Vec<String>,
    columns: Vec<(String, String, String, bool, String)>,
    sequences: Vec<String>,
    constraints: Vec<(String, String, Vec<i16>)>,
    indexes: Vec<String>,
}

impl SchemaDump {
    fn normalize(text: &str, schema: &str) -> String {
        // Scratch-schema and public-schema qualifiers normalize to the same
        // unqualified form (covers regclass references like sequence defaults).
        text.replace(&format!("{schema}."), "")
            .replace("public.", "")
    }

    async fn capture(
        connection: &mut sqlx::Transaction<'_, Postgres>,
        schema: &str,
    ) -> Result<Self, sqlx::Error> {
        let exclude: Vec<String> = HISTORY_TABLES.iter().map(ToString::to_string).collect();
        let tables = sqlx::query_scalar!(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = $1 AND table_type = 'BASE TABLE' AND table_name <> ALL($2) \
             ORDER BY table_name",
            schema,
            &exclude
        )
        .fetch_all(&mut **connection)
        .await?
        .into_iter()
        .flatten()
        .collect();
        let columns = sqlx::query!(
            "SELECT table_name, column_name, data_type, is_nullable, COALESCE(column_default, '') AS column_default \
             FROM information_schema.columns \
             WHERE table_schema = $1 AND table_name <> ALL($2) \
             ORDER BY table_name, ordinal_position",
            schema, &exclude
        )
        .fetch_all(&mut **connection)
        .await?;
        let columns = columns
            .into_iter()
            .map(|row| {
                (
                    row.table_name.unwrap_or_default(),
                    row.column_name.unwrap_or_default(),
                    row.data_type.unwrap_or_default(),
                    row.is_nullable.as_deref() == Some("YES"),
                    Self::normalize(row.column_default.as_deref().unwrap_or(""), schema),
                )
            })
            .collect();
        let sequences = sqlx::query_scalar!(
            "SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = $1 ORDER BY sequence_name",
            schema
        )
        .fetch_all(&mut **connection)
        .await?
        .into_iter()
        .flatten()
        .collect();
        let constraints = sqlx::query!(
            "SELECT c.conname, c.contype::text AS contype, COALESCE(c.conkey, ARRAY[]::smallint[]) AS conkey \
             FROM pg_constraint c \
             JOIN pg_class t ON t.oid = c.conrelid \
             JOIN pg_namespace n ON n.oid = t.relnamespace \
             WHERE n.nspname = $1 AND t.relname <> ALL($2) \
             ORDER BY c.conname",
            schema, &exclude
        )
        .fetch_all(&mut **connection)
        .await?
        .into_iter()
        .map(|row| {
            (
                row.conname,
                row.contype.unwrap_or_default(),
                row.conkey.unwrap_or_default(),
            )
        })
        .collect();
        let indexes = sqlx::query_scalar!(
            "SELECT indexdef FROM pg_indexes WHERE schemaname = $1 AND tablename <> ALL($2) ORDER BY indexname",
            schema, &exclude
        )
        .fetch_all(&mut **connection)
        .await?
        .into_iter()
        .map(|definition| Self::normalize(definition.as_deref().unwrap_or(""), schema))
        .collect();
        Ok(SchemaDump {
            tables,
            columns,
            sequences,
            constraints,
            indexes,
        })
    }

    fn first_difference(&self, other: &Self) -> String {
        macro_rules! compare {
            ($field:ident) => {
                if self.$field != other.$field {
                    return format!(
                        "{}: expected {:?} but database has {:?}",
                        stringify!($field),
                        self.$field,
                        other.$field
                    );
                }
            };
        }
        compare!(tables);
        compare!(columns);
        compare!(sequences);
        compare!(constraints);
        compare!(indexes);
        "no structural difference found".to_owned()
    }
}

impl fmt::Display for SchemaDump {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "tables={:?} sequences={:?}",
            self.tables, self.sequences
        )
    }
}

/// Insert legacy-history rows for every baseline migration already recorded
/// as applied in the SQLx history, creating the legacy table when missing.
async fn sync_legacy_history(pool: &PgPool, applied: &[i64]) -> Result<(), MigrateError> {
    let mut transaction = pool.begin().await?;
    sqlx::raw_sql(LEGACY_HISTORY_DDL)
        .execute(&mut *transaction)
        .await?;
    for (version, legacy) in LEGACY_HISTORY {
        if applied.contains(&version) {
            sqlx::query(
                "INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING",
            )
            .bind(legacy)
            .execute(&mut *transaction)
            .await?;
        }
    }
    transaction.commit().await?;
    Ok(())
}

/// `healthcheck` implementation: bounded connectivity probe.
pub async fn healthcheck(pool: &PgPool) -> bool {
    matches!(
        tokio::time::timeout(
            crate::config::Config::DATABASE_PROBE_TIMEOUT,
            sqlx::query_scalar!("SELECT 1").fetch_one(pool)
        )
        .await,
        Ok(Ok(Some(1)))
    )
}

/// Small pool dedicated to migration commands.
pub async fn migration_pool(
    config: &crate::config::Config,
) -> Result<PgPool, crate::config::ConfigError> {
    Ok(PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(config.database_acquire_timeout)
        .connect_lazy_with(config.connect_options()?))
}
