//! Strict typed configuration loaded from the environment.
//!
//! Fail closed: every malformed value is rejected without echoing the input.
//! Production is separated from development/test: only production may bind a
//! non-loopback address or use a non-loopback database host, and a non-loopback
//! database host requires TLS with CA and hostname verification (`verify-full`).

use std::{net::SocketAddr, time::Duration};

use secrecy::{ExposeSecret, SecretString};
use sqlx::{ConnectOptions, postgres::PgConnectOptions, postgres::PgSslMode};

pub const ENV_ENVIRONMENT: &str = "ZKPM_ENVIRONMENT";
pub const ENV_BIND: &str = "ZKPM_BIND";
pub const ENV_DATABASE_URL: &str = "ZKPM_DATABASE_URL";
pub const ENV_DATABASE_TLS: &str = "ZKPM_DATABASE_TLS";
pub const ENV_DATABASE_TLS_CA_FILE: &str = "ZKPM_DATABASE_TLS_CA_FILE";
pub const ENV_DATABASE_MAX_CONNECTIONS: &str = "ZKPM_DATABASE_MAX_CONNECTIONS";
pub const ENV_DATABASE_ACQUIRE_TIMEOUT_MS: &str = "ZKPM_DATABASE_ACQUIRE_TIMEOUT_MS";
pub const ENV_CORS_ORIGINS: &str = "ZKPM_CORS_ORIGINS";
pub const ENV_LOG_LEVEL: &str = "ZKPM_LOG_LEVEL";
pub const ENV_BODY_LIMIT_BYTES: &str = "ZKPM_BODY_LIMIT_BYTES";
pub const ENV_REQUEST_TIMEOUT_MS: &str = "ZKPM_REQUEST_TIMEOUT_MS";
pub const ENV_CONCURRENCY: &str = "ZKPM_CONCURRENCY";
pub const ENV_SHUTDOWN_TIMEOUT_MS: &str = "ZKPM_SHUTDOWN_TIMEOUT_MS";

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ConfigError {
    #[error("environment must be development, test, or production")]
    InvalidEnvironment,
    #[error("bind must be a valid socket address")]
    InvalidBind,
    #[error("bind must be loopback outside production")]
    BindNotLoopback,
    #[error("database URL is required")]
    MissingDatabase,
    #[error("database URL must be a valid PostgreSQL URL")]
    InvalidDatabase,
    #[error("database host must be loopback outside production")]
    DatabaseHostNotLoopback,
    #[error("database TLS mode must be disabled or verify-full")]
    InvalidDatabaseTls,
    #[error("production database TLS must be verify-full with a CA file")]
    ProductionTlsRequired,
    #[error("TLS CA file must be an existing readable PEM file")]
    InvalidCaFile,
    #[error("database TLS CA file is only used with verify-full")]
    UnusedCaFile,
    #[error("CORS origins must be exact http(s) origins without path, query, or wildcard")]
    InvalidCorsOrigin,
    #[error("production must set CORS origins explicitly")]
    ProductionCorsRequired,
    #[error("log level must be one of error, warn, info")]
    InvalidLogLevel,
    #[error("database connection count must be 1..=64")]
    InvalidMaxConnections,
    #[error("database acquire timeout must be 100..=60000 ms")]
    InvalidAcquireTimeout,
    #[error("body limit must be 1024..=16777216 bytes")]
    InvalidBodyLimit,
    #[error("request timeout must be 1000..=120000 ms")]
    InvalidRequestTimeout,
    #[error("concurrency limit must be 1..=1024")]
    InvalidConcurrency,
    #[error("shutdown timeout must be 1000..=120000 ms")]
    InvalidShutdownTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Test,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseTls {
    Disabled,
    VerifyFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
}

/// Resource limits; bounded at parse time so a bad environment cannot disable them.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub body_limit_bytes: usize,
    pub request_timeout: Duration,
    pub concurrency: usize,
    pub shutdown_timeout: Duration,
}

// Intentionally no Debug derive for the whole Config: the URL embeds credentials.
pub struct Config {
    pub environment: Environment,
    pub bind: SocketAddr,
    database_url: SecretString,
    pub database_tls: DatabaseTls,
    database_tls_ca: Option<Vec<u8>>,
    pub database_max_connections: u32,
    pub database_acquire_timeout: Duration,
    pub cors_origins: Vec<String>,
    pub log_level: LogLevel,
    pub limits: Limits,
}

impl Config {
    pub const DEFAULT_BIND: &'static str = "127.0.0.1:8080";
    /// Bound on the readiness probe query itself.
    pub const DATABASE_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
    pub const DEFAULT_MAX_CONNECTIONS: u32 = 10;
    pub const DEFAULT_ACQUIRE_TIMEOUT_MS: u64 = 2_000;
    pub const DEFAULT_BODY_LIMIT_BYTES: usize = 1_048_576;
    pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 15_000;
    pub const DEFAULT_CONCURRENCY: usize = 64;
    pub const DEFAULT_SHUTDOWN_TIMEOUT_MS: u64 = 10_000;

    pub fn from_env() -> Result<Self, ConfigError> {
        let environment = match std::env::var(ENV_ENVIRONMENT).ok().as_deref() {
            None | Some("development") => Environment::Development,
            Some("test") => Environment::Test,
            Some("production") => Environment::Production,
            Some(_) => return Err(ConfigError::InvalidEnvironment),
        };
        Self::from_values(
            environment,
            Values {
                bind: std::env::var(ENV_BIND).ok(),
                database_url: std::env::var(ENV_DATABASE_URL).ok(),
                database_tls: std::env::var(ENV_DATABASE_TLS).ok(),
                database_tls_ca_file: std::env::var(ENV_DATABASE_TLS_CA_FILE).ok(),
                database_max_connections: std::env::var(ENV_DATABASE_MAX_CONNECTIONS).ok(),
                database_acquire_timeout_ms: std::env::var(ENV_DATABASE_ACQUIRE_TIMEOUT_MS).ok(),
                cors_origins: std::env::var(ENV_CORS_ORIGINS).ok(),
                log_level: std::env::var(ENV_LOG_LEVEL).ok(),
                body_limit_bytes: std::env::var(ENV_BODY_LIMIT_BYTES).ok(),
                request_timeout_ms: std::env::var(ENV_REQUEST_TIMEOUT_MS).ok(),
                concurrency: std::env::var(ENV_CONCURRENCY).ok(),
                shutdown_timeout_ms: std::env::var(ENV_SHUTDOWN_TIMEOUT_MS).ok(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_values(environment: Environment, values: Values) -> Result<Self, ConfigError> {
        let bind: SocketAddr = values
            .bind
            .as_deref()
            .unwrap_or(Self::DEFAULT_BIND)
            .parse()
            .map_err(|_| ConfigError::InvalidBind)?;
        if environment != Environment::Production && !bind.ip().is_loopback() {
            return Err(ConfigError::BindNotLoopback);
        }
        let database_url = values
            .database_url
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(ConfigError::MissingDatabase)?;
        let database_tls = match values.database_tls.as_deref() {
            None => DatabaseTls::Disabled,
            Some("disabled") => DatabaseTls::Disabled,
            Some("verify-full") => DatabaseTls::VerifyFull,
            Some(_) => return Err(ConfigError::InvalidDatabaseTls),
        };
        let database_tls_ca = match (&database_tls, values.database_tls_ca_file) {
            (DatabaseTls::VerifyFull, Some(path)) => {
                Some(std::fs::read(path.trim()).map_err(|_| ConfigError::InvalidCaFile)?)
            }
            (DatabaseTls::VerifyFull, None) => return Err(ConfigError::ProductionTlsRequired),
            (DatabaseTls::Disabled, Some(_)) => return Err(ConfigError::UnusedCaFile),
            (DatabaseTls::Disabled, None) => None,
        };
        // Any PEM parse failure surfaces later as a connection failure; validate
        // readability now so configuration errors are reported before serving.
        if let Some(bytes) = &database_tls_ca {
            let text = std::str::from_utf8(bytes).map_err(|_| ConfigError::InvalidCaFile)?;
            if !text.contains("-----BEGIN CERTIFICATE-----") {
                return Err(ConfigError::InvalidCaFile);
            }
        }
        let database_max_connections = parse_bounded(
            values.database_max_connections.as_deref(),
            1,
            64,
            Self::DEFAULT_MAX_CONNECTIONS as u64,
            ConfigError::InvalidMaxConnections,
        )? as u32;
        let database_acquire_timeout = Duration::from_millis(parse_bounded(
            values.database_acquire_timeout_ms.as_deref(),
            100,
            60_000,
            Self::DEFAULT_ACQUIRE_TIMEOUT_MS,
            ConfigError::InvalidAcquireTimeout,
        )?);
        let cors_origins = match values.cors_origins {
            None => match environment {
                Environment::Production => return Err(ConfigError::ProductionCorsRequired),
                _ => Vec::new(),
            },
            Some(raw) => raw
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(|origin| validate_origin(origin).map(str::to_owned))
                .collect::<Result<Vec<_>, _>>()?,
        };
        let log_level = match values.log_level.as_deref() {
            None => LogLevel::Info,
            Some("error") => LogLevel::Error,
            Some("warn") => LogLevel::Warn,
            Some("info") => LogLevel::Info,
            Some(_) => return Err(ConfigError::InvalidLogLevel),
        };
        let limits = Limits {
            body_limit_bytes: parse_bounded(
                values.body_limit_bytes.as_deref(),
                1_024,
                16_777_216,
                Self::DEFAULT_BODY_LIMIT_BYTES as u64,
                ConfigError::InvalidBodyLimit,
            )? as usize,
            request_timeout: Duration::from_millis(parse_bounded(
                values.request_timeout_ms.as_deref(),
                1_000,
                120_000,
                Self::DEFAULT_REQUEST_TIMEOUT_MS,
                ConfigError::InvalidRequestTimeout,
            )?),
            concurrency: parse_bounded(
                values.concurrency.as_deref(),
                1,
                1_024,
                Self::DEFAULT_CONCURRENCY as u64,
                ConfigError::InvalidConcurrency,
            )? as usize,
            shutdown_timeout: Duration::from_millis(parse_bounded(
                values.shutdown_timeout_ms.as_deref(),
                1_000,
                120_000,
                Self::DEFAULT_SHUTDOWN_TIMEOUT_MS,
                ConfigError::InvalidShutdownTimeout,
            )?),
        };
        let config = Self {
            environment,
            bind,
            database_url: database_url.into(),
            database_tls,
            database_tls_ca,
            database_max_connections,
            database_acquire_timeout,
            cors_origins,
            log_level,
            limits,
        };
        config.connect_options()?;
        Ok(config)
    }

    /// Connection options with TLS policy applied. Outside production only
    /// numeric loopback hosts are accepted; production requires TLS with CA
    /// verification for any non-loopback host (loopback stays allowed for
    /// sidecar databases, still optionally with TLS).
    pub fn connect_options(&self) -> Result<PgConnectOptions, ConfigError> {
        let url = self.database_url.expose_secret();
        if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
            return Err(ConfigError::InvalidDatabase);
        }
        let options: PgConnectOptions = url.parse().map_err(|_| ConfigError::InvalidDatabase)?;
        let host = options.get_host();
        let host_is_loopback =
            matches!(host, "127.0.0.1" | "::1") && options.get_socket().is_none();
        if self.environment != Environment::Production {
            if !host_is_loopback {
                return Err(ConfigError::DatabaseHostNotLoopback);
            }
        } else if !host_is_loopback && self.database_tls == DatabaseTls::Disabled {
            // Production with a remote database must verify CA and hostname.
            return Err(ConfigError::ProductionTlsRequired);
        }
        let mut options = options.disable_statement_logging();
        match self.database_tls {
            DatabaseTls::Disabled => {
                options = options.ssl_mode(PgSslMode::Disable);
            }
            DatabaseTls::VerifyFull => {
                let ca = self
                    .database_tls_ca
                    .as_ref()
                    .ok_or(ConfigError::ProductionTlsRequired)?;
                options = options
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert_from_pem(ca.clone());
            }
        }
        Ok(options)
    }
}

/// Raw environment values; kept separate so tests can construct error cases.
#[derive(Default, Clone)]
pub struct Values {
    pub bind: Option<String>,
    pub database_url: Option<String>,
    pub database_tls: Option<String>,
    pub database_tls_ca_file: Option<String>,
    pub database_max_connections: Option<String>,
    pub database_acquire_timeout_ms: Option<String>,
    pub cors_origins: Option<String>,
    pub log_level: Option<String>,
    pub body_limit_bytes: Option<String>,
    pub request_timeout_ms: Option<String>,
    pub concurrency: Option<String>,
    pub shutdown_timeout_ms: Option<String>,
}

fn parse_bounded(
    raw: Option<&str>,
    min: u64,
    max: u64,
    default: u64,
    error: ConfigError,
) -> Result<u64, ConfigError> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    let value: u64 = raw.trim().parse().map_err(|_| error.clone())?;
    if value < min || value > max {
        return Err(error);
    }
    Ok(value)
}

/// Exact-origin allowlist entries: scheme http/https, host present, no
/// wildcard, path, query or fragment. `tauri://localhost` (local desktop
/// shell) is the single additional permitted scheme in development.
fn validate_origin(origin: &str) -> Result<&str, ConfigError> {
    fn exact_http(origin: &str) -> bool {
        let Ok(url) = origin.parse::<axum::http::Uri>() else {
            return false;
        };
        let scheme = url.scheme_str().unwrap_or_default();
        let path_and_query = url.path_and_query().map(|pq| pq.as_str()).unwrap_or("");
        // Bare origins parse with an implied "/" path; only real paths or
        // queries are rejected.
        matches!(scheme, "http" | "https")
            && url.host().is_some()
            && matches!(path_and_query, "" | "/")
            && !origin.contains('*')
    }
    if origin == "tauri://localhost" || exact_http(origin) {
        Ok(origin)
    } else {
        Err(ConfigError::InvalidCorsOrigin)
    }
}
