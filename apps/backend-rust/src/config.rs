use std::{net::SocketAddr, time::Duration};

use secrecy::{ExposeSecret, SecretString};
use sqlx::{ConnectOptions, postgres::PgConnectOptions};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("POC_DATABASE_URL is required")]
    MissingDatabase,
    #[error("POC_DATABASE_URL must be a valid local PostgreSQL URL")]
    InvalidDatabase,
    #[error("POC_BIND must be a loopback socket address")]
    InvalidBind,
}

// Intentionally no Debug: the connection string may contain credentials.
pub struct Config {
    pub bind: SocketAddr,
    database_url: SecretString,
}

impl Config {
    pub const DATABASE_TIMEOUT: Duration = Duration::from_secs(2);
    pub const MAX_CONNECTIONS: u32 = 4;

    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_values(
            std::env::var("POC_BIND").ok().as_deref(),
            std::env::var("POC_DATABASE_URL").ok(),
        )
    }

    pub fn from_values(
        bind: Option<&str>,
        database_url: Option<String>,
    ) -> Result<Self, ConfigError> {
        let bind: SocketAddr = bind
            .unwrap_or("127.0.0.1:3100")
            .parse()
            .map_err(|_| ConfigError::InvalidBind)?;
        if !bind.ip().is_loopback() {
            return Err(ConfigError::InvalidBind);
        }
        let database_url = database_url
            .filter(|value| !value.trim().is_empty())
            .ok_or(ConfigError::MissingDatabase)?;
        let config = Self {
            bind,
            database_url: database_url.into(),
        };
        config.connect_options()?;
        Ok(config)
    }

    pub fn connect_options(&self) -> Result<PgConnectOptions, ConfigError> {
        if !self.database_url.expose_secret().starts_with("postgres://")
            && !self
                .database_url
                .expose_secret()
                .starts_with("postgresql://")
        {
            return Err(ConfigError::InvalidDatabase);
        }
        let options: PgConnectOptions = self
            .database_url
            .expose_secret()
            .parse()
            .map_err(|_| ConfigError::InvalidDatabase)?;
        // Explicit numeric loopback only; no DNS or Unix socket paths.
        if !matches!(options.get_host(), "127.0.0.1" | "::1") || options.get_socket().is_some() {
            return Err(ConfigError::InvalidDatabase);
        }
        Ok(options.disable_statement_logging())
    }
}
