use std::{future::IntoFuture, process::ExitCode};

use clap::{Parser, Subcommand};
use zkpm_backend::{
    LOG_TARGET, app,
    config::{Config, LogLevel},
    migrate, pool, subscriber,
};

#[derive(Parser)]
#[command(
    name = "zkpm-backend",
    version,
    about = "Zero-knowledge password manager backend"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the HTTP API (never runs migrations implicitly).
    Serve,
    /// Apply pending database migrations with exclusive locking.
    Migrate,
    /// Probe database connectivity; exit code 1 on failure.
    Healthcheck,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if tracing::subscriber::set_global_default(subscriber(std::io::stdout, LogLevel::Info)).is_err()
    {
        return ExitCode::FAILURE;
    }
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            // Errors carry fixed messages; supplied values are never echoed.
            tracing::error!(target: LOG_TARGET, code = %error, "configuration_invalid");
            return ExitCode::FAILURE;
        }
    };
    match cli.command {
        Command::Serve => serve(config).await,
        Command::Migrate => run_migrate(config).await,
        Command::Healthcheck => run_healthcheck(config).await,
    }
}

async fn serve(config: Config) -> ExitCode {
    let Ok(pool) = pool(&config) else {
        tracing::error!(target: LOG_TARGET, "database_configuration_invalid");
        return ExitCode::FAILURE;
    };
    let Ok(listener) = tokio::net::TcpListener::bind(config.bind).await else {
        tracing::error!(target: LOG_TARGET, "bind_failed");
        return ExitCode::FAILURE;
    };
    tracing::info!(target: LOG_TARGET, "server_started");
    let (stopping, stopped) = tokio::sync::oneshot::channel();
    let shutdown_timeout = config.limits.shutdown_timeout;
    let server = axum::serve(listener, app(pool.clone(), &config))
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = stopping.send(());
        })
        .into_future();
    let result = tokio::select! {
        result = server => result,
        _ = async {
            let _ = stopped.await;
            tokio::time::sleep(shutdown_timeout).await;
        } => Err(std::io::Error::other("shutdown_timeout")),
    };
    pool.close().await;
    if result.is_err() {
        tracing::error!(target: LOG_TARGET, "serve_failed");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

async fn run_migrate(config: Config) -> ExitCode {
    let pool = match migrate::migration_pool(&config).await {
        Ok(pool) => pool,
        Err(_) => {
            tracing::error!(target: LOG_TARGET, "database_configuration_invalid");
            return ExitCode::FAILURE;
        }
    };
    match migrate::run(&pool).await {
        Ok(outcome) => {
            tracing::info!(target: LOG_TARGET,
                code = "migrations_complete",
                adopted = outcome.adopted,
                applied = outcome.applied.len(),
                up_to_date = outcome.up_to_date,
                "migrate_complete");
            pool.close().await;
            ExitCode::SUCCESS
        }
        Err(error) => {
            // `code` plus the Display message; messages never contain bound
            // parameters, secrets or table data.
            tracing::error!(target: LOG_TARGET, code = error.code(), error = %error, "migrate_failed");
            pool.close().await;
            ExitCode::FAILURE
        }
    }
}

async fn run_healthcheck(config: Config) -> ExitCode {
    let pool = match migrate::migration_pool(&config).await {
        Ok(pool) => pool,
        Err(_) => {
            tracing::error!(target: LOG_TARGET, "database_configuration_invalid");
            return ExitCode::FAILURE;
        }
    };
    if migrate::healthcheck(&pool).await {
        tracing::info!(target: LOG_TARGET, "healthcheck_ok");
        pool.close().await;
        ExitCode::SUCCESS
    } else {
        tracing::error!(target: LOG_TARGET, "healthcheck_failed");
        pool.close().await;
        ExitCode::FAILURE
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut terminate) = signal(SignalKind::terminate()) else {
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
