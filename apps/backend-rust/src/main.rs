use std::{future::IntoFuture, process::ExitCode, time::Duration};
use zkpm_backend_poc::{app, config::Config, pool, subscriber};

#[tokio::main]
async fn main() -> ExitCode {
    if tracing::subscriber::set_global_default(subscriber(std::io::stdout)).is_err() {
        return ExitCode::FAILURE;
    }
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(target: "zkpm_backend_poc", code = %error, "configuration_invalid");
            return ExitCode::FAILURE;
        }
    };
    let Ok(pool) = pool(&config) else {
        tracing::error!(target: "zkpm_backend_poc", "database_configuration_invalid");
        return ExitCode::FAILURE;
    };
    let Ok(listener) = tokio::net::TcpListener::bind(config.bind).await else {
        tracing::error!(target: "zkpm_backend_poc", "bind_failed");
        return ExitCode::FAILURE;
    };
    tracing::info!(target: "zkpm_backend_poc", "poc_started");
    let (stopping, stopped) = tokio::sync::oneshot::channel();
    let server = axum::serve(listener, app(pool.clone()))
        .with_graceful_shutdown(async move {
            shutdown().await;
            let _ = stopping.send(());
        })
        .into_future();
    let result = tokio::select! {
        result = server => result,
        _ = async {
            let _ = stopped.await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        } => Err(std::io::Error::other("shutdown_timeout")),
    };
    pool.close().await;
    if result.is_err() {
        tracing::error!(target: "zkpm_backend_poc", "serve_failed");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

async fn shutdown() {
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
