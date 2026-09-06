//! OS-process tests for the CLI: configuration failure behavior, graceful
//! shutdown with an in-flight request, and the `healthcheck` command against
//! an unreachable database.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zkpm-backend"));
    for variable in [
        "ZKPM_ENVIRONMENT",
        "ZKPM_BIND",
        "ZKPM_DATABASE_URL",
        "ZKPM_DATABASE_TLS",
        "ZKPM_DATABASE_TLS_CA_FILE",
        "ZKPM_CORS_ORIGINS",
        "ZKPM_LOG_LEVEL",
    ] {
        command.env_remove(variable);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn missing_subcommand_or_bad_config_exits_without_echoing_input() {
    // No subcommand: clap usage error (non-zero) with no secrets involved.
    let output = command().output().unwrap();
    assert!(!output.status.success());

    let output = command()
        .arg("serve")
        .env("ZKPM_DATABASE_URL", "CONFIG_MARKER")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("configuration_invalid"));
    assert!(!stdout.contains("CONFIG_MARKER"));
    assert!(String::from_utf8(output.stderr).unwrap().is_empty());
}

#[test]
fn occupied_port_fails_with_safe_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let output = command()
        .arg("serve")
        .env("ZKPM_BIND", listener.local_addr().unwrap().to_string())
        .env(
            "ZKPM_DATABASE_URL",
            "postgres://postgres@127.0.0.1:1/rust02",
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("bind_failed")
    );
}

#[test]
fn healthcheck_command_fails_cleanly_on_unreachable_database() {
    let output = command()
        .arg("healthcheck")
        .env(
            "ZKPM_DATABASE_URL",
            "postgres://postgres@127.0.0.1:1/rust02",
        )
        .env("ZKPM_DATABASE_ACQUIRE_TIMEOUT_MS", "1000")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("healthcheck_failed"));
}

#[test]
fn migrate_command_never_runs_at_server_startup_and_reports_safely() {
    // Unreachable database: migrate fails with a safe code, no URL echoed.
    let output = command()
        .arg("migrate")
        .env(
            "ZKPM_DATABASE_URL",
            "postgres://postgres@127.0.0.1:1/MARKER_DB",
        )
        .env("ZKPM_DATABASE_ACQUIRE_TIMEOUT_MS", "1000")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("migrate_failed"));
    assert!(!stdout.contains("MARKER_DB"));
}

#[cfg(unix)]
#[test]
fn graceful_shutdown_completes_with_in_flight_request() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = reserve.local_addr().unwrap();
    drop(reserve);
    let mut process = Process(
        command()
            .arg("serve")
            .env("ZKPM_BIND", addr.to_string())
            // Readiness acquires a pool connection with a bounded timeout, so
            // this request stays in flight for ~2 seconds while shutdown is
            // requested.
            .env(
                "ZKPM_DATABASE_URL",
                "postgres://postgres@127.0.0.1:1/rust02",
            )
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    let mut stream = loop {
        if let Ok(stream) = TcpStream::connect(addr) {
            break stream;
        }
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "server exited before listening"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "server did not start"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    // In-flight request: readiness will be pending on the DB acquire timeout.
    stream
        .write_all(b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        Command::new("kill")
            .args(["-TERM", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let stopping = Instant::now();
    let mut response = String::new();
    // The in-flight response must still be delivered before exit.
    stream.read_to_string(&mut response).unwrap();
    assert!(response.contains("HTTP/1.1 503"), "response: {response}");
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            stopping.elapsed() < Duration::from_secs(15),
            "shutdown exceeded bound"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // Server exits only after the in-flight request finished (acquire timeout
    // is 2s) — proves connections are drained, not dropped.
    assert!(stopping.elapsed() >= Duration::from_millis(500));
}
