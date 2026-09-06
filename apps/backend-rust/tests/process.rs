use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zkpm-backend-poc"));
    command
        .env_remove("POC_BIND")
        .env_remove("POC_DATABASE_URL")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
fn invalid_configuration_exits_without_echoing_input() {
    let output = command()
        .env("POC_DATABASE_URL", "CONFIG_MARKER")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("configuration_invalid"));
    assert!(!stdout.contains("CONFIG_MARKER"));
    assert!(output.stderr.is_empty());
}

#[test]
fn occupied_port_fails_with_safe_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let output = command()
        .env("POC_BIND", listener.local_addr().unwrap().to_string())
        .env(
            "POC_DATABASE_URL",
            "postgres://postgres@127.0.0.1:1/rust01_poc",
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("bind_failed")
    );
    assert!(output.stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn actual_http_listener_and_sigterm_shutdown() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = reserve.local_addr().unwrap();
    drop(reserve);
    let mut process = Process(
        command()
            .env("POC_BIND", addr.to_string())
            .env(
                "POC_DATABASE_URL",
                "postgres://postgres@127.0.0.1:1/rust01_poc",
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
            start.elapsed() < Duration::from_secs(5),
            "server did not start"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(b"GET /health/live HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("{\"status\":\"ok\"}"));
    assert!(
        Command::new("kill")
            .args(["-TERM", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let stopping = Instant::now();
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            stopping.elapsed() < Duration::from_secs(7),
            "shutdown exceeded bound"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
