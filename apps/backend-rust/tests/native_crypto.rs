use crypto_core::{Error, keys::AccountKey, opaque};

#[tokio::test]
async fn native_opaque_round_trip_uses_existing_core_only() {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore.acquire_owned().await.unwrap();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        // Fresh ephemeral bytes supplied by the approved core; never a stored password fixture.
        let input = AccountKey::generate();
        let result = opaque::round_trip(input.as_bytes(), b"RUST-01-native-smoke");
        assert!(result.is_ok(), "native OPAQUE round-trip failed");
        let (session, export) = result.unwrap();
        assert_eq!(session.len(), 64);
        assert_eq!(export.len(), 64);
        // Secret buffers are dropped/zeroized; no assertion formats their contents.
    })
    .await
    .unwrap();
}

#[test]
fn native_core_rejects_malformed_remote_messages_generically() {
    let setup = opaque::ServerSetupHandle::generate();
    assert!(matches!(
        opaque::server_registration_start(&setup, &[], b"RUST-01"),
        Err(Error::AuthenticationFailed)
    ));
    assert!(matches!(
        opaque::server_registration_finish(&[]),
        Err(Error::AuthenticationFailed)
    ));
    assert!(matches!(
        opaque::server_login_state(&[]),
        Err(Error::InvalidEncoding)
    ));
}
