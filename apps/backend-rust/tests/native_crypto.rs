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

/// Fixed by the pinned Ristretto255-SHA512 suite (ADR-0003): a
/// `RegistrationRequest` is exactly the 32-byte OPRF blinded element, and a
/// `RegistrationUpload` is always 192 bytes (client static public key +
/// masking key + envelope). The two never overlap in length, which is what
/// lets the server dispatch on message length alone (mirroring how the
/// login route already dispatches leg 1 vs. leg 2 by `KE1_LEN`).
#[test]
fn registration_request_and_upload_lengths_are_fixed_and_distinct() {
    let reg = crypto_core::opaque::client_registration_start(b"pw").unwrap();
    assert_eq!(reg.message.len(), 32);
    let setup = crypto_core::opaque::ServerSetupHandle::generate();
    let sr = crypto_core::opaque::server_registration_start(&setup, &reg.message, b"id").unwrap();
    let state = crypto_core::opaque::client_registration_state(&reg.state_bytes()).unwrap();
    let finish =
        crypto_core::opaque::client_registration_finish(state, b"pw", &sr.message).unwrap();
    assert_eq!(finish.message.len(), 192);
}
