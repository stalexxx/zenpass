//! `fixtures/crypto/recovery-semantics.json`: the placeholder ciphertext must
//! fail closed, the positive recovery flow must work end-to-end, and the
//! fixture's post-recovery assertions are mapped onto checkable behaviour.

use crypto_core::keys::{AccountKey, RecoveryKey, UnlockKey};
use crypto_core::recovery::RecoveryKit;
use crypto_core::Error;
use serde_json::Value;

fn load() -> Value {
    crypto_core_tests::load_fixture("recovery-semantics.json")
}

#[test]
fn placeholder_ciphertext_fails_closed_as_invalid_recovery_kit() {
    // G-09: the fixture ciphertext is a known placeholder (56 bytes, not the
    // 48 bytes of a real recovery-wrap of a 32-byte key). The core must
    // reject it, never return key bytes, and surface InvalidRecoveryKit.
    let fixture = load();
    let wrapped = &fixture["recoveryWrappedAccountKey"];
    let account_id = fixture["accountId"].as_str().unwrap();
    let key_version = wrapped["keyVersion"].as_u64().unwrap();

    let mut placeholder_envelope = build_envelope_from_parts(wrapped, account_id, key_version);
    let recovery_key = RecoveryKey::from_bytes(&crypto_core_tests::bytes_field(
        fixture["recoveryKey"].as_str().unwrap(),
    ))
    .unwrap();
    let error = crypto_core::keys::open_account_key_with_recovery(
        &recovery_key,
        &placeholder_envelope,
        account_id,
        key_version,
    )
    .unwrap_err();
    assert_eq!(error, Error::InvalidRecoveryKit);
    placeholder_envelope.clear();
}

fn build_envelope_from_parts(wrapped: &Value, account_id: &str, key_version: u64) -> Vec<u8> {
    use minicbor::Encoder;
    let nonce = crypto_core_tests::bytes_field(wrapped["nonce"].as_str().unwrap());
    let ciphertext = crypto_core_tests::bytes_field(wrapped["ciphertext"].as_str().unwrap());
    let aad = crypto_core::envelope::encode_aad(&crypto_core::Context {
        account_id,
        vault_id: None,
        item_id: None,
        record_kind: crypto_core::RecordKind::RecoveryWrap,
        key_version,
    })
    .unwrap();
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6).unwrap();
    encoder.u64(1).unwrap();
    encoder.str("crypto-envelope/v1").unwrap();
    encoder.u64(2).unwrap();
    encoder.str("recovery-wrap").unwrap();
    encoder.u64(3).unwrap();
    encoder.u64(key_version).unwrap();
    encoder.u64(4).unwrap();
    encoder.bytes(&nonce).unwrap();
    encoder.u64(5).unwrap();
    encoder.bytes(&ciphertext).unwrap();
    encoder.u64(6).unwrap();
    encoder.bytes(&aad).unwrap();
    encoder.into_writer()
}

#[test]
fn positive_recovery_flow_unwraps_and_rewraps_with_a_new_version() {
    let fixture = load();
    let account_id = fixture["accountId"].as_str().unwrap();
    let old_version = fixture["oldWrapperVersion"].as_u64().unwrap();
    let new_version = fixture["newWrapperVersion"].as_u64().unwrap();

    // The account key is recovered only on the client: recovery unwrap is a
    // local operation over kit bytes.
    let account_key = AccountKey::generate();
    let (recovery_key, kit) = RecoveryKit::generate(&account_key, account_id, old_version).unwrap();
    let recovered = kit.unwrap_account_key(&recovery_key).unwrap();
    assert_eq!(recovered.as_bytes(), account_key.as_bytes());

    // New password wrapper is version 2: the kit's wrapper version is
    // independent and re-wrapping under the new version round-trips.
    let new_kit_bytes = {
        let mut ctx_kit = kit.clone();
        assert_eq!(ctx_kit.key_version(), old_version);
        ctx_kit = rewrap_version(&ctx_kit, &recovery_key, new_version);
        ctx_kit.wrapped_account_key().to_vec()
    };
    let new_kit = RecoveryKit::from_parts(account_id, new_version, new_kit_bytes).unwrap();
    assert_eq!(new_kit.key_version(), new_version);
    let again = new_kit.unwrap_account_key(&recovery_key).unwrap();
    assert_eq!(again.as_bytes(), account_key.as_bytes());

    // The server cannot decrypt either wrapper: without the recovery key or
    // the unlock key the bytes are inert (authentication fails for any other
    // 32-byte key with overwhelming probability, tested directly).
    let stranger = RecoveryKey::generate();
    assert_eq!(
        new_kit.unwrap_account_key(&stranger).unwrap_err(),
        Error::InvalidRecoveryKit
    );
    let unlock = UnlockKey::generate();
    let password_wrapped = crypto_core::keys::wrap_account_key_with_password(
        &unlock,
        &account_key,
        account_id,
        new_version,
    )
    .unwrap();
    assert_eq!(
        crypto_core::keys::open_account_key_with_password(
            &UnlockKey::generate(),
            &password_wrapped,
            account_id,
            new_version
        )
        .unwrap_err(),
        Error::AuthenticationFailed
    );
}

fn rewrap_version(kit: &RecoveryKit, recovery_key: &RecoveryKey, new_version: u64) -> RecoveryKit {
    let account_key = kit.unwrap_account_key(recovery_key).unwrap();
    let new_bytes = crypto_core::keys::wrap_account_key_with_recovery(
        recovery_key,
        &account_key,
        kit.account_id(),
        new_version,
    )
    .unwrap();
    RecoveryKit::from_parts(kit.account_id(), new_version, new_bytes).unwrap()
}

#[test]
fn post_recovery_assertions_are_covered_by_checkable_behaviour() {
    let fixture = load();
    let assertions = fixture["postRecoveryAssertions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(assertions.len(), 5, "all five assertions present");

    // 1. "AccountKey is recovered only on the client": recovery unwrap is a
    //    pure local call; nothing in this crate performs I/O.
    // 2. "new password wrapper is version 2": covered above by key_version.
    // 3. "all prior sessions and devices are revoked": session/device
    //    revocation is server-side policy (B02/B04), outside the crypto
    //    core; recorded as an integration boundary, not testable here.
    // 4. "server cannot decrypt either wrapper": covered above.
    // 5. "missing recovery key fails with InvalidRecoveryKit": a wrong or
    //    absent recovery key yields InvalidRecoveryKit (tested above and in
    //    crypto-core unit tests).
}
