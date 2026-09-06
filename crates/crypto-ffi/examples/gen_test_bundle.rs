//! D02-MVP test-fixture generator (not part of crypto-ffi's public API
//! surface — this is an `examples/` binary, invoked manually, that uses
//! `crypto-core` directly the same way `crates/crypto-ffi/src/lib.rs`'s own
//! `persisted_wrapper_lifecycle_opens_an_opaque_item_session` test does, to
//! produce a fixed, valid `PersistedItemAccess`-shaped fixture for
//! `apps/android`'s Kotlin unit tests (which cannot call
//! `wrap_account_key_with_password`/`wrap_vault_key`/`wrap_item_key` —
//! those are deliberately *not* exported through the UniFFI boundary in
//! this task, see docs/tasks/D02-MVP.md). Prints one JSON object to stdout;
//! run via `cargo run --example gen_test_bundle -p crypto-ffi` and redirect
//! the output into a checked-in fixture file.
use crypto_core::kdf::{derive_unlock_key, KdfParams};
use crypto_core::keys::{
    wrap_account_key_with_password, wrap_item_key, wrap_vault_key, AccountKey, ItemKey, VaultKey,
};

/// Minimal standard (RFC 4648, padded) base64 encoder — avoids adding a new
/// crate dependency (subject to DEPENDENCY-POLICY.md's ADR/integrator
/// approval requirement) for this test-fixture-only tool.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[((n >> 6) & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(n & 0x3f) as usize] as char } else { '=' });
    }
    out
}

fn b64(bytes: &[u8]) -> String {
    format!("b64:{}", base64_encode(bytes))
}

fn main() {
    let password = b"correct horse battery staple".to_vec();
    let account_id = "acct-fixture-01";
    let vault_id = "vault-fixture-01";
    let item_id = "item-fixture-01";

    // Small-but-valid Argon2id parameters (same values used by
    // crypto-ffi's own `persisted_wrapper_lifecycle_opens_an_opaque_item_session`
    // test) so the fixture derives fast in a JVM unit-test run.
    let params = KdfParams::new(65_536, 3, 1, &[0u8; 16]).unwrap();
    let reported_physical_memory_kib: u64 = 65_536 * 4;
    let unlock = derive_unlock_key(&password, &params, reported_physical_memory_kib).unwrap();

    let account = AccountKey::generate();
    let vault = VaultKey::generate();
    let item = ItemKey::generate();

    let wrapped_account_key =
        wrap_account_key_with_password(&unlock, &account, account_id, 1).unwrap();
    let wrapped_vault_key = wrap_vault_key(&account, &vault, account_id, vault_id, 1).unwrap();
    let wrapped_item_key =
        wrap_item_key(&vault, &item, account_id, vault_id, item_id, 1).unwrap();
    // Not used by ItemSession::unlock (which never reads a recovery
    // wrapper); parseAccountBundle only validates it's a bounded b64
    // string, so arbitrary bytes of a plausible size are fine here.
    let wrapped_recovery_key = vec![0xABu8; 64];

    let kdf_cbor = params.encode_canonical_cbor().unwrap();

    println!("{{");
    println!("  \"password\": \"{}\",", String::from_utf8(password).unwrap());
    println!("  \"accountId\": \"{account_id}\",");
    println!("  \"vaultId\": \"{vault_id}\",");
    println!("  \"itemId\": \"{item_id}\",");
    println!(
        "  \"reportedPhysicalMemoryKib\": {reported_physical_memory_kib},"
    );
    println!("  \"kdfParametersCbor\": \"{}\",", b64(&kdf_cbor));
    println!("  \"wrappedAccountKey\": \"{}\",", b64(&wrapped_account_key));
    println!("  \"wrappedVaultKey\": \"{}\",", b64(&wrapped_vault_key));
    println!("  \"wrappedItemKey\": \"{}\",", b64(&wrapped_item_key));
    println!("  \"wrappedRecoveryKey\": \"{}\"", b64(&wrapped_recovery_key));
    println!("}}");
}
