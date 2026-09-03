#![forbid(unsafe_code)]
//! Browser WASM bindings generated with wasm-bindgen.
//!
//! This boundary deliberately exports public envelope metadata/AAD utilities
//! only. Persisted-key unlocking is currently exposed through UniFFI while
//! the OPAQUE transport/session architecture is awaiting B04 integration;
//! there is no byte-array key import or export in this module.

use crypto_core::envelope::{encode_aad, Context, RecordKind};
use wasm_bindgen::prelude::*;

fn error(error: crypto_core::Error) -> JsValue {
    JsValue::from_str(match error {
        crypto_core::Error::InvalidEncoding => "InvalidEncoding",
        crypto_core::Error::UnsupportedVersion => "UnsupportedVersion",
        crypto_core::Error::NonCanonicalCbor => "NonCanonicalCbor",
        crypto_core::Error::UnknownField => "UnknownField",
        crypto_core::Error::InvalidContext => "InvalidContext",
        crypto_core::Error::InvalidNonce => "InvalidNonce",
        crypto_core::Error::AuthenticationFailed => "AuthenticationFailed",
        crypto_core::Error::InvalidKdfParameters => "InvalidKdfParameters",
        crypto_core::Error::KdfResourceLimit => "KdfResourceLimit",
        crypto_core::Error::InvalidKeyLength => "InvalidKeyLength",
        crypto_core::Error::InvalidRecoveryKit => "InvalidRecoveryKit",
        crypto_core::Error::Locked => "Locked",
        crypto_core::Error::Internal => "Internal",
    })
}

#[wasm_bindgen]
pub fn protocol_status() -> String {
    crypto_core::protocol_status().to_owned()
}

/// Actual WASM export used for the cross-binding canonical-AAD golden vector.
/// It accepts identifiers only and cannot observe or return a key.
#[wasm_bindgen]
pub fn encode_item_payload_aad(
    account_id: String,
    vault_id: String,
    item_id: String,
    key_version: u64,
) -> Result<Vec<u8>, JsValue> {
    encode_aad(&Context {
        account_id: &account_id,
        vault_id: Some(&vault_id),
        item_id: Some(&item_id),
        record_kind: RecordKind::ItemPayload,
        key_version,
    })
    .map_err(error)
}
