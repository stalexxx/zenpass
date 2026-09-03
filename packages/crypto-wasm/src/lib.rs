#![forbid(unsafe_code)]
//! Browser WASM bindings generated with wasm-bindgen.
//!
//! This boundary deliberately exports public envelope metadata/AAD utilities
//! only. Persisted-key unlocking is currently exposed through UniFFI while
//! the OPAQUE transport/session architecture is awaiting B04 integration;
//! there is no byte-array key import or export in this module.

use std::collections::HashMap;

use crypto_core::envelope::{encode_aad, inspect_envelope, Context, RecordKind};
use crypto_core::kdf::{derive_unlock_key, KdfParams};
use crypto_core::keys::{
    open_account_key_with_password, open_item_key, open_item_payload, open_vault_key,
    seal_item_payload, ItemKey,
};
use js_sys::{Object, Reflect};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

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

/// Browser-owned capability store. Keys never leave this Rust object; JS sees
/// only numeric session ids and encrypted/public bytes.
#[wasm_bindgen]
pub struct WasmCrypto {
    sessions: HashMap<u32, ItemKey>,
    next_session: u32,
}

#[wasm_bindgen]
impl WasmCrypto {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmCrypto {
        WasmCrypto {
            sessions: HashMap::new(),
            next_session: 1,
        }
    }

    /// Opens the persisted password/account/vault/item envelope hierarchy
    /// inside WASM. This is intentionally not an OPAQUE exchange: B03 has no
    /// server transport authority and must not simulate one.
    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn unlock_item_session(
        &mut self,
        password: Vec<u8>,
        kdf_parameters_cbor: Vec<u8>,
        reported_physical_memory_kib: u64,
        account_id: String,
        vault_id: String,
        item_id: String,
        account_key_version: u64,
        vault_key_version: u64,
        item_key_version: u64,
        wrapped_account_key: Vec<u8>,
        wrapped_vault_key: Vec<u8>,
        wrapped_item_key: Vec<u8>,
    ) -> Result<u32, JsValue> {
        // wasm-bindgen transfers JS byte arrays into these owned Vec values.
        // Zeroizing overwrites their WASM linear-memory allocations before
        // deallocation on both success and every early-error return. The
        // caller-owned JS Uint8Array cannot be wiped across that boundary.
        let password = Zeroizing::new(password);
        let kdf_parameters_cbor = Zeroizing::new(kdf_parameters_cbor);
        let wrapped_account_key = Zeroizing::new(wrapped_account_key);
        let wrapped_vault_key = Zeroizing::new(wrapped_vault_key);
        let wrapped_item_key = Zeroizing::new(wrapped_item_key);
        let params =
            KdfParams::decode_canonical_cbor(&kdf_parameters_cbor, reported_physical_memory_kib)
                .map_err(error)?;
        let unlock =
            derive_unlock_key(&password, &params, reported_physical_memory_kib).map_err(error)?;
        let account = open_account_key_with_password(
            &unlock,
            &wrapped_account_key,
            &account_id,
            account_key_version,
        )
        .map_err(error)?;
        let vault = open_vault_key(
            &account,
            &wrapped_vault_key,
            &account_id,
            &vault_id,
            vault_key_version,
        )
        .map_err(error)?;
        let item = open_item_key(
            &vault,
            &wrapped_item_key,
            &account_id,
            &vault_id,
            &item_id,
            item_key_version,
        )
        .map_err(error)?;
        let id = self.next_session;
        self.next_session = self
            .next_session
            .checked_add(1)
            .ok_or_else(|| JsValue::from_str("Internal"))?;
        self.sessions.insert(id, item);
        Ok(id)
    }

    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn seal_item_payload(
        &self,
        session: u32,
        account_id: String,
        vault_id: String,
        item_id: String,
        key_version: u64,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        let key = self
            .sessions
            .get(&session)
            .ok_or_else(|| JsValue::from_str("Locked"))?;
        seal_item_payload(
            key,
            &account_id,
            &vault_id,
            &item_id,
            key_version,
            &plaintext,
        )
        .map_err(error)
    }

    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn open_item_payload(
        &self,
        session: u32,
        account_id: String,
        vault_id: String,
        item_id: String,
        key_version: u64,
        envelope: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        let key = self
            .sessions
            .get(&session)
            .ok_or_else(|| JsValue::from_str("Locked"))?;
        Ok(open_item_payload(
            key,
            &account_id,
            &vault_id,
            &item_id,
            key_version,
            &envelope,
        )
        .map_err(error)?
        .to_vec())
    }

    #[wasm_bindgen]
    pub fn close_session(&mut self, session: u32) {
        self.sessions.remove(&session);
    }

    #[wasm_bindgen]
    pub fn inspect_envelope(&self, envelope: Vec<u8>) -> Result<JsValue, JsValue> {
        let ctx = inspect_envelope(&envelope).map_err(error)?;
        let metadata = Object::new();
        Reflect::set(&metadata, &"accountId".into(), &ctx.account_id.into())
            .map_err(|_| JsValue::from_str("Internal"))?;
        Reflect::set(
            &metadata,
            &"vaultId".into(),
            &ctx.vault_id.map(str::to_owned).into(),
        )
        .map_err(|_| JsValue::from_str("Internal"))?;
        Reflect::set(
            &metadata,
            &"itemId".into(),
            &ctx.item_id.map(str::to_owned).into(),
        )
        .map_err(|_| JsValue::from_str("Internal"))?;
        Reflect::set(
            &metadata,
            &"recordKind".into(),
            &ctx.record_kind.as_str().into(),
        )
        .map_err(|_| JsValue::from_str("Internal"))?;
        Reflect::set(
            &metadata,
            &"keyVersion".into(),
            &JsValue::from_f64(ctx.key_version as f64),
        )
        .map_err(|_| JsValue::from_str("Internal"))?;
        Ok(metadata.into())
    }
}
