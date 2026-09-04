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
    open_account_key_with_password, open_account_key_with_recovery, open_item_key,
    open_item_payload, open_vault_key, seal_item_payload, wrap_account_key_with_password,
    wrap_item_key, wrap_vault_key, AccountKey, ItemKey, RecoveryKey, VaultKey,
};
use crypto_core::recovery::RecoveryKit;
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

fn object(entries: &[(&str, JsValue)]) -> Result<JsValue, JsValue> {
    let result = Object::new();
    for (name, value) in entries {
        Reflect::set(&result, &(*name).into(), value).map_err(|_| JsValue::from_str("Internal"))?;
    }
    Ok(result.into())
}

fn bytes(value: &[u8]) -> JsValue {
    js_sys::Uint8Array::from(value).into()
}

#[wasm_bindgen]
pub fn protocol_status() -> String {
    crypto_core::protocol_status().to_owned()
}

// ADR-0007: production browser-side OPAQUE client binding. Mechanical
// byte-in/byte-out wrappers around `crypto_core::opaque`'s existing client
// helpers, moved here from `packages/crypto-server`'s test-only `test_client`
// module (which stays as-is, for that crate's own in-process test suite).
// No new cryptography; `packages/sdk` owns the HTTP register/login
// choreography and session handling, this module only ever
// returns/consumes protocol message bytes and opaque state bytes.

/// Start OPAQUE client registration. `password` is zeroized on the Rust
/// side after use, matching `unlock_item_session` above; the caller-owned
/// JS buffer cannot be wiped across the wasm boundary. Returns
/// `{ message, state }`: send `message` to `/auth/opaque/register` as the
/// first leg's `clientMessage`; hold `state` opaquely and pass it unmodified
/// to `client_registration_finish`.
#[wasm_bindgen]
pub fn client_registration_start(password: Vec<u8>) -> Result<JsValue, JsValue> {
    let password = Zeroizing::new(password);
    let result = crypto_core::opaque::client_registration_start(&password).map_err(error)?;
    object(&[
        ("message", bytes(&result.message)),
        ("state", bytes(&result.state_bytes())),
    ])
}

/// Finish OPAQUE client registration against the server's first-leg
/// response. Returns `{ message }`: send `message` to
/// `/auth/opaque/register` as the second leg's `clientMessage`.
#[wasm_bindgen]
pub fn client_registration_finish(
    state: Vec<u8>,
    password: Vec<u8>,
    response: Vec<u8>,
) -> Result<JsValue, JsValue> {
    let password = Zeroizing::new(password);
    let state = crypto_core::opaque::client_registration_state(&state).map_err(error)?;
    let result = crypto_core::opaque::client_registration_finish(state, &password, &response)
        .map_err(error)?;
    object(&[("message", bytes(&result.message))])
}

/// Start OPAQUE client login. Returns `{ message, state }`: send `message`
/// to `/auth/opaque/login` as the first leg's `clientMessage`; hold `state`
/// opaquely and pass it unmodified to `client_login_finish`.
#[wasm_bindgen]
pub fn client_login_start(password: Vec<u8>) -> Result<JsValue, JsValue> {
    let password = Zeroizing::new(password);
    let result = crypto_core::opaque::client_login_start(&password).map_err(error)?;
    object(&[
        ("message", bytes(&result.message)),
        ("state", bytes(&result.state_bytes())),
    ])
}

/// Finish OPAQUE client login against the server's KE2 challenge. `context`
/// must be the exact same application-context bytes the server uses
/// (`OPAQUE_CONTEXT = "zkpm-opaque-v1"` in `apps/backend/src/auth/routes.mjs`)
/// or the real backend rejects the login generically. Returns
/// `{ message }`: send `message` to `/auth/opaque/login` as the second
/// leg's `clientMessage`.
#[wasm_bindgen]
pub fn client_login_finish(
    state: Vec<u8>,
    password: Vec<u8>,
    response: Vec<u8>,
    context: Vec<u8>,
) -> Result<JsValue, JsValue> {
    let password = Zeroizing::new(password);
    let state = crypto_core::opaque::client_login_state(&state).map_err(error)?;
    let result = crypto_core::opaque::client_login_finish(state, &password, &response, &context)
        .map_err(error)?;
    object(&[("message", bytes(&result.message))])
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

    /// Runtime-only setup path: creates fresh keys internally and returns only
    /// encrypted wrappers plus canonical public metadata. No key bytes leave
    /// WASM; this enables binding lifecycle tests without static fixtures.
    #[wasm_bindgen]
    pub fn create_item_session_for_setup(
        &mut self,
        password: Vec<u8>,
        reported_physical_memory_kib: u64,
    ) -> Result<JsValue, JsValue> {
        let password = Zeroizing::new(password);
        let params = KdfParams::generate(65_536, 3, 1).map_err(error)?;
        let unlock =
            derive_unlock_key(&password, &params, reported_physical_memory_kib).map_err(error)?;
        let account = AccountKey::generate();
        let vault = VaultKey::generate();
        let item = ItemKey::generate();
        let account_id = "runtime-account";
        let vault_id = "runtime-vault";
        let item_id = "runtime-item";
        let account_wrap =
            wrap_account_key_with_password(&unlock, &account, account_id, 1).map_err(error)?;
        let vault_wrap =
            wrap_vault_key(&account, &vault, account_id, vault_id, 1).map_err(error)?;
        let item_wrap =
            wrap_item_key(&vault, &item, account_id, vault_id, item_id, 1).map_err(error)?;
        let session = self.next_session;
        self.next_session += 1;
        self.sessions.insert(session, item);
        let result = Object::new();
        for (name, value) in [
            ("accountId", JsValue::from_str(account_id)),
            ("vaultId", JsValue::from_str(vault_id)),
            ("itemId", JsValue::from_str(item_id)),
            ("session", JsValue::from_f64(f64::from(session))),
        ] {
            Reflect::set(&result, &name.into(), &value)
                .map_err(|_| JsValue::from_str("Internal"))?;
        }
        for (name, value) in [
            (
                "kdfParametersCbor",
                params.encode_canonical_cbor().map_err(error)?,
            ),
            ("wrappedAccountKey", account_wrap),
            ("wrappedVaultKey", vault_wrap),
            ("wrappedItemKey", item_wrap),
        ] {
            Reflect::set(
                &result,
                &name.into(),
                &js_sys::Uint8Array::from(value.as_slice()),
            )
            .map_err(|_| JsValue::from_str("Internal"))?;
        }
        Ok(result.into())
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

    // ADR-0008 addition (C01): account-setup for real registration. Unlike
    // `create_item_session_for_setup` above (which hardcodes synthetic ids
    // for binding lifecycle tests), this accepts caller-supplied
    // `account_id`/`vault_id`/`item_id` so the wrapped material lines up
    // with the identifiers the caller actually persists and sends to the
    // backend. It mirrors that method's shape (fresh AccountKey/VaultKey/
    // ItemKey, password wrap, vault wrap, item wrap, open session) and
    // additionally wraps the AccountKey independently under a fresh
    // RecoveryKey (`crypto_core::recovery::RecoveryKit::generate`),
    // returning the recovery key's raw bytes exactly once. The caller must
    // display those bytes for the user to save and never persist them.
    //
    // MVP key-hierarchy scope note: C01 uses a single vault-wide ItemKey
    // (wrapped once here under a caller-chosen synthetic `item_id`, e.g.
    // "vault-key") to encrypt every item in the vault, distinguishing
    // items only via the per-item AAD context (`item_id`, `key_version`)
    // passed to `seal_item_payload`/`open_item_payload` — not via a
    // separate wrapped ItemKey per item. True per-item key issuance would
    // need a further WASM export outside ADR-0008's narrow grant
    // (account-setup + recovery-kit opening only) and is deferred; see the
    // completion report's Known limitations.
    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn create_account_setup(
        &mut self,
        password: Vec<u8>,
        reported_physical_memory_kib: u64,
        account_id: String,
        vault_id: String,
        item_id: String,
    ) -> Result<JsValue, JsValue> {
        let password = Zeroizing::new(password);
        let params = KdfParams::generate(65_536, 3, 1).map_err(error)?;
        let unlock =
            derive_unlock_key(&password, &params, reported_physical_memory_kib).map_err(error)?;
        let account = AccountKey::generate();
        let vault = VaultKey::generate();
        let item = ItemKey::generate();
        let account_wrap =
            wrap_account_key_with_password(&unlock, &account, &account_id, 1).map_err(error)?;
        let vault_wrap =
            wrap_vault_key(&account, &vault, &account_id, &vault_id, 1).map_err(error)?;
        let item_wrap =
            wrap_item_key(&vault, &item, &account_id, &vault_id, &item_id, 1).map_err(error)?;
        let (recovery_key, kit) = RecoveryKit::generate(&account, &account_id, 1).map_err(error)?;
        let session = self.next_session;
        self.next_session += 1;
        self.sessions.insert(session, item);
        let result = Object::new();
        for (name, value) in [
            ("accountId", JsValue::from_str(&account_id)),
            ("vaultId", JsValue::from_str(&vault_id)),
            ("itemId", JsValue::from_str(&item_id)),
            ("session", JsValue::from_f64(f64::from(session))),
        ] {
            Reflect::set(&result, &name.into(), &value)
                .map_err(|_| JsValue::from_str("Internal"))?;
        }
        for (name, value) in [
            (
                "kdfParametersCbor",
                params.encode_canonical_cbor().map_err(error)?,
            ),
            ("wrappedAccountKey", account_wrap),
            ("wrappedVaultKey", vault_wrap),
            ("wrappedItemKey", item_wrap),
            ("wrappedRecoveryKey", kit.wrapped_account_key().to_vec()),
        ] {
            Reflect::set(
                &result,
                &name.into(),
                &js_sys::Uint8Array::from(value.as_slice()),
            )
            .map_err(|_| JsValue::from_str("Internal"))?;
        }
        // Returned exactly once: the caller must display it for the user to
        // save (per ADR-0008 §2, provisional labeling only) and must never
        // persist it itself.
        Reflect::set(
            &result,
            &"recoveryKey".into(),
            &js_sys::Uint8Array::from(recovery_key.as_bytes().as_slice()),
        )
        .map_err(|_| JsValue::from_str("Internal"))?;
        Ok(result.into())
    }

    // ADR-0008 addition (C01): open an item session using the recovery key
    // instead of the password, mirroring `unlock_item_session`'s shape
    // exactly (same wrapped-material parameters, same session-handle
    // return) but substituting `open_account_key_with_recovery` for the
    // password-derived unlock. Used both for the registration
    // reveal/confirm step (proving the user captured the correct recovery
    // key by actually opening the account with it) and, in principle, for
    // a future account-recovery unlock path — this export alone does not
    // implement password reset (`/account/recovery-reset` stays blocked).
    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn unlock_item_session_with_recovery(
        &mut self,
        recovery_key: Vec<u8>,
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
        let recovery_key_bytes = Zeroizing::new(recovery_key);
        let wrapped_account_key = Zeroizing::new(wrapped_account_key);
        let wrapped_vault_key = Zeroizing::new(wrapped_vault_key);
        let wrapped_item_key = Zeroizing::new(wrapped_item_key);
        let recovery_key = RecoveryKey::from_bytes(&recovery_key_bytes).map_err(error)?;
        let account = open_account_key_with_recovery(
            &recovery_key,
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
