#![forbid(unsafe_code)]
//! UniFFI-safe crypto-core boundary.
//!
//! This crate intentionally exports opaque session handles, never key bytes.
//! A handle owns an `ItemKey` only for its lifetime; `close` drops it early and
//! the core's `Zeroizing` key storage clears it on drop.  Callers may pass
//! envelope bytes and non-secret context identifiers, but cannot import,
//! export, serialize, debug, or persist raw keys through this API.

use std::sync::{Arc, Mutex};

use crypto_core::envelope::{encode_aad, inspect_envelope, Context, RecordKind};
use crypto_core::kdf::{derive_unlock_key, KdfParams};
use crypto_core::keys::{
    open_account_key_with_password, open_item_key, open_item_payload, open_vault_key,
    seal_item_payload, ItemKey,
};
use crypto_core::Error;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CryptoFfiError {
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("non-canonical cbor")]
    NonCanonicalCbor,
    #[error("unknown field")]
    UnknownField,
    #[error("invalid context")]
    InvalidContext,
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("invalid kdf parameters")]
    InvalidKdfParameters,
    #[error("kdf resource limit")]
    KdfResourceLimit,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid recovery kit")]
    InvalidRecoveryKit,
    #[error("locked")]
    Locked,
    #[error("internal error")]
    Internal,
}

impl From<Error> for CryptoFfiError {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidEncoding => Self::InvalidEncoding,
            Error::UnsupportedVersion => Self::UnsupportedVersion,
            Error::NonCanonicalCbor => Self::NonCanonicalCbor,
            Error::UnknownField => Self::UnknownField,
            Error::InvalidContext => Self::InvalidContext,
            Error::InvalidNonce => Self::InvalidNonce,
            Error::AuthenticationFailed => Self::AuthenticationFailed,
            Error::InvalidKdfParameters => Self::InvalidKdfParameters,
            Error::KdfResourceLimit => Self::KdfResourceLimit,
            Error::InvalidKeyLength => Self::InvalidKeyLength,
            Error::InvalidRecoveryKit => Self::InvalidRecoveryKit,
            Error::Locked => Self::Locked,
            Error::Internal => Self::Internal,
        }
    }
}

#[derive(uniffi::Record)]
pub struct EnvelopeMetadata {
    pub account_id: String,
    pub vault_id: Option<String>,
    pub item_id: Option<String>,
    pub record_kind: String,
    pub key_version: u64,
}

/// Persisted, encrypted hierarchy inputs required to open one item. This is
/// deliberately envelopes/metadata only: it cannot contain a plaintext key.
#[derive(uniffi::Record)]
pub struct PersistedItemAccess {
    pub account_id: String,
    pub vault_id: String,
    pub item_id: String,
    pub account_key_version: u64,
    pub vault_key_version: u64,
    pub item_key_version: u64,
    pub kdf_parameters_cbor: Vec<u8>,
    pub reported_physical_memory_kib: u64,
    pub wrapped_account_key: Vec<u8>,
    pub wrapped_vault_key: Vec<u8>,
    pub wrapped_item_key: Vec<u8>,
}

fn item_context<'a>(
    account_id: &'a str,
    vault_id: &'a str,
    item_id: &'a str,
    key_version: u64,
) -> Context<'a> {
    Context {
        account_id,
        vault_id: Some(vault_id),
        item_id: Some(item_id),
        record_kind: RecordKind::ItemPayload,
        key_version,
    }
}

/// An opaque, in-memory item-key capability. It cannot be reconstructed from
/// FFI values and is invalid permanently after `close`.
#[derive(uniffi::Object)]
pub struct ItemSession {
    key: Mutex<Option<ItemKey>>,
}

#[uniffi::export]
impl ItemSession {
    #[uniffi::constructor]
    pub fn create() -> Arc<Self> {
        Arc::new(Self {
            key: Mutex::new(Some(ItemKey::generate())),
        })
    }

    /// Opens persisted wrappers entirely inside Rust. Password and derived
    /// keys never become return values or serializable FFI fields.
    #[uniffi::constructor]
    pub fn unlock(
        password: Vec<u8>,
        access: PersistedItemAccess,
    ) -> Result<Arc<Self>, CryptoFfiError> {
        let password = Zeroizing::new(password);
        let params = KdfParams::decode_canonical_cbor(
            &access.kdf_parameters_cbor,
            access.reported_physical_memory_kib,
        )?;
        let unlock = derive_unlock_key(&password, &params, access.reported_physical_memory_kib)?;
        let account = open_account_key_with_password(
            &unlock,
            &access.wrapped_account_key,
            &access.account_id,
            access.account_key_version,
        )?;
        let vault = open_vault_key(
            &account,
            &access.wrapped_vault_key,
            &access.account_id,
            &access.vault_id,
            access.vault_key_version,
        )?;
        let item = open_item_key(
            &vault,
            &access.wrapped_item_key,
            &access.account_id,
            &access.vault_id,
            &access.item_id,
            access.item_key_version,
        )?;
        Ok(Arc::new(Self {
            key: Mutex::new(Some(item)),
        }))
    }

    pub fn seal_item_payload(
        &self,
        account_id: String,
        vault_id: String,
        item_id: String,
        key_version: u64,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoFfiError> {
        let key = self.key.lock().map_err(|_| CryptoFfiError::Internal)?;
        let key = key.as_ref().ok_or(CryptoFfiError::Locked)?;
        seal_item_payload(
            key,
            &account_id,
            &vault_id,
            &item_id,
            key_version,
            &plaintext,
        )
        .map_err(Into::into)
    }

    pub fn open_item_payload(
        &self,
        account_id: String,
        vault_id: String,
        item_id: String,
        key_version: u64,
        envelope: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoFfiError> {
        let key = self.key.lock().map_err(|_| CryptoFfiError::Internal)?;
        let key = key.as_ref().ok_or(CryptoFfiError::Locked)?;
        Ok(open_item_payload(
            key,
            &account_id,
            &vault_id,
            &item_id,
            key_version,
            &envelope,
        )
        .map_err(CryptoFfiError::from)?
        .to_vec())
    }

    /// End this capability's lifetime. Repeated closes are harmless.
    pub fn close(&self) -> Result<(), CryptoFfiError> {
        let mut key = self.key.lock().map_err(|_| CryptoFfiError::Internal)?;
        *key = None;
        Ok(())
    }
}

#[uniffi::export]
pub fn protocol_status() -> String {
    crypto_core::protocol_status().to_owned()
}

/// Exposes public AAD bytes only; key operations remain session-bound.
#[uniffi::export]
pub fn encode_item_payload_aad(
    account_id: String,
    vault_id: String,
    item_id: String,
    key_version: u64,
) -> Result<Vec<u8>, CryptoFfiError> {
    encode_aad(&item_context(&account_id, &vault_id, &item_id, key_version)).map_err(Into::into)
}

#[uniffi::export]
pub fn inspect(envelope: Vec<u8>) -> Result<EnvelopeMetadata, CryptoFfiError> {
    let context = inspect_envelope(&envelope).map_err(CryptoFfiError::from)?;
    Ok(EnvelopeMetadata {
        account_id: context.account_id.to_owned(),
        vault_id: context.vault_id.map(str::to_owned),
        item_id: context.item_id.map(str::to_owned),
        record_kind: context.record_kind.as_str().to_owned(),
        key_version: context.key_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_binding_never_exports_a_raw_key_and_closes_sessions() {
        let session = ItemSession::create();
        let envelope = session
            .seal_item_payload("acct".into(), "vault".into(), "item".into(), 1, vec![1, 2])
            .unwrap();
        assert_eq!(
            session
                .open_item_payload("acct".into(), "vault".into(), "item".into(), 1, envelope)
                .unwrap(),
            vec![1, 2]
        );
        session.close().unwrap();
        assert!(matches!(
            session.seal_item_payload("acct".into(), "vault".into(), "item".into(), 1, vec![1]),
            Err(CryptoFfiError::Locked)
        ));
    }

    #[test]
    fn aad_matches_the_cross_language_golden_vector() {
        assert_eq!(
            encode_item_payload_aad("account_01".into(), "vault_01".into(), "item_01".into(), 1).unwrap(),
            hex("a6017263727970746f2d656e76656c6f70652f7631026a6163636f756e745f303103687661756c745f303104676974656d5f3031056c6974656d2d7061796c6f61640601")
        );
    }

    #[test]
    fn persisted_wrapper_lifecycle_opens_an_opaque_item_session() {
        use crypto_core::keys::{
            wrap_account_key_with_password, wrap_item_key, wrap_vault_key, AccountKey, VaultKey,
        };

        let password = vec![7];
        let params = KdfParams::new(65_536, 3, 1, &[0; 16]).unwrap();
        let unlock = derive_unlock_key(&password, &params, 65_536 * 4).unwrap();
        let account = AccountKey::generate();
        let vault = VaultKey::generate();
        let item = ItemKey::generate();
        let access = PersistedItemAccess {
            account_id: "acct".into(),
            vault_id: "vault".into(),
            item_id: "item".into(),
            account_key_version: 1,
            vault_key_version: 1,
            item_key_version: 1,
            kdf_parameters_cbor: params.encode_canonical_cbor().unwrap(),
            reported_physical_memory_kib: 65_536 * 4,
            wrapped_account_key: wrap_account_key_with_password(&unlock, &account, "acct", 1)
                .unwrap(),
            wrapped_vault_key: wrap_vault_key(&account, &vault, "acct", "vault", 1).unwrap(),
            wrapped_item_key: wrap_item_key(&vault, &item, "acct", "vault", "item", 1).unwrap(),
        };
        let session = ItemSession::unlock(password, access).unwrap();
        let envelope = session
            .seal_item_payload("acct".into(), "vault".into(), "item".into(), 1, vec![3])
            .unwrap();
        assert_eq!(
            session
                .open_item_payload("acct".into(), "vault".into(), "item".into(), 1, envelope)
                .unwrap(),
            vec![3]
        );
    }

    fn hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }
}
