//! Key hierarchy for `crypto-envelope/v1`.
//!
//! Keys are uniformly random 32-byte values generated from the OS CSPRNG;
//! they are never derived from identifiers or plaintext. Every key type is a
//! distinct newtype so a wrapper kind cannot be opened with the wrong role of
//! key at the type level where possible, and at the context level everywhere
//! else. All secret material lives in [`Zeroizing`] buffers and no `Debug`
//! implementation ever exposes key bytes.

use zeroize::Zeroizing;

use crate::envelope::{open_envelope, seal_envelope, Context, RecordKind};
use crate::error::Error;

/// Common behaviour of the 32-byte secret key types.
macro_rules! secret_key_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name(Secret32);

        impl $name {
            /// Wrap raw bytes; must be exactly 32 bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Secret32::from_bytes(bytes).map(Self)
            }

            /// Generate a fresh key from the OS CSPRNG.
            #[must_use]
            pub fn generate() -> Self {
                Self(Secret32::generate())
            }

            /// Access the raw key bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(redacted)"))
            }
        }
    };
}

#[derive(Clone)]
struct Secret32(Zeroizing<[u8; 32]>);

impl Secret32 {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(Zeroizing::new(
            bytes.try_into().map_err(|_| Error::InvalidKeyLength)?,
        )))
    }

    fn generate() -> Self {
        let mut bytes = [0u8; 32];
        crate::aead::fill_random(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

secret_key_type!(
    /// The account master key, wrapped by the password and recovery keys.
    AccountKey
);
secret_key_type!(
    /// Per-vault key, wrapped by the [`AccountKey`].
    VaultKey
);
secret_key_type!(
    /// Per-item key that encrypts item payloads.
    ItemKey
);
secret_key_type!(
    /// 32 random recovery bytes; display encodings are decided outside this
    /// crate (open decision G-10).
    RecoveryKey
);
secret_key_type!(
    /// Argon2id output derived from the master password.
    UnlockKey
);

fn wrap(wrapping_key: &[u8], wrapped: &[u8; 32], ctx: &Context<'_>) -> Result<Vec<u8>, Error> {
    seal_envelope(wrapping_key, ctx, wrapped)
}

fn unwrap(wrapping_key: &[u8], envelope: &[u8], ctx: &Context<'_>) -> Result<[u8; 32], Error> {
    let plaintext = open_envelope(wrapping_key, ctx, envelope)?;
    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKeyLength)
}

/// Wrap `account_key` under the password-derived `unlock_key`.
pub fn wrap_account_key_with_password(
    unlock_key: &UnlockKey,
    account_key: &AccountKey,
    account_id: &str,
    key_version: u64,
) -> Result<Vec<u8>, Error> {
    let ctx = Context {
        account_id,
        vault_id: None,
        item_id: None,
        record_kind: RecordKind::AccountWrap,
        key_version,
    };
    wrap(unlock_key.as_bytes(), account_key.as_bytes(), &ctx)
}

/// Wrap `account_key` under `recovery_key` (independent of the password
/// wrapper).
pub fn wrap_account_key_with_recovery(
    recovery_key: &RecoveryKey,
    account_key: &AccountKey,
    account_id: &str,
    key_version: u64,
) -> Result<Vec<u8>, Error> {
    let ctx = Context {
        account_id,
        vault_id: None,
        item_id: None,
        record_kind: RecordKind::RecoveryWrap,
        key_version,
    };
    wrap(recovery_key.as_bytes(), account_key.as_bytes(), &ctx)
}

/// Wrap `vault_key` under `account_key`.
pub fn wrap_vault_key(
    account_key: &AccountKey,
    vault_key: &VaultKey,
    account_id: &str,
    vault_id: &str,
    key_version: u64,
) -> Result<Vec<u8>, Error> {
    let ctx = Context {
        account_id,
        vault_id: Some(vault_id),
        item_id: None,
        record_kind: RecordKind::VaultWrap,
        key_version,
    };
    wrap(account_key.as_bytes(), vault_key.as_bytes(), &ctx)
}

/// Wrap `item_key` under `vault_key`.
pub fn wrap_item_key(
    vault_key: &VaultKey,
    item_key: &ItemKey,
    account_id: &str,
    vault_id: &str,
    item_id: &str,
    key_version: u64,
) -> Result<Vec<u8>, Error> {
    let ctx = Context {
        account_id,
        vault_id: Some(vault_id),
        item_id: Some(item_id),
        record_kind: RecordKind::ItemWrap,
        key_version,
    };
    wrap(vault_key.as_bytes(), item_key.as_bytes(), &ctx)
}

/// Encrypt an item payload under `item_key`.
pub fn seal_item_payload(
    item_key: &ItemKey,
    account_id: &str,
    vault_id: &str,
    item_id: &str,
    key_version: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let ctx = Context {
        account_id,
        vault_id: Some(vault_id),
        item_id: Some(item_id),
        record_kind: RecordKind::ItemPayload,
        key_version,
    };
    seal_envelope(item_key.as_bytes(), &ctx, plaintext)
}

/// Open the password wrapper. Fails with [`Error::AuthenticationFailed`] for
/// a wrong password (the caller cannot distinguish wrong password from
/// corrupt wrapper, by contract).
pub fn open_account_key_with_password(
    unlock_key: &UnlockKey,
    envelope: &[u8],
    account_id: &str,
    key_version: u64,
) -> Result<AccountKey, Error> {
    let ctx = Context {
        account_id,
        vault_id: None,
        item_id: None,
        record_kind: RecordKind::AccountWrap,
        key_version,
    };
    AccountKey::from_bytes(&unwrap(unlock_key.as_bytes(), envelope, &ctx)?)
}

/// Open the recovery wrapper. Fails with [`Error::InvalidRecoveryKit`] when
/// the kit is wrong or corrupt (fixture: "missing recovery key fails with
/// InvalidRecoveryKit").
pub fn open_account_key_with_recovery(
    recovery_key: &RecoveryKey,
    envelope: &[u8],
    account_id: &str,
    key_version: u64,
) -> Result<AccountKey, Error> {
    let ctx = Context {
        account_id,
        vault_id: None,
        item_id: None,
        record_kind: RecordKind::RecoveryWrap,
        key_version,
    };
    match unwrap(recovery_key.as_bytes(), envelope, &ctx) {
        Ok(bytes) => AccountKey::from_bytes(&bytes),
        Err(Error::AuthenticationFailed)
        | Err(Error::InvalidEncoding)
        | Err(Error::NonCanonicalCbor)
        | Err(Error::InvalidNonce) => Err(Error::InvalidRecoveryKit),
        Err(other) => Err(other),
    }
}

/// Open the vault wrapper under `account_key`.
pub fn open_vault_key(
    account_key: &AccountKey,
    envelope: &[u8],
    account_id: &str,
    vault_id: &str,
    key_version: u64,
) -> Result<VaultKey, Error> {
    let ctx = Context {
        account_id,
        vault_id: Some(vault_id),
        item_id: None,
        record_kind: RecordKind::VaultWrap,
        key_version,
    };
    VaultKey::from_bytes(&unwrap(account_key.as_bytes(), envelope, &ctx)?)
}

/// Open the item-key wrapper under `vault_key`.
pub fn open_item_key(
    vault_key: &VaultKey,
    envelope: &[u8],
    account_id: &str,
    vault_id: &str,
    item_id: &str,
    key_version: u64,
) -> Result<ItemKey, Error> {
    let ctx = Context {
        account_id,
        vault_id: Some(vault_id),
        item_id: Some(item_id),
        record_kind: RecordKind::ItemWrap,
        key_version,
    };
    ItemKey::from_bytes(&unwrap(vault_key.as_bytes(), envelope, &ctx)?)
}

/// Decrypt an item payload under `item_key`.
pub fn open_item_payload(
    item_key: &ItemKey,
    account_id: &str,
    vault_id: &str,
    item_id: &str,
    key_version: u64,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let ctx = Context {
        account_id,
        vault_id: Some(vault_id),
        item_id: Some(item_id),
        record_kind: RecordKind::ItemPayload,
        key_version,
    };
    open_envelope(item_key.as_bytes(), &ctx, envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_redact_debug_output() {
        let key = AccountKey::generate();
        assert_eq!(format!("{key:?}"), "AccountKey(redacted)");
        assert!(!format!("{key:?}").contains(&hex_of(key.as_bytes())));
    }

    #[test]
    fn full_hierarchy_round_trip() {
        let account_key = AccountKey::generate();
        let vault_key = VaultKey::generate();
        let item_key = ItemKey::generate();
        let unlock_key = UnlockKey::generate();

        let wrapped_account =
            wrap_account_key_with_password(&unlock_key, &account_key, "account_01", 1).unwrap();
        let opened =
            open_account_key_with_password(&unlock_key, &wrapped_account, "account_01", 1).unwrap();
        assert_eq!(opened.as_bytes(), account_key.as_bytes());

        let wrapped_vault =
            wrap_vault_key(&account_key, &vault_key, "account_01", "vault_01", 1).unwrap();
        let opened =
            open_vault_key(&account_key, &wrapped_vault, "account_01", "vault_01", 1).unwrap();
        assert_eq!(opened.as_bytes(), vault_key.as_bytes());

        let wrapped_item = wrap_item_key(
            &vault_key,
            &item_key,
            "account_01",
            "vault_01",
            "item_01",
            1,
        )
        .unwrap();
        let opened = open_item_key(
            &vault_key,
            &wrapped_item,
            "account_01",
            "vault_01",
            "item_01",
            1,
        )
        .unwrap();
        assert_eq!(opened.as_bytes(), item_key.as_bytes());

        let payload = seal_item_payload(
            &item_key,
            "account_01",
            "vault_01",
            "item_01",
            1,
            b"vault plaintext",
        )
        .unwrap();
        let opened =
            open_item_payload(&item_key, "account_01", "vault_01", "item_01", 1, &payload).unwrap();
        assert_eq!(*opened, b"vault plaintext".to_vec());
    }

    #[test]
    fn wrong_key_fails_generically() {
        let account_key = AccountKey::generate();
        let wrapped =
            wrap_account_key_with_password(&UnlockKey::generate(), &account_key, "account_01", 1)
                .unwrap();
        let wrong = UnlockKey::generate();
        assert_eq!(
            open_account_key_with_password(&wrong, &wrapped, "account_01", 1).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn recovery_failure_is_invalid_recovery_kit() {
        let account_key = AccountKey::generate();
        let recovery_key = RecoveryKey::generate();
        let wrapped =
            wrap_account_key_with_recovery(&recovery_key, &account_key, "account_01", 1).unwrap();
        let wrong = RecoveryKey::generate();
        assert_eq!(
            open_account_key_with_recovery(&wrong, &wrapped, "account_01", 1).unwrap_err(),
            Error::InvalidRecoveryKit
        );
        // Corrupt ciphertext also maps to InvalidRecoveryKit.
        let mut corrupt = wrapped.clone();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0x01;
        assert_eq!(
            open_account_key_with_recovery(&recovery_key, &corrupt, "account_01", 1).unwrap_err(),
            Error::InvalidRecoveryKit
        );
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert_eq!(
            AccountKey::from_bytes(&[0u8; 31]).unwrap_err(),
            Error::InvalidKeyLength
        );
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
