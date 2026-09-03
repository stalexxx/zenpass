//! Recovery kit semantics for `crypto-envelope/v1`.
//!
//! The recovery key is 32 random bytes wrapping the [`AccountKey`]
//! independently of the password wrapper. A saved-kit confirmation is an
//! AEAD-authenticated challenge under the recovery key with
//! `export-manifest` context: verification succeeds only with the same key
//! and the same challenge bytes, so the client can require proof the user
//! retained the kit before marking it saved. The recovery-code display
//! encoding is open decision G-10 and is deliberately not implemented here;
//! only raw bytes are exposed.

use zeroize::Zeroizing;

use crate::envelope::{Context, RecordKind};
use crate::error::Error;
use crate::keys::{
    open_account_key_with_recovery, wrap_account_key_with_recovery, AccountKey, RecoveryKey,
};

/// Marker plaintext used for kit confirmations.
const CONFIRMATION_MARKER: &[u8] = b"crypto-envelope/v1 recovery-kit-confirmation";

/// A recovery kit: the recovery-wrapped AccountKey plus the context needed
/// to open it. Contains no plaintext key material.
#[derive(Clone, Debug)]
pub struct RecoveryKit {
    account_id: String,
    key_version: u64,
    wrapped_account_key: Vec<u8>,
}

impl RecoveryKit {
    /// Generate a fresh recovery key and wrap `account_key` with it.
    ///
    /// The recovery key is returned exactly once; the caller displays it (in
    /// a future display encoding ruled by G-10) and then keeps only the
    /// wrapped key.
    pub fn generate(
        account_key: &AccountKey,
        account_id: &str,
        key_version: u64,
    ) -> Result<(RecoveryKey, Self), Error> {
        let recovery_key = RecoveryKey::generate();
        let wrapped_account_key =
            wrap_account_key_with_recovery(&recovery_key, account_key, account_id, key_version)?;
        Ok((
            recovery_key,
            Self {
                account_id: account_id.to_owned(),
                key_version,
                wrapped_account_key,
            },
        ))
    }

    /// Reassemble a kit from stored parts.
    ///
    /// Fails closed with [`Error::InvalidRecoveryKit`] unless the wrapped
    /// key is a structurally valid `recovery-wrap` envelope for this
    /// account and version.
    pub fn from_parts(
        account_id: &str,
        key_version: u64,
        wrapped_account_key: Vec<u8>,
    ) -> Result<Self, Error> {
        let expected = Context {
            account_id,
            vault_id: None,
            item_id: None,
            record_kind: RecordKind::RecoveryWrap,
            key_version,
        };
        let embedded = crate::envelope::inspect_envelope(&wrapped_account_key)
            .map_err(|_| Error::InvalidRecoveryKit)?;
        if embedded != expected {
            return Err(Error::InvalidRecoveryKit);
        }
        Ok(Self {
            account_id: account_id.to_owned(),
            key_version,
            wrapped_account_key,
        })
    }

    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    #[must_use]
    pub fn key_version(&self) -> u64 {
        self.key_version
    }

    /// The recovery-wrapped AccountKey envelope bytes (safe to store
    /// server-side).
    #[must_use]
    pub fn wrapped_account_key(&self) -> &[u8] {
        &self.wrapped_account_key
    }

    /// Locally unwrap the AccountKey with the recovery key.
    ///
    /// A wrong or absent recovery key fails with
    /// [`Error::InvalidRecoveryKit`]; without the kit, loss is permanent.
    pub fn unwrap_account_key(&self, recovery_key: &RecoveryKey) -> Result<AccountKey, Error> {
        open_account_key_with_recovery(
            recovery_key,
            &self.wrapped_account_key,
            &self.account_id,
            self.key_version,
        )
    }

    /// Produce an authenticated confirmation token for `challenge`.
    ///
    /// The token is a `recovery-wrap`-context-free envelope under the
    /// recovery key using the `export-manifest` record kind: it can only be
    /// produced and verified with the recovery key.
    pub fn confirmation(
        &self,
        recovery_key: &RecoveryKey,
        challenge: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let ctx = Context {
            account_id: &self.account_id,
            vault_id: None,
            item_id: None,
            record_kind: RecordKind::ExportManifest,
            key_version: self.key_version,
        };
        let mut message = Zeroizing::new(Vec::with_capacity(
            CONFIRMATION_MARKER.len() + challenge.len(),
        ));
        message.extend_from_slice(CONFIRMATION_MARKER);
        message.extend_from_slice(challenge);
        crate::envelope::seal_envelope(recovery_key.as_bytes(), &ctx, &message)
    }

    /// Verify a confirmation token against `challenge`.
    ///
    /// Returns [`Error::InvalidRecoveryKit`] unless the token authenticates
    /// under `recovery_key` and carries exactly this challenge.
    pub fn verify_confirmation(
        &self,
        recovery_key: &RecoveryKey,
        challenge: &[u8],
        token: &[u8],
    ) -> Result<(), Error> {
        let ctx = Context {
            account_id: &self.account_id,
            vault_id: None,
            item_id: None,
            record_kind: RecordKind::ExportManifest,
            key_version: self.key_version,
        };
        let message = crate::envelope::open_envelope(recovery_key.as_bytes(), &ctx, token)
            .map_err(|_| Error::InvalidRecoveryKit)?;
        if message.len() != CONFIRMATION_MARKER.len() + challenge.len()
            || !message.starts_with(CONFIRMATION_MARKER)
            || &message[CONFIRMATION_MARKER.len()..] != challenge
        {
            return Err(Error::InvalidRecoveryKit);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kit_round_trip_and_independence_from_password_wrapper() {
        let account_key = AccountKey::generate();
        let (recovery_key, kit) = RecoveryKit::generate(&account_key, "account_01", 1).unwrap();
        let recovered = kit.unwrap_account_key(&recovery_key).unwrap();
        assert_eq!(recovered.as_bytes(), account_key.as_bytes());

        // A different recovery key cannot open the kit.
        let wrong = RecoveryKey::generate();
        assert_eq!(
            kit.unwrap_account_key(&wrong).unwrap_err(),
            Error::InvalidRecoveryKit
        );
    }

    #[test]
    fn confirmation_requires_same_key_and_challenge() {
        let account_key = AccountKey::generate();
        let (recovery_key, kit) = RecoveryKit::generate(&account_key, "account_01", 1).unwrap();
        let token = kit.confirmation(&recovery_key, b"challenge-1234").unwrap();
        kit.verify_confirmation(&recovery_key, b"challenge-1234", &token)
            .unwrap();

        let wrong = RecoveryKey::generate();
        assert_eq!(
            kit.verify_confirmation(&wrong, b"challenge-1234", &token)
                .unwrap_err(),
            Error::InvalidRecoveryKit
        );
        assert_eq!(
            kit.verify_confirmation(&recovery_key, b"challenge-5678", &token)
                .unwrap_err(),
            Error::InvalidRecoveryKit
        );
        let mut tampered = token.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            kit.verify_confirmation(&recovery_key, b"challenge-1234", &tampered)
                .unwrap_err(),
            Error::InvalidRecoveryKit
        );
    }

    #[test]
    fn kit_debug_contains_no_key_material() {
        let account_key = AccountKey::generate();
        let (_, kit) = RecoveryKit::generate(&account_key, "account_01", 1).unwrap();
        let debugged = format!("{kit:?}");
        assert!(!debugged.contains(&hex_of(account_key.as_bytes())));
        assert!(debugged.contains("account_01"));
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
