//! Typed public error surface for `crypto-envelope/v1`.
//!
//! The variant set is exactly the one mandated by the contract section
//! "Typed errors". Every variant is a unit variant: errors can carry no
//! secret bytes and no raw parser details by construction, and callers can
//! never accidentally embed key material or decoder offsets in a message.
//!
//! `Locked` is part of the contract surface for the lock-state layer above
//! this crate (vault lock/unlock flows in bindings and clients); the core
//! itself is stateless and does not emit it.

use core::fmt;

/// Public, secret-free error type of the crypto core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Input bytes are structurally invalid (truncated, wrong type, bad shape).
    InvalidEncoding,
    /// The envelope/AAD version string is not `crypto-envelope/v1`.
    UnsupportedVersion,
    /// Bytes are valid CBOR but violate canonical RFC 8949 encoding rules
    /// (non-minimal integers, unordered or duplicate keys, indefinite
    /// lengths, tags, floating point values).
    NonCanonicalCbor,
    /// A structurally valid map contains a key outside the fixed contract set.
    UnknownField,
    /// The AAD/context (identifiers, record type, key version) does not match
    /// the expected decryption context.
    InvalidContext,
    /// A nonce has the wrong length or otherwise violates nonce rules.
    InvalidNonce,
    /// AEAD authentication failed, or an OPAQUE exchange failed. Deliberately
    /// generic: callers must not be able to distinguish a wrong password from
    /// corrupted remote credential material.
    AuthenticationFailed,
    /// Argon2id parameters violate the contract bounds or parameter-map shape.
    InvalidKdfParameters,
    /// KDF parameters exceed an allowed resource envelope (for example more
    /// than 25% of reported physical memory, or no candidate inside the
    /// calibration window).
    KdfResourceLimit,
    /// A key or wrapped-key plaintext has the wrong length.
    InvalidKeyLength,
    /// Recovery material is absent, corrupt, or fails confirmation.
    InvalidRecoveryKit,
    /// The operation requires an unlocked state managed above this crate.
    Locked,
    /// An unexpected internal condition. Never carries diagnostic detail.
    Internal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::InvalidEncoding => "invalid encoding",
            Error::UnsupportedVersion => "unsupported version",
            Error::NonCanonicalCbor => "non-canonical cbor",
            Error::UnknownField => "unknown field",
            Error::InvalidContext => "invalid context",
            Error::InvalidNonce => "invalid nonce",
            Error::AuthenticationFailed => "authentication failed",
            Error::InvalidKdfParameters => "invalid kdf parameters",
            Error::KdfResourceLimit => "kdf resource limit",
            Error::InvalidKeyLength => "invalid key length",
            Error::InvalidRecoveryKit => "invalid recovery kit",
            Error::Locked => "locked",
            Error::Internal => "internal error",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn display_messages_are_stable_and_secret_free() {
        assert_eq!(Error::InvalidEncoding.to_string(), "invalid encoding");
        assert_eq!(Error::UnsupportedVersion.to_string(), "unsupported version");
        assert_eq!(Error::NonCanonicalCbor.to_string(), "non-canonical cbor");
        assert_eq!(Error::UnknownField.to_string(), "unknown field");
        assert_eq!(Error::InvalidContext.to_string(), "invalid context");
        assert_eq!(Error::InvalidNonce.to_string(), "invalid nonce");
        assert_eq!(
            Error::AuthenticationFailed.to_string(),
            "authentication failed"
        );
        assert_eq!(
            Error::InvalidKdfParameters.to_string(),
            "invalid kdf parameters"
        );
        assert_eq!(Error::KdfResourceLimit.to_string(), "kdf resource limit");
        assert_eq!(Error::InvalidKeyLength.to_string(), "invalid key length");
        assert_eq!(
            Error::InvalidRecoveryKit.to_string(),
            "invalid recovery kit"
        );
        assert_eq!(Error::Locked.to_string(), "locked");
        assert_eq!(Error::Internal.to_string(), "internal error");
    }

    #[test]
    fn variants_are_unit_and_copyable() {
        let e = Error::AuthenticationFailed;
        let copy = e;
        assert_eq!(e, copy);
        let _ = format!("{copy:?}");
    }

    #[test]
    fn implements_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&Error::Internal);
    }
}
