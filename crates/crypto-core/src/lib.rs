#![forbid(unsafe_code)]
//! # crypto-core
//!
//! Rust cryptographic core for `crypto-envelope/v1`, implementing exactly the
//! frozen contract approved with findings in ADR-0003 (2026-09-03):
//!
//! * strict canonical-CBOR (RFC 8949) validation and encoding behind a
//!   dedicated wrapper ([`canon`]) — the F-2 condition on `minicbor`;
//! * XChaCha20-Poly1305 (IETF) AEAD with fixed 32/24/16-byte sizes
//!   ([`aead`]);
//! * the canonical envelope and AAD with full context binding
//!   ([`envelope`]);
//! * Argon2id (RFC 9106 v1.3) unlock derivation, parameter maps and
//!   first-setup calibration ([`kdf`]);
//! * the random 32-byte key hierarchy with wrap/unwrap per wrapper kind and
//!   zeroization of all secret buffers ([`keys`]);
//! * recovery kit semantics with challenge confirmation ([`recovery`]);
//! * the approved OPAQUE RFC 9807 Ristretto255 helper API ([`opaque`]).
//!
//! All primitive implementations come from the exact library versions pinned
//! in the ADR-0003 library table; nothing here invents cryptography. The
//! crate is `unsafe_code = "forbid"` and no debug output ever contains key
//! bytes. Errors are the thirteen contract variants of [`error::Error`] and
//! carry no secret or parser detail.
//!
//! Clients consume this crate through future WASM/UniFFI bindings (B03) and
//! must not implement primitives themselves.

pub mod aead;
pub mod canon;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod opaque;
pub mod recovery;

pub use envelope::{Context, RecordKind};
pub use error::Error;
pub use kdf::KdfParams;

/// Protocol implementation status for health checks.
#[must_use]
pub fn protocol_status() -> &'static str {
    "crypto-envelope/v1"
}

#[cfg(test)]
mod tests {
    use super::protocol_status;

    #[test]
    fn protocol_status_reports_implemented_contract() {
        assert_eq!(protocol_status(), "crypto-envelope/v1");
    }
}
