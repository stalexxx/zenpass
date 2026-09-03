//! XChaCha20-Poly1305 (IETF) AEAD boundary.
//!
//! Sizes are fixed by the contract: 32-byte keys, 24-byte nonces, 16-byte
//! tags, and `ciphertext || tag` output. Authentication is verified before
//! any plaintext is produced: the underlying implementation authenticates the
//! whole ciphertext before releasing a single plaintext byte, and this
//! wrapper never returns partial output.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::error::Error;

/// AEAD key length in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Maximum plaintext size of an item payload (1 MiB).
pub const MAX_ITEM_PLAINTEXT_LEN: usize = 1024 * 1024;
/// Maximum size of a wrapped key envelope (64 KiB).
pub const MAX_WRAPPED_KEY_LEN: usize = 64 * 1024;

/// Fill `buffer` with fresh OS-CSPRNG bytes.
pub(crate) fn fill_random(buffer: &mut [u8]) {
    // OsRng from rand 0.8, the RNG stack of the approved opaque-ke closure.
    // An OS entropy failure aborts the process, which is the only safe
    // behaviour during encryption.
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buffer);
}

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305, Error> {
    let key: &[u8; KEY_LEN] = key.try_into().map_err(|_| Error::InvalidKeyLength)?;
    Ok(XChaCha20Poly1305::new(key.into()))
}

/// Encrypt `plaintext` under `key`, `nonce` and `aad`, returning
/// `ciphertext || tag`.
///
/// `nonce` must be 24 fresh OS-CSPRNG bytes; this function performs no nonce
/// construction of its own, so nonce reuse under the same key and context is
/// a caller error the type system of [`crate::envelope`] prevents by
/// generating nonces internally.
pub fn seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != KEY_LEN {
        return Err(Error::InvalidKeyLength);
    }
    if nonce.len() != NONCE_LEN {
        return Err(Error::InvalidNonce);
    }
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("length checked above");
    cipher(key)?
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::AuthenticationFailed)
}

/// Authenticate and decrypt `ciphertext || tag`, returning the plaintext in a
/// zeroizing buffer.
///
/// Returns [`Error::AuthenticationFailed`] if the ciphertext, tag or AAD do
/// not authenticate; no plaintext bytes are released in that case.
pub fn open(
    key: &[u8],
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if key.len() != KEY_LEN {
        return Err(Error::InvalidKeyLength);
    }
    if nonce.len() != NONCE_LEN {
        return Err(Error::InvalidNonce);
    }
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(Error::InvalidEncoding);
    }
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("length checked above");
    let plaintext = cipher(key)?
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| Error::AuthenticationFailed)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // draft-irtf-cfrg-xchacha-03, Appendix A.1 (also fixtures/crypto/aead-xchacha20poly1305.json).
    const KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const NONCE: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
    const PLAINTEXT: &str = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
    const AAD: &str = "50515253c0c1c2c3c4c5c6c7";
    const CIPHERTEXT_TAG: &str = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49";

    #[test]
    fn xchacha20poly1305_reference_vector_encrypts_exactly() {
        let ct = seal(&hex(KEY), &hex(NONCE), &hex(PLAINTEXT), &hex(AAD)).unwrap();
        assert_eq!(ct, hex(CIPHERTEXT_TAG));
    }

    #[test]
    fn xchacha20poly1305_reference_vector_decrypts() {
        let pt = open(&hex(KEY), &hex(NONCE), &hex(CIPHERTEXT_TAG), &hex(AAD)).unwrap();
        assert_eq!(*pt, hex(PLAINTEXT));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut ct = hex(CIPHERTEXT_TAG);
        ct[5] ^= 0x01;
        assert_eq!(
            open(&hex(KEY), &hex(NONCE), &ct, &hex(AAD)).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn tampered_final_tag_byte_fails() {
        let mut ct = hex(CIPHERTEXT_TAG);
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert_eq!(
            open(&hex(KEY), &hex(NONCE), &ct, &hex(AAD)).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn tampered_nonce_fails() {
        let mut nonce = hex(NONCE);
        nonce[7] ^= 0x01;
        assert_eq!(
            open(&hex(KEY), &nonce, &hex(CIPHERTEXT_TAG), &hex(AAD)).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn changed_aad_fails_at_aead_layer() {
        let mut aad = hex(AAD);
        aad[3] ^= 0x01;
        assert_eq!(
            open(&hex(KEY), &hex(NONCE), &hex(CIPHERTEXT_TAG), &aad).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn short_nonce_is_invalid_nonce() {
        let mut nonce = hex(NONCE);
        nonce.truncate(23);
        assert_eq!(
            open(&hex(KEY), &nonce, &hex(CIPHERTEXT_TAG), &hex(AAD)).unwrap_err(),
            Error::InvalidNonce
        );
        assert_eq!(
            seal(&hex(KEY), &nonce, &hex(PLAINTEXT), &hex(AAD)).unwrap_err(),
            Error::InvalidNonce
        );
    }

    #[test]
    fn wrong_key_length_is_rejected() {
        assert_eq!(
            seal(&hex(KEY)[..31], &hex(NONCE), b"x", b"").unwrap_err(),
            Error::InvalidKeyLength
        );
        assert_eq!(
            open(&hex(KEY)[..31], &hex(NONCE), &hex(CIPHERTEXT_TAG), b"").unwrap_err(),
            Error::InvalidKeyLength
        );
    }

    #[test]
    fn truncated_ciphertext_is_invalid_encoding() {
        let mut ct = hex(CIPHERTEXT_TAG);
        ct.truncate(15);
        assert_eq!(
            open(&hex(KEY), &hex(NONCE), &ct, &hex(AAD)).unwrap_err(),
            Error::InvalidEncoding
        );
    }
}
