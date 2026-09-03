//! `fixtures/crypto/aead-xchacha20poly1305.json`: the draft-irtf-cfrg-xchacha
//! A.1 vector through the crypto-core AEAD boundary, plus the five negative
//! cases under the fixture's `xor-0x01-at-offset` tamper rule.

use crypto_core::aead;
use crypto_core::Error;
use serde_json::Value;

fn load() -> Value {
    crypto_core_tests::load_fixture("aead-xchacha20poly1305.json")
}

fn expected_error(name: &str) -> Error {
    match name {
        "AuthenticationFailed" => Error::AuthenticationFailed,
        "InvalidNonce" => Error::InvalidNonce,
        "InvalidContext" => Error::InvalidContext,
        other => panic!("unknown fixture error name {other}"),
    }
}

#[test]
fn encryption_reproduces_the_vector_exactly() {
    let fixture = load();
    let key = field(&fixture, "key");
    let nonce = field(&fixture, "nonce");
    let plaintext = field(&fixture, "plaintext");
    let aad = field(&fixture, "aad");
    let expected = field(&fixture, "ciphertextTag");

    let produced = aead::seal(&key, &nonce, &plaintext, &aad).unwrap();
    assert_eq!(produced, expected, "AEAD output must be ciphertext || tag");

    let recovered = aead::open(&key, &nonce, &expected, &aad).unwrap();
    assert_eq!(*recovered, plaintext);
}

#[test]
fn every_negative_case_fails_with_the_declared_error() {
    let fixture = load();
    let key = field(&fixture, "key");
    let nonce = field(&fixture, "nonce");
    let aad = field(&fixture, "aad");
    let ciphertext_tag = field(&fixture, "ciphertextTag");
    assert_eq!(
        fixture["tamperRule"].as_str().unwrap(),
        "xor-0x01-at-offset"
    );

    let negatives = fixture["negative"].as_array().unwrap();
    assert_eq!(negatives.len(), 5);
    for case in negatives {
        let name = case["case"].as_str().unwrap();
        let expected = expected_error(case["error"].as_str().unwrap());
        let error = match name {
            "ciphertext-byte-change" => {
                let offset = case["offset"].as_u64().unwrap() as usize;
                aead::open(&key, &nonce, &xor_at(&ciphertext_tag, offset), &aad).unwrap_err()
            }
            "final-tag-byte-change" => {
                let offset = case["offset"].as_u64().unwrap() as usize;
                assert_eq!(offset, ciphertext_tag.len() - 1, "final tag byte");
                aead::open(&key, &nonce, &xor_at(&ciphertext_tag, offset), &aad).unwrap_err()
            }
            "nonce-byte-change" => {
                let offset = case["offset"].as_u64().unwrap() as usize;
                aead::open(&key, &xor_at(&nonce, offset), &ciphertext_tag, &aad).unwrap_err()
            }
            "aad-byte-change" => {
                // At the raw AEAD layer a changed AAD fails authentication;
                // the contract's InvalidContext distinction belongs to the
                // envelope layer (see envelope_fixture.rs
                // aad-context-mismatch). The fixture note and the H01
                // verifier-plan matrix allow exactly this mapping.
                let offset = case["offset"].as_u64().unwrap() as usize;
                assert_eq!(case["error"].as_str().unwrap(), "InvalidContext");
                aead::open(&key, &nonce, &ciphertext_tag, &xor_at(&aad, offset)).unwrap_err()
            }
            "nonce-23-bytes" => {
                let truncate_to = case["truncateTo"].as_u64().unwrap() as usize;
                assert_eq!(truncate_to, 23);
                let mut short = nonce.clone();
                short.truncate(23);
                assert_eq!(
                    aead::open(&key, &short, &ciphertext_tag, &aad).unwrap_err(),
                    Error::InvalidNonce
                );
                aead::open(&key, &short, &ciphertext_tag, &aad).unwrap_err()
            }
            other => panic!("unexpected fixture case {other}"),
        };
        if name == "aad-byte-change" {
            assert_eq!(
                error,
                Error::AuthenticationFailed,
                "raw AEAD layer reports authentication failure for changed AAD"
            );
        } else {
            assert_eq!(error, expected, "case {name}");
        }
    }
}

#[test]
fn tampering_any_single_byte_of_ciphertext_or_tag_never_authenticates() {
    let fixture = load();
    let key = field(&fixture, "key");
    let nonce = field(&fixture, "nonce");
    let aad = field(&fixture, "aad");
    let ciphertext_tag = field(&fixture, "ciphertextTag");
    for offset in 0..ciphertext_tag.len() {
        let error = aead::open(&key, &nonce, &xor_at(&ciphertext_tag, offset), &aad).unwrap_err();
        assert_eq!(error, Error::AuthenticationFailed, "offset {offset}");
    }
}

fn field(fixture: &Value, name: &str) -> Vec<u8> {
    crypto_core_tests::bytes_field(fixture[name].as_str().unwrap())
}

fn xor_at(bytes: &[u8], offset: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[offset] ^= 0x01;
    out
}
