//! Deterministic fuzz smoke (stable toolchain): pseudo-random mutations of
//! valid envelopes, AAD maps, and KDF parameter maps must never panic and
//! must only ever produce typed errors. Nightly cargo-fuzz/libFuzzer
//! integration is a follow-up; these deterministic campaigns stand in for
//! it on the stable toolchain required by this repository.

use crypto_core::keys::{seal_item_payload, ItemKey};
use crypto_core::{Error, KdfParams};

/// xorshift64* — deterministic, test-only randomness source.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }
}

const ITERATIONS: usize = 4000;

#[test]
fn envelope_mutation_smoke_never_panics_and_only_yields_typed_errors() {
    let mut rng = XorShift(0x5eed_1234_abcd_ef01);
    let item_key = ItemKey::generate();
    let envelope = seal_item_payload(
        &item_key,
        "account_01",
        "vault_01",
        "item_01",
        1,
        b"fuzz-smoke payload",
    )
    .unwrap();

    for i in 0..ITERATIONS {
        let mut mutated = envelope.clone();
        match rng.below(4) {
            0 => {
                // single-byte flip
                let at = rng.below(mutated.len());
                mutated[at] ^= 1u8 << rng.below(8);
            }
            1 => {
                // truncate by at least one byte
                mutated.truncate(rng.below(mutated.len()));
            }
            2 => {
                // extend with junk; at least one byte so the mutation is
                // never a no-op (trailing bytes must reject as
                // InvalidEncoding)
                let extra = 1 + rng.below(64);
                mutated.extend(std::iter::repeat_n(0xa5u8, extra));
            }
            _ => {
                // multi-byte corruption; at least one byte, XOR so every
                // write changes the byte (a zero-iteration or identity
                // write would be a no-op mutation, not a valid case)
                for _ in 0..1 + rng.below(8) {
                    let at = rng.below(mutated.len());
                    mutated[at] ^= 1u8 << rng.below(8);
                }
            }
        }
        let result = crypto_core::keys::open_item_payload(
            &item_key,
            "account_01",
            "vault_01",
            "item_01",
            1,
            &mutated,
        );
        match result {
            Ok(plaintext) => panic!(
                "iteration {i}: mutated envelope unexpectedly opened ({} bytes returned)",
                plaintext.len()
            ),
            Err(
                e @ (Error::InvalidEncoding
                | Error::UnsupportedVersion
                | Error::NonCanonicalCbor
                | Error::UnknownField
                | Error::InvalidContext
                | Error::InvalidNonce
                | Error::AuthenticationFailed
                | Error::InvalidKeyLength),
            ) => {
                let _ = e;
            }
            Err(other) => panic!("iteration {i}: unexpected error {other:?}"),
        }
    }
}

#[test]
fn kdf_parameter_map_mutation_smoke_never_panics() {
    let mut rng = XorShift(0x0bad_c0de_feed_face);
    let params = KdfParams::new(65_536, 3, 1, &[0x33u8; 16]).unwrap();
    let encoded = params.encode_canonical_cbor().unwrap();

    for i in 0..ITERATIONS {
        let mut mutated = encoded.clone();
        match rng.below(3) {
            0 => {
                let at = rng.below(mutated.len());
                mutated[at] ^= 1u8 << rng.below(8);
            }
            1 => mutated.truncate(rng.below(mutated.len() + 1)),
            _ => {
                let at = rng.below(mutated.len());
                mutated[at] = rng.next() as u8;
            }
        }
        if let Ok(decoded) = KdfParams::decode_canonical_cbor(&mutated) {
            // A mutation that still decodes must satisfy every bound.
            assert!(decoded.memory_kib() >= 65_536, "iteration {i}");
            assert!(decoded.iterations() >= 3, "iteration {i}");
            assert!(decoded.parallelism() >= 1, "iteration {i}");
            assert_eq!(decoded.salt().len(), 16, "iteration {i}");
        }
    }
}

#[test]
fn aad_mutation_smoke_never_panics() {
    let mut rng = XorShift(0x9001_1337_bea7_f00d);
    let ctx = crypto_core::Context {
        account_id: "account_01",
        vault_id: Some("vault_01"),
        item_id: Some("item_01"),
        record_kind: crypto_core::RecordKind::ItemPayload,
        key_version: 1,
    };
    let encoded = crypto_core::envelope::encode_aad(&ctx).unwrap();

    for i in 0..ITERATIONS {
        let mut mutated = encoded.clone();
        let at = rng.below(mutated.len());
        mutated[at] ^= 1u8 << rng.below(8);
        // Any outcome is fine as long as it is a typed error or an equal
        // context; panicking or hanging is the failure mode under test.
        if let Ok(decoded) = crypto_core::envelope::validate_aad(&mutated) {
            assert_ne!(decoded, ctx, "iteration {i}: mutated AAD decoded equal");
        }
    }
}
