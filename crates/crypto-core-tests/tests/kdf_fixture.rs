//! `fixtures/crypto/kdf-parameters.json`: positive parameter-map bytes, the
//! G-11 semantic regression, the non-minimal-integer canonical rejection, and
//! the four parameter-bound negatives.

use crypto_core::kdf::{self, KdfParams};
use crypto_core::Error;
use serde_json::Value;

fn load() -> Value {
    crypto_core_tests::load_fixture("kdf-parameters.json")
}

fn bytes_field(v: &Value) -> Vec<u8> {
    crypto_core_tests::bytes_field(v.as_str().unwrap())
}

/// Build the canonical parameter map with one field overridden, test-side,
/// using the approved encoder (mirrors the fixture's parameter negatives).
fn params_with(fixture: &Value, overrides: &Value) -> Vec<u8> {
    let base = &fixture["parameters"];
    let get = |name: &str| {
        overrides
            .get(name)
            .unwrap_or_else(|| base.get(name).unwrap())
            .clone()
    };
    let salt = match overrides.get("salt") {
        Some(v) => bytes_field(v),
        None => bytes_field(&base["salt"]),
    };
    let memory = get("memoryKiB").as_u64().unwrap();
    let iterations = get("iterations").as_u64().unwrap();
    let parallelism = get("parallelism").as_u64().unwrap();
    let output_length = get("outputLength").as_u64().unwrap();
    let algorithm = get("algorithm").as_str().unwrap().to_owned();
    let version = get("version").as_u64().unwrap();

    // Encode directly so that semantic violations (like outputLength 16)
    // survive into the map for decode_canonical_cbor to reject.
    use minicbor::{Decoder, Encoder};
    let template = bytes_field(&fixture["canonicalCborHex"]);
    let mut decoder = Decoder::new(&template);
    let entries = decoder.map().unwrap().unwrap();
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(entries).unwrap();
    for _ in 0..entries {
        let key = decoder.u64().unwrap();
        // Consume the template value; the overridden value is re-encoded.
        decoder.skip().unwrap();
        encoder.u64(key).unwrap();
        match key {
            1 => {
                encoder.str(&algorithm).unwrap();
            }
            2 => {
                encoder.u64(version).unwrap();
            }
            3 => {
                encoder.u64(memory).unwrap();
            }
            4 => {
                encoder.u64(iterations).unwrap();
            }
            5 => {
                encoder.u64(parallelism).unwrap();
            }
            6 => {
                encoder.bytes(&salt).unwrap();
            }
            7 => {
                encoder.u64(output_length).unwrap();
            }
            _ => unreachable!("fixed key set"),
        }
    }
    encoder.into_writer()
}

#[test]
fn positive_parameter_map_encodes_to_the_fixture_bytes() {
    let fixture = load();
    let params = fixture["parameters"].clone();
    let built = KdfParams::new(
        params["memoryKiB"].as_u64().unwrap() as u32,
        params["iterations"].as_u64().unwrap() as u32,
        params["parallelism"].as_u64().unwrap() as u32,
        &bytes_field(&params["salt"]),
    )
    .unwrap();
    assert_eq!(
        built.encode_canonical_cbor().unwrap(),
        bytes_field(&fixture["canonicalCborHex"])
    );
}

#[test]
fn decode_accepts_the_fixture_bytes_and_returns_the_declared_parameters() {
    let fixture = load();
    let params = KdfParams::decode_canonical_cbor(
        &bytes_field(&fixture["canonicalCborHex"]),
        // 65 536 KiB is exactly 25% of 256 MiB.
        65_536 * 4,
    )
    .expect("fixture bytes are valid");
    let expected = &fixture["parameters"];
    assert_eq!(
        u64::from(params.memory_kib()),
        expected["memoryKiB"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(params.iterations()),
        expected["iterations"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(params.parallelism()),
        expected["parallelism"].as_u64().unwrap()
    );
    assert_eq!(params.salt(), bytes_field(&expected["salt"]).as_slice());
}

#[test]
fn canonical_reject_cases_fail_with_the_declared_errors() {
    let fixture = load();
    for case in fixture["canonicalReject"].as_array().unwrap() {
        let bytes = bytes_field(&case["encoding"]);
        let error = KdfParams::decode_canonical_cbor(&bytes, 65_536 * 4).unwrap_err();
        assert_eq!(
            error,
            expected_error(case["error"].as_str().unwrap()),
            "case {}",
            case["case"].as_str().unwrap()
        );
    }
}

#[test]
fn parameter_negative_cases_fail_with_invalid_kdf_parameters() {
    let fixture = load();
    for case in fixture["negative"].as_array().unwrap() {
        let bytes = params_with(&fixture, case);
        let error = KdfParams::decode_canonical_cbor(&bytes, 65_536 * 4).unwrap_err();
        assert_eq!(
            error,
            Error::InvalidKdfParameters,
            "case {}",
            case["case"].as_str().unwrap()
        );
    }
}

#[test]
fn derive_uses_the_fixture_parameters_deterministically() {
    let fixture = load();
    let params =
        KdfParams::decode_canonical_cbor(&bytes_field(&fixture["canonicalCborHex"]), 65_536 * 4)
            .unwrap();
    let a = kdf::derive_unlock_key(b"fixture-password", &params, 65_536 * 4).unwrap();
    let b = kdf::derive_unlock_key(b"fixture-password", &params, 65_536 * 4).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());
    let c = kdf::derive_unlock_key(b"other-password", &params, 65_536 * 4).unwrap();
    assert_ne!(a.as_bytes(), c.as_bytes());
}

fn expected_error(name: &str) -> Error {
    match name {
        "InvalidKdfParameters" => Error::InvalidKdfParameters,
        "NonCanonicalCbor" => Error::NonCanonicalCbor,
        other => panic!("unknown fixture error name {other}"),
    }
}
