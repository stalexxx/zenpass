//! `fixtures/crypto/envelope-malformed.json`: valid shape and the six reject
//! cases with their exact typed errors.
//!
//! Malformed envelopes are constructed with the approved `minicbor` encoder
//! (test-side surgery only; production encoding lives in crypto-core).

use crypto_core::envelope::{encode_aad, Context, RecordKind};
use crypto_core::Error;
use minicbor::{Decoder, Encoder};
use serde_json::Value;

const KEY: [u8; 32] = [0x11u8; 32];

#[derive(Clone)]
struct EnvelopeBytes {
    version: String,
    kind: String,
    key_version: u64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
    extra_unknown_key: bool,
}

impl EnvelopeBytes {
    fn decode(bytes: &[u8]) -> Self {
        let mut decoder = Decoder::new(bytes);
        let entries = decoder.map().unwrap().unwrap();
        let mut out = Self {
            version: String::new(),
            kind: String::new(),
            key_version: 0,
            nonce: Vec::new(),
            ciphertext: Vec::new(),
            aad: Vec::new(),
            extra_unknown_key: false,
        };
        for _ in 0..entries {
            match decoder.u64().unwrap() {
                1 => out.version = decoder.str().unwrap().to_owned(),
                2 => out.kind = decoder.str().unwrap().to_owned(),
                3 => out.key_version = decoder.u64().unwrap(),
                4 => out.nonce = decoder.bytes().unwrap().to_vec(),
                5 => out.ciphertext = decoder.bytes().unwrap().to_vec(),
                6 => out.aad = decoder.bytes().unwrap().to_vec(),
                _ => {
                    decoder.skip().unwrap();
                    out.extra_unknown_key = true;
                }
            }
        }
        assert!(!out.extra_unknown_key, "template carries no unknown keys");
        out
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        let len = if self.extra_unknown_key { 7 } else { 6 };
        encoder.map(len).unwrap();
        encoder.u64(1).unwrap();
        encoder.str(&self.version).unwrap();
        encoder.u64(2).unwrap();
        encoder.str(&self.kind).unwrap();
        encoder.u64(3).unwrap();
        encoder.u64(self.key_version).unwrap();
        encoder.u64(4).unwrap();
        encoder.bytes(&self.nonce).unwrap();
        encoder.u64(5).unwrap();
        encoder.bytes(&self.ciphertext).unwrap();
        encoder.u64(6).unwrap();
        encoder.bytes(&self.aad).unwrap();
        if self.extra_unknown_key {
            encoder.u64(7).unwrap();
            encoder.u64(1).unwrap();
        }
        encoder.into_writer()
    }
}

fn shape_ctx<'a>(shape: &'a Value, item_id: &'a str) -> Context<'a> {
    Context {
        account_id: "account_01",
        vault_id: Some("vault_01"),
        item_id: Some(item_id),
        record_kind: RecordKind::parse(shape["kind"].as_str().unwrap()).unwrap(),
        key_version: shape["keyVersion"].as_u64().unwrap(),
    }
}

fn load(name: &str) -> Value {
    crypto_core_tests::load_fixture(name)
}

fn expected_error(name: &str) -> Error {
    match name {
        "UnsupportedVersion" => Error::UnsupportedVersion,
        "InvalidNonce" => Error::InvalidNonce,
        "UnknownField" => Error::UnknownField,
        "InvalidContext" => Error::InvalidContext,
        "NonCanonicalCbor" => Error::NonCanonicalCbor,
        other => panic!("unknown fixture error name {other}"),
    }
}

#[test]
fn fixture_shape_context_encodes_the_declared_aad() {
    let fixture = load("envelope-malformed.json");
    let shape = &fixture["validEnvelopeShape"];
    let aad = crypto_core_tests::bytes_field(shape["aad"].as_str().unwrap());
    assert_eq!(
        encode_aad(&shape_ctx(shape, "item_01")).unwrap(),
        aad,
        "fixture aad must equal the canonical encoding of the declared context"
    );
    assert_eq!(
        crypto_core_tests::bytes_field(shape["nonce"].as_str().unwrap()).len(),
        24
    );
}

#[test]
fn every_reject_case_fails_with_the_declared_typed_error() {
    let fixture = load("envelope-malformed.json");
    let shape = &fixture["validEnvelopeShape"];
    let template = {
        // Real envelope produced by the core over the fixture context.
        let envelope =
            crypto_core::envelope::seal_envelope(&KEY, &shape_ctx(shape, "item_01"), &[0xa5u8; 16])
                .unwrap();
        EnvelopeBytes::decode(&envelope)
    };

    let rejects = fixture["reject"].as_array().unwrap();
    assert_eq!(rejects.len(), 6, "all six reject cases are exercised");

    for case in rejects {
        let case_name = case["case"].as_str().unwrap();
        let expected = expected_error(case["error"].as_str().unwrap());
        let error = match case_name {
            "wrong-version" => {
                let mut mutated = template.clone();
                mutated.version = "crypto-envelope/v2".to_owned();
                crypto_core::envelope::inspect_envelope(&mutated.encode()).unwrap_err()
            }
            "nonce-23-bytes" => {
                let mut mutated = template.clone();
                mutated.nonce =
                    crypto_core_tests::bytes_field(case["change"]["nonce"].as_str().unwrap());
                crypto_core::envelope::inspect_envelope(&mutated.encode()).unwrap_err()
            }
            "unknown-key" => {
                let mut mutated = template.clone();
                mutated.extra_unknown_key = true;
                crypto_core::envelope::inspect_envelope(&mutated.encode()).unwrap_err()
            }
            "aad-context-mismatch" => {
                // The fixture's declared itemId change binds the AAD to
                // item_02 while the envelope targets item_01.
                let envelope = crypto_core::envelope::seal_envelope(
                    &KEY,
                    &shape_ctx(shape, "item_01"),
                    &[0xa5u8; 16],
                )
                .unwrap();
                crypto_core::envelope::open_envelope(&KEY, &shape_ctx(shape, "item_02"), &envelope)
                    .unwrap_err()
            }
            "indefinite-map" | "duplicate-key" => crypto_core::envelope::inspect_envelope(
                &crypto_core_tests::bytes_field(case["encoding"].as_str().unwrap()),
            )
            .unwrap_err(),
            other => panic!("unexpected fixture case {other}"),
        };
        assert_eq!(error, expected, "case {case_name}");
    }
}
