//! `fixtures/crypto/aad-item-payload.json`: canonical AAD bytes, semantic
//! equality, and the three non-canonical rejections.

use crypto_core::envelope::{Context, RecordKind};
use crypto_core::Error;
use serde_json::Value;

fn aad_bytes(input: &Value) -> Vec<u8> {
    let vault = input["vaultId"].as_str();
    let item = input["itemId"].as_str();
    let ctx = Context {
        account_id: input["accountId"].as_str().expect("accountId"),
        vault_id: vault.map(|_| input["vaultId"].as_str().expect("vaultId")),
        item_id: item.map(|_| input["itemId"].as_str().expect("itemId")),
        record_kind: RecordKind::parse(input["recordType"].as_str().expect("recordType"))
            .expect("known record type"),
        key_version: input["keyVersion"].as_u64().expect("keyVersion"),
    };
    crypto_core::envelope::encode_aad(&ctx).expect("canonical AAD")
}

#[test]
fn positive_aad_matches_fixture_bytes_exactly() {
    let fixture = crypto_core_tests::load_fixture("aad-item-payload.json");
    assert_eq!(
        fixture["id"].as_str().unwrap(),
        "aad-item-payload-01",
        "fixture identity"
    );
    let expected = crypto_core_tests::bytes_field(fixture["canonicalCborHex"].as_str().unwrap());
    assert_eq!(aad_bytes(&fixture["input"]), expected);
}

#[test]
fn every_non_canonical_case_rejects_with_non_canonical_cbor() {
    let fixture = crypto_core_tests::load_fixture("aad-item-payload.json");
    let cases = fixture["nonCanonical"]
        .as_array()
        .expect("nonCanonical list");
    assert_eq!(cases.len(), 3);
    for case in cases {
        let bytes = crypto_core_tests::bytes_field(case["encoding"].as_str().expect("encoding"));
        let error = crypto_core::envelope::validate_aad(&bytes).unwrap_err();
        assert_eq!(
            error,
            Error::NonCanonicalCbor,
            "case {:?} must reject as NonCanonicalCbor",
            case["case"]
        );
        assert_eq!(
            case["error"].as_str().unwrap(),
            "NonCanonicalCbor",
            "fixture expectation"
        );
    }
}

#[test]
fn changing_any_identifier_changes_aad() {
    let fixture = crypto_core_tests::load_fixture("aad-item-payload.json");
    let original = aad_bytes(&fixture["input"]);
    for field in ["accountId", "vaultId", "itemId"] {
        let mut input = fixture["input"].clone();
        let value = input[field].as_str().unwrap().to_owned();
        input[field] = Value::String(format!("{value}X"));
        assert_ne!(
            aad_bytes(&input),
            original,
            "changing {field} must change AAD"
        );
    }
    let mut input = fixture["input"].clone();
    input["keyVersion"] = Value::from(2);
    assert_ne!(aad_bytes(&input), original);
    let mut input = fixture["input"].clone();
    input["recordType"] = Value::String("item-wrap".to_owned());
    assert_ne!(aad_bytes(&input), original);
}
