//! Property tests: round trips, context binding, tamper resistance and
//! canonical re-encoding invariants over generated inputs.

use crypto_core::envelope::RecordKind;
use crypto_core::keys::{
    open_account_key_with_password, open_item_key, open_item_payload, open_vault_key,
    wrap_account_key_with_password, wrap_item_key, wrap_vault_key, AccountKey, ItemKey, UnlockKey,
    VaultKey,
};
use crypto_core::Context;
use proptest::prelude::*;

fn any_record_kind() -> impl Strategy<Value = RecordKind> {
    prop_oneof![
        Just(RecordKind::AccountWrap),
        Just(RecordKind::RecoveryWrap),
        Just(RecordKind::VaultWrap),
        Just(RecordKind::ItemWrap),
        Just(RecordKind::ItemPayload),
        Just(RecordKind::ExportManifest),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn item_payload_round_trip_arbitrary_plaintexts(
        plaintext in proptest::collection::vec(any::<u8>(), 1..=2048),
        key_version in 1u64..=8,
        item_suffix in "[a-z0-9_]{1,8}",
    ) {
        let item_key = ItemKey::generate();
        let item_id = format!("item_{item_suffix}");
        let envelope = crypto_core::keys::seal_item_payload(
            &item_key, "account_01", "vault_01", &item_id, key_version, &plaintext,
        )
        .unwrap();
        let opened = open_item_payload(
            &item_key, "account_01", "vault_01", &item_id, key_version, &envelope,
        )
        .unwrap();
        prop_assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn tampering_any_envelope_byte_fails_closed(
        plaintext in proptest::collection::vec(any::<u8>(), 16..=256),
        offset in any::<usize>(),
    ) {
        let item_key = ItemKey::generate();
        let envelope = crypto_core::keys::seal_item_payload(
            &item_key, "account_01", "vault_01", "item_01", 1, &plaintext,
        )
        .unwrap();
        let offset = offset % envelope.len();
        let mut tampered = envelope.clone();
        tampered[offset] ^= 0x01;
        // Never panics; always a typed error; never returns plaintext.
        let result = open_item_payload(&item_key, "account_01", "vault_01", "item_01", 1, &tampered);
        prop_assert!(result.is_err());
    }

    #[test]
    fn wrong_context_never_opens(
        plaintext in proptest::collection::vec(any::<u8>(), 16..=128),
        field in 0u8..4,
        value in "[a-z0-9_]{1,8}",
    ) {
        let item_key = ItemKey::generate();
        let envelope = crypto_core::keys::seal_item_payload(
            &item_key, "account_01", "vault_01", "item_01", 1, &plaintext,
        )
        .unwrap();
        let (account, vault, item, version) = match field % 4 {
            0 => ("account_02", "vault_01", "item_01", 1u64),
            1 => ("account_01", "vault_02", "item_01", 1),
            2 => ("account_01", "vault_01", value.as_str(), 1),
            _ => ("account_01", "vault_01", "item_01", 2),
        };
        let result = open_item_payload(&item_key, account, vault, item, version, &envelope);
        prop_assert_eq!(result.unwrap_err(), crypto_core::Error::InvalidContext);
    }

    #[test]
    fn hierarchy_round_trip_arbitrary_versions(key_version in 1u64..=32) {
        let account_key = AccountKey::generate();
        let vault_key = VaultKey::generate();
        let item_key = ItemKey::generate();
        let unlock_key = UnlockKey::generate();

        let wrapped_account =
            wrap_account_key_with_password(&unlock_key, &account_key, "account_01", key_version).unwrap();
        let opened_account =
            open_account_key_with_password(&unlock_key, &wrapped_account, "account_01", key_version)
                .unwrap();
        prop_assert_eq!(opened_account.as_bytes(), account_key.as_bytes());

        let wrapped_vault =
            wrap_vault_key(&account_key, &vault_key, "account_01", "vault_01", key_version).unwrap();
        let opened_vault =
            open_vault_key(&account_key, &wrapped_vault, "account_01", "vault_01", key_version)
                .unwrap();
        prop_assert_eq!(opened_vault.as_bytes(), vault_key.as_bytes());

        let wrapped_item =
            wrap_item_key(&vault_key, &item_key, "account_01", "vault_01", "item_01", key_version)
                .unwrap();
        let opened_item =
            open_item_key(&vault_key, &wrapped_item, "account_01", "vault_01", "item_01", key_version)
                .unwrap();
        prop_assert_eq!(opened_item.as_bytes(), item_key.as_bytes());
    }

    #[test]
    fn aad_reencoding_is_a_fixpoint(
        account in "[a-zA-Z0-9_]{1,12}",
        vault in proptest::option::of("[a-zA-Z0-9_]{1,12}"),
        key_version in 1u64..=100,
        kind in any_record_kind(),
    ) {
        // Build a nullability-consistent context for the chosen kind.
        let (vault_id, item_id) = match kind {
            RecordKind::VaultWrap => (vault.as_deref(), None),
            RecordKind::ItemWrap | RecordKind::ItemPayload => {
                (vault.as_deref().or(Some("vault_01")), Some("item_01"))
            }
            _ => (None, None),
        };
        let needs_vault = matches!(
            kind,
            RecordKind::VaultWrap | RecordKind::ItemWrap | RecordKind::ItemPayload
        );
        prop_assume!(!needs_vault || vault_id.is_some());
        let ctx = Context {
            account_id: &account,
            vault_id,
            item_id,
            record_kind: kind,
            key_version,
        };
        match crypto_core::envelope::encode_aad(&ctx) {
            Ok(encoded) => {
                let decoded = crypto_core::envelope::validate_aad(&encoded).unwrap();
                prop_assert_eq!(decoded, ctx);
                let reencoded = crypto_core::envelope::encode_aad(&decoded).unwrap();
                prop_assert_eq!(encoded, reencoded);
            }
            Err(crypto_core::Error::InvalidContext) => {}
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }
}
