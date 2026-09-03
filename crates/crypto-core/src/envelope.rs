//! Canonical envelope bytes and AAD construction for `crypto-envelope/v1`.
//!
//! The outer envelope is a canonical CBOR map with integer keys
//! `{1: version, 2: kind, 3: keyVersion, 4: nonce, 5: ciphertext, 6: aad}`.
//! The AAD is the canonical CBOR map
//! `{1: version, 2: accountId, 3: vaultId-or-null, 4: itemId-or-null,
//! 5: recordType, 6: keyVersion}`. Decryption re-derives the expected AAD
//! from the caller-supplied context and rejects any mismatch before touching
//! the AEAD, so identifiers, record types and key versions are all bound into
//! the authentication of every envelope.

use zeroize::Zeroizing;

use crate::aead;
use crate::canon::{self, StrictMap, FORMAT_VERSION};
use crate::error::Error;

/// Record kinds defined by the contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    AccountWrap,
    RecoveryWrap,
    VaultWrap,
    ItemWrap,
    ItemPayload,
    ExportManifest,
}

impl RecordKind {
    /// The contract text value of this kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::AccountWrap => "account-wrap",
            RecordKind::RecoveryWrap => "recovery-wrap",
            RecordKind::VaultWrap => "vault-wrap",
            RecordKind::ItemWrap => "item-wrap",
            RecordKind::ItemPayload => "item-payload",
            RecordKind::ExportManifest => "export-manifest",
        }
    }

    /// Parse a contract kind text value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "account-wrap" => RecordKind::AccountWrap,
            "recovery-wrap" => RecordKind::RecoveryWrap,
            "vault-wrap" => RecordKind::VaultWrap,
            "item-wrap" => RecordKind::ItemWrap,
            "item-payload" => RecordKind::ItemPayload,
            "export-manifest" => RecordKind::ExportManifest,
            _ => return None,
        })
    }

    fn expects_vault(self) -> bool {
        matches!(
            self,
            RecordKind::VaultWrap | RecordKind::ItemWrap | RecordKind::ItemPayload
        )
    }

    fn expects_item(self) -> bool {
        matches!(self, RecordKind::ItemWrap | RecordKind::ItemPayload)
    }
}

/// The AAD context of an envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context<'a> {
    /// Account identifier; always present in v1.
    pub account_id: &'a str,
    /// Vault identifier; required for vault/item kinds, null otherwise.
    pub vault_id: Option<&'a str>,
    /// Item identifier; required for item kinds, null otherwise.
    pub item_id: Option<&'a str>,
    /// The record kind bound into the AAD.
    pub record_kind: RecordKind,
    /// Wrapper/payload version; rotation increments it.
    pub key_version: u64,
}

impl Context<'_> {
    fn validate(&self) -> Result<(), Error> {
        if self.account_id.is_empty() {
            return Err(Error::InvalidContext);
        }
        if self.vault_id.is_some_and(str::is_empty) || self.item_id.is_some_and(str::is_empty) {
            return Err(Error::InvalidContext);
        }
        if self.vault_id.is_some() != self.record_kind.expects_vault() {
            return Err(Error::InvalidContext);
        }
        if self.item_id.is_some() != self.record_kind.expects_item() {
            return Err(Error::InvalidContext);
        }
        if self.key_version == 0 {
            return Err(Error::InvalidContext);
        }
        Ok(())
    }

    fn encode_aad(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let vault = match self.vault_id {
            Some(id) => canon::text(3, id),
            None => canon::null(3),
        };
        let item = match self.item_id {
            Some(id) => canon::text(4, id),
            None => canon::null(4),
        };
        canon::encode_owned(vec![
            canon::text(1, FORMAT_VERSION),
            canon::text(2, self.account_id),
            vault,
            item,
            canon::text(5, self.record_kind.as_str()),
            canon::int(
                6,
                i64::try_from(self.key_version).map_err(|_| Error::InvalidContext)?,
            ),
        ])
    }
}

fn decode_aad(bytes: &[u8]) -> Result<Context<'_>, Error> {
    let map = StrictMap::decode(bytes)?;
    map.require_keys(&[1, 2, 3, 4, 5, 6])?;
    map.assert_canonical_bytes(bytes)?;
    if !map.text_is(1, FORMAT_VERSION).unwrap_or(false) {
        return Err(Error::UnsupportedVersion);
    }
    let account_id = map.get_text(2).ok_or(Error::InvalidEncoding)?;
    let record_kind = RecordKind::parse(map.get_text(5).ok_or(Error::InvalidEncoding)?)
        .ok_or(Error::InvalidEncoding)?;
    let key_version = u64::try_from(map.get_int(6).ok_or(Error::InvalidEncoding)?)
        .map_err(|_| Error::InvalidContext)?;
    let vault_id = match map.get_text(3) {
        Some(id) => Some(id),
        None if map.get_null(3).is_some() => None,
        None => return Err(Error::InvalidEncoding),
    };
    let item_id = match map.get_text(4) {
        Some(id) => Some(id),
        None if map.get_null(4).is_some() => None,
        None => return Err(Error::InvalidEncoding),
    };
    let ctx = Context {
        account_id,
        vault_id,
        item_id,
        record_kind,
        key_version,
    };
    ctx.validate()?;
    Ok(ctx)
}

/// Canonical AAD bytes for a validated context (fixture-verifiable form).
pub fn encode_aad(ctx: &Context<'_>) -> Result<Vec<u8>, Error> {
    ctx.encode_aad()
}

/// Strictly decode and validate canonical AAD bytes.
///
/// Returns the embedded context or a typed error; used by fixture
/// verification and by callers that need to inspect AAD in isolation.
pub fn validate_aad(bytes: &[u8]) -> Result<Context<'_>, Error> {
    decode_aad(bytes)
}

struct EnvelopeParts<'a> {
    kind: RecordKind,
    key_version: u64,
    nonce: &'a [u8],
    ciphertext_and_tag: &'a [u8],
    aad: &'a [u8],
}

fn decode_envelope(bytes: &[u8]) -> Result<EnvelopeParts<'_>, Error> {
    let map = StrictMap::decode(bytes)?;
    map.require_keys(&[1, 2, 3, 4, 5, 6])?;
    map.assert_canonical_bytes(bytes)?;
    if !map.text_is(1, FORMAT_VERSION).unwrap_or(false) {
        return Err(Error::UnsupportedVersion);
    }
    let kind = RecordKind::parse(map.get_text(2).ok_or(Error::InvalidEncoding)?)
        .ok_or(Error::InvalidEncoding)?;
    let key_version = u64::try_from(map.get_int(3).ok_or(Error::InvalidEncoding)?)
        .map_err(|_| Error::InvalidContext)?;
    let nonce = map.get_bytes(4).ok_or(Error::InvalidEncoding)?;
    let ciphertext = map.get_bytes(5).ok_or(Error::InvalidEncoding)?;
    let aad = map.get_bytes(6).ok_or(Error::InvalidEncoding)?;
    if nonce.len() != aead::NONCE_LEN {
        return Err(Error::InvalidNonce);
    }
    if ciphertext.len() < aead::TAG_LEN {
        return Err(Error::InvalidEncoding);
    }
    Ok(EnvelopeParts {
        kind,
        key_version,
        nonce,
        ciphertext_and_tag: ciphertext,
        aad,
    })
}

fn plaintext_within_limit(kind: RecordKind, len: usize) -> bool {
    match kind {
        RecordKind::ItemPayload | RecordKind::ExportManifest => {
            !len_is_empty(len) && len <= aead::MAX_ITEM_PLAINTEXT_LEN
        }
        RecordKind::AccountWrap
        | RecordKind::RecoveryWrap
        | RecordKind::VaultWrap
        | RecordKind::ItemWrap => len == aead::KEY_LEN,
    }
}

fn len_is_empty(len: usize) -> bool {
    len == 0
}

/// Encrypt `plaintext` into a canonical envelope under `key` and `ctx`.
///
/// The nonce is 24 fresh OS-CSPRNG bytes generated here; callers cannot
/// inject a nonce, which structurally prevents nonce reuse under the same
/// key and context.
pub fn seal_envelope(key: &[u8], ctx: &Context<'_>, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    ctx.validate()?;
    if key.len() != aead::KEY_LEN {
        return Err(Error::InvalidKeyLength);
    }
    if !plaintext_within_limit(ctx.record_kind, plaintext.len()) {
        return Err(Error::InvalidKeyLength);
    }
    let aad_bytes = ctx.encode_aad()?;
    let mut nonce = [0u8; aead::NONCE_LEN];
    aead::fill_random(&mut nonce);
    let ciphertext = aead::seal(key, &nonce, plaintext, &aad_bytes)?;
    let envelope = canon::encode_owned(vec![
        canon::text(1, FORMAT_VERSION),
        canon::text(2, ctx.record_kind.as_str()),
        canon::int(
            3,
            i64::try_from(ctx.key_version).map_err(|_| Error::InvalidContext)?,
        ),
        canon::bytes(4, nonce),
        canon::bytes(5, ciphertext),
        canon::bytes(6, aad_bytes),
    ])?;
    // Contract limits: 1 MiB per item plaintext (already enforced above,
    // with room for the envelope overhead only) and 64 KiB per wrapped-key
    // envelope. Wrap envelopes are structurally ~150 bytes, so this is a
    // fail-closed sanity bound, never a reachable path for valid input.
    let envelope_limit = match ctx.record_kind {
        RecordKind::AccountWrap
        | RecordKind::RecoveryWrap
        | RecordKind::VaultWrap
        | RecordKind::ItemWrap => aead::MAX_WRAPPED_KEY_LEN,
        RecordKind::ItemPayload | RecordKind::ExportManifest => {
            aead::MAX_ITEM_PLAINTEXT_LEN + aead::TAG_LEN + 1024
        }
    };
    if envelope.len() > envelope_limit {
        return Err(Error::Internal);
    }
    Ok(envelope)
}

/// Authenticate, context-check and decrypt an envelope.
///
/// Ordering of checks: strict canonical decode, version, key set, nonce
/// length, then AAD equality against the expected context
/// ([`Error::InvalidContext`] on mismatch), then AEAD authentication
/// ([`Error::AuthenticationFailed`] on failure). Plaintext is returned in a
/// zeroizing buffer and is never partially released.
pub fn open_envelope(
    key: &[u8],
    expected_ctx: &Context<'_>,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    expected_ctx.validate()?;
    if key.len() != aead::KEY_LEN {
        return Err(Error::InvalidKeyLength);
    }
    let parts = decode_envelope(envelope)?;
    let expected_aad = expected_ctx.encode_aad()?;
    let embedded_ctx = decode_aad(parts.aad)?;
    // Three-way binding before any authentication is attempted: the outer
    // envelope kind, the record type inside the authenticated AAD, and the
    // caller's expected context must all agree, and the outer keyVersion
    // must equal the AAD keyVersion. A substituted outer kind is rejected
    // here even though the bytes otherwise decode.
    if parts.kind != embedded_ctx.record_kind
        || embedded_ctx != *expected_ctx
        || embedded_ctx.key_version != parts.key_version
    {
        return Err(Error::InvalidContext);
    }
    if parts.aad != expected_aad.as_slice() {
        return Err(Error::InvalidContext);
    }
    let plaintext = aead::open(key, parts.nonce, parts.ciphertext_and_tag, &expected_aad)?;
    // Size limits are enforced under the authenticated record kind (the
    // expected context the AAD bound), never under the outer envelope kind
    // alone, which is only trusted after the three-way match above.
    if !plaintext_within_limit(expected_ctx.record_kind, plaintext.len()) {
        return Err(Error::InvalidKeyLength);
    }
    Ok(plaintext)
}

/// Strictly decode only the metadata of an envelope without decrypting it.
///
/// Useful for UI routing; performs the same canonical, version, key-set and
/// nonce checks as [`open_envelope`], requires the outer kind to match the
/// AAD record type, and returns the AAD context.
pub fn inspect_envelope(envelope: &[u8]) -> Result<Context<'_>, Error> {
    let parts = decode_envelope(envelope)?;
    let ctx = decode_aad(parts.aad)?;
    if parts.kind != ctx.record_kind {
        return Err(Error::InvalidContext);
    }
    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    fn item_ctx<'a>() -> Context<'a> {
        Context {
            account_id: "account_01",
            vault_id: Some("vault_01"),
            item_id: Some("item_01"),
            record_kind: RecordKind::ItemPayload,
            key_version: 1,
        }
    }

    #[test]
    fn aad_matches_reference_fixture_bytes() {
        // fixtures/crypto/aad-item-payload.json canonicalCborHex.
        let expected = hex("a6017263727970746f2d656e76656c6f70652f7631026a6163636f756e745f303103687661756c745f303104676974656d5f3031056c6974656d2d7061796c6f61640601");
        assert_eq!(item_ctx().encode_aad().unwrap(), expected);
    }

    #[test]
    fn seal_open_round_trip() {
        let envelope = seal_envelope(&KEY, &item_ctx(), b"secret payload").unwrap();
        let plaintext = open_envelope(&KEY, &item_ctx(), &envelope).unwrap();
        assert_eq!(*plaintext, b"secret payload".to_vec());
    }

    #[test]
    fn context_mismatch_rejects_before_aead() {
        let envelope = seal_envelope(&KEY, &item_ctx(), b"secret payload").unwrap();
        let mut wrong = item_ctx();
        wrong.item_id = Some("item_02");
        assert_eq!(
            open_envelope(&KEY, &wrong, &envelope).unwrap_err(),
            Error::InvalidContext
        );
    }

    #[test]
    fn wrong_key_version_rejects() {
        let envelope = seal_envelope(&KEY, &item_ctx(), b"secret payload").unwrap();
        let mut wrong = item_ctx();
        wrong.key_version = 2;
        assert_eq!(
            open_envelope(&KEY, &wrong, &envelope).unwrap_err(),
            Error::InvalidContext
        );
    }

    #[test]
    fn wrong_kind_rejects() {
        let envelope = seal_envelope(&KEY, &item_ctx(), b"secret payload").unwrap();
        let mut wrong = item_ctx();
        wrong.record_kind = RecordKind::ItemWrap;
        assert_eq!(
            open_envelope(&KEY, &wrong, &envelope).unwrap_err(),
            Error::InvalidContext
        );
    }

    #[test]
    fn wrap_kinds_take_exactly_32_byte_plaintexts() {
        let ctx = Context {
            account_id: "account_01",
            vault_id: None,
            item_id: None,
            record_kind: RecordKind::AccountWrap,
            key_version: 1,
        };
        assert_eq!(
            seal_envelope(&KEY, &ctx, &[0u8; 31]).unwrap_err(),
            Error::InvalidKeyLength
        );
        assert_eq!(
            seal_envelope(&KEY, &ctx, &[0u8; 33]).unwrap_err(),
            Error::InvalidKeyLength
        );
        assert!(seal_envelope(&KEY, &ctx, &[42u8; 32]).is_ok());
    }

    #[test]
    fn item_payload_limit_is_enforced() {
        let big = vec![0u8; aead::MAX_ITEM_PLAINTEXT_LEN + 1];
        assert_eq!(
            seal_envelope(&KEY, &item_ctx(), &big).unwrap_err(),
            Error::InvalidKeyLength
        );
    }

    #[test]
    fn exactly_one_mib_item_payload_seals_and_opens() {
        // The contract maximum must round-trip; the envelope-size sanity
        // bound may not reject a maximum-size item.
        let big = vec![0xa5u8; aead::MAX_ITEM_PLAINTEXT_LEN];
        let envelope = seal_envelope(&KEY, &item_ctx(), &big).unwrap();
        let opened = open_envelope(&KEY, &item_ctx(), &envelope).unwrap();
        assert_eq!(opened.len(), aead::MAX_ITEM_PLAINTEXT_LEN);
    }

    #[test]
    fn nullability_rules_are_enforced() {
        let mut ctx = Context {
            account_id: "account_01",
            vault_id: Some("vault_01"),
            item_id: None,
            record_kind: RecordKind::AccountWrap,
            key_version: 1,
        };
        assert_eq!(ctx.validate().unwrap_err(), Error::InvalidContext);
        ctx.vault_id = None;
        ctx.item_id = Some("item_01");
        assert_eq!(ctx.validate().unwrap_err(), Error::InvalidContext);
        ctx.item_id = None;
        ctx.record_kind = RecordKind::VaultWrap;
        assert_eq!(ctx.validate().unwrap_err(), Error::InvalidContext);
        ctx.record_kind = RecordKind::ItemPayload;
        assert_eq!(ctx.validate().unwrap_err(), Error::InvalidContext);
        ctx.vault_id = Some("vault_01");
        ctx.item_id = Some("item_01");
        ctx.validate().unwrap();
    }

    #[test]
    fn nonces_are_unique_across_seals() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..128 {
            let envelope = seal_envelope(&KEY, &item_ctx(), b"x").unwrap();
            let map = canon::StrictMap::decode(&envelope).unwrap();
            let nonce = map.get_bytes(4).unwrap().to_vec();
            assert_eq!(nonce.len(), aead::NONCE_LEN);
            assert!(seen.insert(nonce), "nonce reuse detected");
        }
    }

    #[test]
    fn inspect_returns_embedded_context() {
        let envelope = seal_envelope(&KEY, &item_ctx(), b"secret payload").unwrap();
        assert_eq!(inspect_envelope(&envelope).unwrap(), item_ctx());
    }

    #[test]
    fn outer_kind_substitution_rejects_before_authentication() {
        // Structured attack: re-encode a genuine item-payload envelope with
        // the outer kind swapped to item-wrap while the AAD (and ciphertext)
        // still bind item-payload. The bytes are canonical and well-formed;
        // only the three-way kind binding can catch it.
        let envelope = seal_envelope(&KEY, &item_ctx(), b"secret payload").unwrap();
        let map = canon::StrictMap::decode(&envelope).unwrap();
        let substituted = canon::encode_owned(vec![
            canon::text(1, FORMAT_VERSION),
            canon::text(2, RecordKind::ItemWrap.as_str()),
            canon::int(3, map.get_int(3).unwrap()),
            canon::bytes(4, map.get_bytes(4).unwrap().to_vec()),
            canon::bytes(5, map.get_bytes(5).unwrap().to_vec()),
            canon::bytes(6, map.get_bytes(6).unwrap().to_vec()),
        ])
        .unwrap();
        // Opening with the genuine context must reject: the outer kind does
        // not match the AAD record type.
        assert_eq!(
            open_envelope(&KEY, &item_ctx(), &substituted).unwrap_err(),
            Error::InvalidContext
        );
        // Opening with the substituted kind's context also rejects: the
        // authenticated AAD still binds item-payload.
        let mut wrap_ctx = item_ctx();
        wrap_ctx.record_kind = RecordKind::ItemWrap;
        assert_eq!(
            open_envelope(&KEY, &wrap_ctx, &substituted).unwrap_err(),
            Error::InvalidContext
        );
        // Metadata inspection rejects the same substitution.
        assert_eq!(
            inspect_envelope(&substituted).unwrap_err(),
            Error::InvalidContext
        );
        // The unmodified envelope still opens (control).
        assert!(open_envelope(&KEY, &item_ctx(), &envelope).is_ok());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
