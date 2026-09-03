//! Strict canonical-CBOR validation and encoding for `crypto-envelope/v1`
//! (ADR-0003 finding F-2 follow-up).
//!
//! `minicbor` is approved conditionally on exactly this wrapper: it is used
//! only behind [decode]/**[`StrictMap`]**, which enforces the contract's
//! canonical rules before any semantic interpretation:
//!
//! * definite-length maps and strings only (indefinite lengths reject as
//!   [`Error::NonCanonicalCbor`]);
//! * integer keys in strictly ascending numeric order (unordered and
//!   duplicate keys reject as [`Error::NonCanonicalCbor`]);
//! * tags and floating point values reject as [`Error::NonCanonicalCbor`];
//! * every accepted byte string must re-encode to identical bytes, which
//!   rejects non-minimal integer encodings (for example `0x18 0x13` for 19)
//!   and any remaining non-canonical form;
//! * trailing bytes after the map reject as [`Error::InvalidEncoding`].
//!
//! Encoding helpers in this module produce canonical bytes by construction:
//! fixed key order, minimal integer encodings and definite lengths come from
//! the underlying encoder, and round-trip equality is asserted by tests.

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use crate::error::Error;

/// The only format version string accepted in v1 envelopes and AAD.
pub const FORMAT_VERSION: &str = "crypto-envelope/v1";

/// Maximum number of map entries ever accepted in a contract map. Maps with
/// more entries necessarily contain unknown or duplicate keys.
const MAX_MAP_ENTRIES: usize = 16;

/// A strictly validated CBOR value from a contract map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Field<'a> {
    Text(&'a str),
    Bytes(&'a [u8]),
    Int(i64),
    Null,
}

impl<'a> Field<'a> {
    fn as_text(self) -> Option<&'a str> {
        match self {
            Field::Text(text) => Some(text),
            _ => None,
        }
    }

    fn as_bytes(self) -> Option<&'a [u8]> {
        match self {
            Field::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    fn as_int(self) -> Option<i64> {
        match self {
            Field::Int(int) => Some(int),
            _ => None,
        }
    }

    fn is_null(self) -> bool {
        matches!(self, Field::Null)
    }
}

/// A canonical CBOR map with integer keys, decoded under the strict rules of
/// this module. Entries are stored in decoded (ascending) key order.
#[derive(Debug)]
pub(crate) struct StrictMap<'a> {
    entries: Vec<(u64, Field<'a>)>,
}

impl<'a> StrictMap<'a> {
    /// Strictly decode a canonical CBOR map with integer keys from `bytes`.
    ///
    /// This performs every structural canonicality check; key-set and value
    /// semantics belong to the callers of [`Self::require_keys`] and the
    /// per-map validators.
    pub(crate) fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes);
        let len = decoder.map().map_err(|_| Error::InvalidEncoding)?;
        let Some(len) = len else {
            return Err(Error::NonCanonicalCbor);
        };
        let len = usize::try_from(len).map_err(|_| Error::InvalidEncoding)?;
        if len > MAX_MAP_ENTRIES {
            // More entries than any contract map can contain: some key must
            // be unknown or duplicated. UnknownField is the closest typed
            // error and never leaks how far decoding went.
            return Err(Error::UnknownField);
        }

        let mut entries = Vec::with_capacity(len);
        for _ in 0..len {
            let key = read_key(&mut decoder)?;
            let value = read_value(&mut decoder)?;
            entries.push((key, value));
        }
        if decoder.position() != bytes.len() {
            return Err(Error::InvalidEncoding);
        }
        for window in entries.windows(2) {
            if window[0].0 >= window[1].0 {
                return Err(Error::NonCanonicalCbor);
            }
        }
        Ok(Self { entries })
    }

    /// Require the key set to be exactly `expected` (any order is impossible
    /// after canonical validation; missing keys are structural violations and
    /// keys outside the set are [`Error::UnknownField`]).
    pub(crate) fn require_keys(&self, expected: &[u64]) -> Result<(), Error> {
        for &key in expected {
            if !self.entries.iter().any(|(k, _)| *k == key) {
                return Err(Error::InvalidEncoding);
            }
        }
        for &(key, _) in &self.entries {
            if !expected.contains(&key) {
                return Err(Error::UnknownField);
            }
        }
        Ok(())
    }

    /// Assert that the decoded map re-encodes to exactly the input bytes.
    ///
    /// Combined with strict typing this is the F-2 enforcement step: any
    /// non-minimal integer encoding, non-shortest form, or otherwise
    /// non-canonical variant of an otherwise well-typed map is rejected here.
    pub(crate) fn assert_canonical_bytes(&self, bytes: &[u8]) -> Result<(), Error> {
        if encode_map(self.entries.iter().copied())? != bytes {
            return Err(Error::NonCanonicalCbor);
        }
        Ok(())
    }

    pub(crate) fn get_text(&self, key: u64) -> Option<&'a str> {
        self.field(key)?.as_text()
    }

    pub(crate) fn get_bytes(&self, key: u64) -> Option<&'a [u8]> {
        self.field(key)?.as_bytes()
    }

    pub(crate) fn get_int(&self, key: u64) -> Option<i64> {
        self.field(key)?.as_int()
    }

    pub(crate) fn get_null(&self, key: u64) -> Option<()> {
        self.field(key)?.is_null().then_some(())
    }

    pub(crate) fn text_is(&self, key: u64, expected: &str) -> Option<bool> {
        Some(self.get_text(key)? == expected)
    }

    fn field(&self, key: u64) -> Option<Field<'a>> {
        self.entries
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
    }
}

fn read_key(decoder: &mut Decoder<'_>) -> Result<u64, Error> {
    match decoder.datatype().map_err(|_| Error::InvalidEncoding)? {
        Type::U8
        | Type::U16
        | Type::U32
        | Type::U64
        | Type::I8
        | Type::I16
        | Type::I32
        | Type::I64
        | Type::Int => {
            let value = decoder.i64().map_err(|_| Error::InvalidEncoding)?;
            u64::try_from(value).map_err(|_| Error::UnknownField)
        }
        Type::Tag | Type::F16 | Type::F32 | Type::F64 => Err(Error::NonCanonicalCbor),
        _ => Err(Error::InvalidEncoding),
    }
}

fn read_value<'a>(decoder: &mut Decoder<'a>) -> Result<Field<'a>, Error> {
    let field = match decoder.datatype().map_err(|_| Error::InvalidEncoding)? {
        Type::String => Field::Text(decoder.str().map_err(|_| Error::InvalidEncoding)?),
        Type::Bytes => Field::Bytes(decoder.bytes().map_err(|_| Error::InvalidEncoding)?),
        Type::Null => {
            decoder.skip().map_err(|_| Error::InvalidEncoding)?;
            Field::Null
        }
        Type::U8
        | Type::U16
        | Type::U32
        | Type::U64
        | Type::I8
        | Type::I16
        | Type::I32
        | Type::I64
        | Type::Int => Field::Int(decoder.i64().map_err(|_| Error::InvalidEncoding)?),
        Type::Tag | Type::F16 | Type::F32 | Type::F64 => return Err(Error::NonCanonicalCbor),
        Type::StringIndef | Type::BytesIndef => return Err(Error::NonCanonicalCbor),
        _ => return Err(Error::InvalidEncoding),
    };
    Ok(field)
}

fn encode_map<'a, I>(entries: I) -> Result<Vec<u8>, Error>
where
    I: Iterator<Item = (u64, Field<'a>)>,
{
    let collected: Vec<(u64, Field<'a>)> = entries.collect();
    let mut encoder = Encoder::new(Vec::with_capacity(16 + collected.len() * 8));
    encoder
        .map(u64::try_from(collected.len()).map_err(|_| Error::Internal)?)
        .map_err(|_| Error::Internal)?;
    for (key, value) in collected {
        encoder.u64(key).map_err(|_| Error::Internal)?;
        match value {
            Field::Text(text) => encoder.str(text).map_err(|_| Error::Internal)?,
            Field::Bytes(bytes) => encoder.bytes(bytes).map_err(|_| Error::Internal)?,
            Field::Int(int) => encoder.i64(int).map_err(|_| Error::Internal)?,
            Field::Null => encoder.null().map_err(|_| Error::Internal)?,
        };
    }
    Ok(encoder.into_writer())
}

/// Encode a canonical CBOR map from `(key, value)` pairs.
///
/// Keys must already be unique and are emitted in the order given; callers in
/// this crate always pass ascending keys, so the output is canonical by
/// construction and tests assert round-trip equality with [`StrictMap`].
pub(crate) fn encode_owned(entries: Vec<(u64, OwnedField)>) -> Result<Vec<u8>, Error> {
    encode_map(entries.iter().map(|(k, v)| (*k, v.as_field())))
}

/// Owned counterpart of [`Field`] for encoding.
#[derive(Clone, Debug)]
pub(crate) enum OwnedField {
    Text(String),
    Bytes(Vec<u8>),
    Int(i64),
    Null,
}

impl OwnedField {
    fn as_field(&self) -> Field<'_> {
        match self {
            OwnedField::Text(text) => Field::Text(text.as_str()),
            OwnedField::Bytes(bytes) => Field::Bytes(bytes),
            OwnedField::Int(int) => Field::Int(*int),
            OwnedField::Null => Field::Null,
        }
    }
}

/// Append a text field under `key` to an owned entry list.
pub(crate) fn text(key: u64, value: impl Into<String>) -> (u64, OwnedField) {
    (key, OwnedField::Text(value.into()))
}

/// Append a bytes field under `key` to an owned entry list.
pub(crate) fn bytes(key: u64, value: impl Into<Vec<u8>>) -> (u64, OwnedField) {
    (key, OwnedField::Bytes(value.into()))
}

/// Append an integer field under `key` to an owned entry list.
pub(crate) fn int(key: u64, value: i64) -> (u64, OwnedField) {
    (key, OwnedField::Int(value))
}

/// Append a null field under `key` to an owned entry list.
pub(crate) fn null(key: u64) -> (u64, OwnedField) {
    (key, OwnedField::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("hex:").unwrap_or(s);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn indefinite_map_rejects() {
        let bytes = hex("bf0101ff");
        assert_eq!(
            StrictMap::decode(&bytes).unwrap_err(),
            Error::NonCanonicalCbor
        );
    }

    #[test]
    fn duplicate_keys_reject() {
        let bytes = hex("a2017263727970746f2d656e76656c6f70652f76310101");
        assert_eq!(
            StrictMap::decode(&bytes).unwrap_err(),
            Error::NonCanonicalCbor
        );
    }

    #[test]
    fn non_minimal_integer_rejects_via_reencode() {
        // key 2 encoded as 0x18 0x13 (19) instead of minimal 0x13.
        let bytes = hex("a1011813");
        assert_eq!(
            StrictMap::decode(&bytes)
                .and_then(|m| m.assert_canonical_bytes(&bytes))
                .unwrap_err(),
            Error::NonCanonicalCbor
        );
        // Minimal form of the same map is accepted.
        let minimal = hex("a10113");
        let map = StrictMap::decode(&minimal).unwrap();
        map.assert_canonical_bytes(&minimal).unwrap();
        assert_eq!(map.get_int(1), Some(19));
    }

    #[test]
    fn tagged_integer_rejects() {
        let bytes = hex("a106c24101");
        assert_eq!(
            StrictMap::decode(&bytes).unwrap_err(),
            Error::NonCanonicalCbor
        );
    }

    #[test]
    fn float_value_rejects() {
        let bytes = hex("a106f93c00");
        assert_eq!(
            StrictMap::decode(&bytes).unwrap_err(),
            Error::NonCanonicalCbor
        );
    }

    #[test]
    fn trailing_bytes_reject() {
        let bytes = hex("a1011300");
        assert_eq!(
            StrictMap::decode(&bytes).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn unordered_keys_reject() {
        let bytes = hex("a202020101");
        assert_eq!(
            StrictMap::decode(&bytes).unwrap_err(),
            Error::NonCanonicalCbor
        );
    }

    #[test]
    fn negative_key_reports_unknown_field() {
        let bytes = hex("a12001");
        assert_eq!(StrictMap::decode(&bytes).unwrap_err(), Error::UnknownField);
    }

    #[test]
    fn owned_encoding_round_trips_strictly() {
        let entries = vec![
            text(1, "crypto-envelope/v1"),
            int(2, 19),
            bytes(3, vec![0u8; 16]),
            null(4),
        ];
        let encoded = encode_owned(entries).unwrap();
        let map = StrictMap::decode(&encoded).unwrap();
        map.require_keys(&[1, 2, 3, 4]).unwrap();
        map.assert_canonical_bytes(&encoded).unwrap();
        assert_eq!(map.get_text(1), Some("crypto-envelope/v1"));
        assert_eq!(map.get_int(2), Some(19));
        assert_eq!(map.get_bytes(3), Some(&[0u8; 16][..]));
        assert_eq!(map.get_null(4), Some(()));
    }
}
