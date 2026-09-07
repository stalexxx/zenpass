//! DTO skeleton mapped manually from `packages/contracts/openapi.yaml` (the
//! single source of truth). Shapes only: no product routes are implemented in
//! RUST-02. Unknown fields are rejected (`additionalProperties: false`),
//! binary fields use the distinct prefixed/padded encodings, and `DateTime`
//! is RFC 3339 UTC.

use serde::{Deserialize, Serialize, de::Error};

pub const ENVELOPE_VERSION: &str = "crypto-envelope/v1";
const ID_MAX: usize = 128;

/// `Id`: `^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`.
pub fn validate_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && value.len() <= ID_MAX
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Prefixed padded standard base64 matching `^b64:[A-Za-z0-9+/]+={0,2}$`
/// and additionally decodable as canonical standard base64 (so malformed
/// lengths such as `b64:QUJD=` are rejected at the boundary).
/// URL-safe alphabets are deliberately a different encoding and rejected.
pub fn validate_b64(value: &str) -> bool {
    use base64::Engine;
    let Some(encoded) = value.strip_prefix("b64:") else {
        return false;
    };
    let body = encoded.trim_end_matches('=');
    let padding = encoded.len() - body.len();
    !body.is_empty()
        && padding <= 2
        && !body.contains('=')
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        && base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .is_ok()
}

/// RFC 3339 date-time; serialized values are always UTC.
pub fn validate_datetime(value: &str) -> bool {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).is_ok()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    pub error: &'static str,
    pub message: &'static str,
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OpaqueMessage {
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OpaqueRegisterRequest {
    pub account_id: String,
    pub client_message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OpaqueLoginRequest {
    pub account_id: String,
    pub client_message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Session {
    pub access_token: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KeyBundle {
    pub bundle: String,
    pub version: i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KeyBundleConflict {
    pub error: String,
    pub current_version: Option<i32>,
    pub attempted_version: i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecoveryResetRequest {
    pub recovery_proof: String,
    pub key_bundle: KeyBundle,
}

/// `enrollmentMode: "bearer-session-v1"` const marker (OpenAPI `const`).
#[derive(Debug, PartialEq, Eq)]
pub struct BearerSessionV1;

impl Serialize for BearerSessionV1 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("bearer-session-v1")
    }
}

impl<'de> Deserialize<'de> for BearerSessionV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = BearerSessionV1;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("the string \"bearer-session-v1\"")
            }
            fn visit_str<E: Error>(self, value: &str) -> Result<BearerSessionV1, E> {
                if value == "bearer-session-v1" {
                    Ok(BearerSessionV1)
                } else {
                    Err(E::custom("unexpected enrollment mode"))
                }
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeviceCreateLegacy {
    pub name: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeviceCreateBearer {
    pub name: String,
    #[serde(rename = "enrollmentMode")]
    pub enrollment_mode: BearerSessionV1,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceCreate {
    LegacyPublicKey(DeviceCreateLegacy),
    BearerSession(DeviceCreateBearer),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Device {
    pub device_id: String,
    pub name: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeviceList {
    pub devices: Vec<Device>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ItemRecord {
    pub item_id: String,
    pub vault_id: String,
    pub ciphertext: String,
    pub envelope_version: String,
    pub revision: i64,
    pub deleted: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Mutation {
    pub mutation_id: String,
    pub item_id: String,
    pub vault_id: String,
    pub base_revision: i64,
    pub ciphertext: String,
    pub envelope_version: String,
    pub deleted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangePage {
    pub changes: Vec<ItemRecord>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Conflict {
    pub error: String,
    pub mutation_id: String,
    pub current: ItemRecord,
    pub attempted: Mutation,
}
