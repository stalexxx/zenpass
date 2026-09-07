//! Binary API value codec: `b64:` + standard RFC 4648 base64 with padding
//! (docs/contracts/crypto-envelope-v1.md). Ported unchanged from the Bun
//! reference's `auth/codec.mjs` (byte-for-byte identical acceptance rules).

use base64::Engine;

const PREFIX: &str = "b64:";

/// Returns the decoded bytes, or `None` if `value` isn't a well-formed
/// `b64:` string. Mirrors the Bun reference's `decodeB64`: the alphabet is
/// validated up front (a permissive decoder would otherwise silently ignore
/// invalid characters), and `body.len() % 4 == 0` is required.
pub fn decode_b64(value: &str) -> Option<Vec<u8>> {
    let body = value.strip_prefix(PREFIX)?;
    if body.len() % 4 != 0 {
        return None;
    }
    let core = body.trim_end_matches('=');
    let padding = body.len() - core.len();
    if padding > 2 {
        return None;
    }
    if !core
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

pub fn encode_b64(bytes: &[u8]) -> String {
    format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let encoded = encode_b64(b"hello world");
        assert_eq!(decode_b64(&encoded).unwrap(), b"hello world");
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(decode_b64("aGVsbG8=").is_none());
    }

    #[test]
    fn rejects_bad_alphabet() {
        assert!(decode_b64("b64:not base64!!").is_none());
    }

    #[test]
    fn rejects_bad_length() {
        assert!(decode_b64("b64:abcde").is_none());
    }

    #[test]
    fn accepts_empty_body() {
        assert_eq!(decode_b64("b64:").unwrap(), Vec::<u8>::new());
    }
}
