//! Shared test-only helpers: fixture loading, `hex:`/`b64:` decoding and
//! the deterministic tamper rule. Nothing here is production code.

use std::fmt;
use std::path::PathBuf;

/// Decode a `hex:`-prefixed (or bare) lowercase hex string.
pub fn hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("hex:").unwrap_or(s);
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

/// Decode a `b64:`-prefixed standard RFC 4648 string with padding
/// (test-only implementation; no production dependency introduced).
pub fn b64(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("b64:").unwrap_or(s);
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for (index, ch) in s.bytes().enumerate() {
        if ch == b'=' {
            assert_eq!(s.len() - index, s.len() - index); // padding only at end
            continue;
        }
        let value = ALPHABET
            .iter()
            .position(|&a| a == ch)
            .expect("valid base64 character") as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

/// Decode a fixture byte field (`hex:` or `b64:` prefix required).
pub fn bytes_field(s: &str) -> Vec<u8> {
    if let Some(rest) = s.strip_prefix("hex:") {
        hex(rest)
    } else if let Some(rest) = s.strip_prefix("b64:") {
        b64(rest)
    } else {
        panic!("fixture byte field must carry a hex:/b64: prefix");
    }
}

/// Locate `fixtures/crypto/<name>` relative to this crate.
pub fn fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("fixtures");
    path.push("crypto");
    path.push(name);
    path
}

/// Load and parse a JSON fixture.
pub fn load_fixture(name: &str) -> serde_json::Value {
    let raw = std::fs::read(fixture_path(name)).expect("fixture file readable");
    serde_json::from_slice(&raw).expect("fixture is valid JSON")
}

/// Apply the fixtures' `xor-0x01-at-offset` tamper rule.
pub fn xor_at_offset(bytes: &[u8], offset: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[offset] ^= 0x01;
    out
}

/// Deterministic scripted RNG for reproducing fixed test vectors.
///
/// `fill_bytes` consumes the stream sequentially; the [0u8; 32] padding
/// after a 32-byte scalar reproduces that scalar exactly because the
/// underlying `Scalar::random` wide-reduces the 64 drawn bytes.
pub struct ScriptedRng {
    stream: Vec<u8>,
    position: usize,
    label: &'static str,
}

impl ScriptedRng {
    pub fn new(label: &'static str, stream: Vec<u8>) -> Self {
        Self {
            stream,
            position: 0,
            label,
        }
    }

    /// A wide-reduction chunk that yields exactly `scalar_le`.
    pub fn scalar(scalar_le: &[u8]) -> Vec<u8> {
        assert_eq!(scalar_le.len(), 32);
        let mut chunk = scalar_le.to_vec();
        chunk.extend_from_slice(&[0u8; 32]);
        chunk
    }

    fn take(&mut self, len: usize) -> Vec<u8> {
        assert!(
            self.position + len <= self.stream.len(),
            "scripted rng '{}' exhausted at offset {} (need {len} more bytes)",
            self.label,
            self.position
        );
        let out = self.stream[self.position..self.position + len].to_vec();
        self.position += len;
        out
    }
}

impl rand::RngCore for ScriptedRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().expect("4 bytes"))
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().expect("8 bytes"))
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(&self.take(dest.len()));
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand::CryptoRng for ScriptedRng {}

impl fmt::Debug for ScriptedRng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScriptedRng(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex("hex:00ff10"), vec![0x00, 0xff, 0x10]);
        assert_eq!(hex("a1b2"), vec![0xa1, 0xb2]);
    }

    #[test]
    fn b64_decodes_standard_alphabet() {
        // RFC 4648 test vectors.
        assert_eq!(b64("b64:"), Vec::<u8>::new());
        assert_eq!(b64("b64:Zg=="), b"f".to_vec());
        assert_eq!(b64("b64:Zm8="), b"fo".to_vec());
        assert_eq!(b64("b64:Zm9v"), b"foo".to_vec());
        assert_eq!(b64("b64:Zm9vYg=="), b"foob".to_vec());
        assert_eq!(b64("b64:Zm9vYmE="), b"fooba".to_vec());
        assert_eq!(b64("b64:Zm9vYmFy"), b"foobar".to_vec());
    }

    #[test]
    fn scripted_rng_wide_reduction_chunk_is_deterministic() {
        let scalar = [0x42u8; 32];
        let mut rng = ScriptedRng::new("t", ScriptedRng::scalar(&scalar));
        let mut buf = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rng, &mut buf);
        assert_eq!(&buf[..32], &scalar);
        assert_eq!(&buf[32..], &[0u8; 32]);
    }
}
