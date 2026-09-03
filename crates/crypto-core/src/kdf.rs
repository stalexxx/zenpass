//! Argon2id password KDF for `crypto-envelope/v1` (RFC 9106, v1.3, 32-byte
//! output, 16-byte salt).
//!
//! The password wrapper stores the canonical CBOR parameter map
//! `{1: "argon2id", 2: 19, 3: memoryKiB, 4: iterations, 5: parallelism,
//! 6: salt, 7: 32}`. Parameter bounds are enforced on construction and on
//! decode; they can never be silently weakened because validation only
//! accepts values at or above the contract minima, and the calibration
//! ladder in [`calibrate`] only produces in-bounds candidates.

use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use zeroize::Zeroizing;

use crate::canon::{self, StrictMap};
use crate::error::Error;
use crate::keys::UnlockKey;

/// Minimum accepted `memoryKiB` (contract: 64 MiB).
pub const MIN_MEMORY_KIB: u32 = 65_536;
/// Minimum accepted iterations (contract).
pub const MIN_ITERATIONS: u32 = 3;
/// Minimum accepted parallelism (contract).
pub const MIN_PARALLELISM: u32 = 1;
/// Argon2 salt length in bytes.
pub const SALT_LEN: usize = 16;
/// KDF output length in bytes.
pub const OUTPUT_LEN: usize = 32;
/// Argon2 version (v1.3) encoded in the parameter map.
pub const ARGON2_VERSION: i64 = 19;
/// Algorithm label in the parameter map.
pub const ALGORITHM: &str = "argon2id";
/// Maximum accepted `memoryKiB`: 2^32-1 KiB is the Argon2 limit; the
/// physical-memory cap (25%) is enforced separately by the caller.
const MAX_MEMORY_KIB: u32 = u32::MAX;

/// Calibrated Argon2id parameters with a 16-byte salt.
#[derive(Clone)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: Zeroizing<[u8; SALT_LEN]>,
}

impl std::fmt::Debug for KdfParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Salt bytes stay out of debug output by policy, even though the
        // stored salt is not secret; the conservative rule is cheaper than
        // arguing per-field classifications.
        f.debug_struct("KdfParams")
            .field("memory_kib", &self.memory_kib)
            .field("iterations", &self.iterations)
            .field("parallelism", &self.parallelism)
            .finish_non_exhaustive()
    }
}

impl KdfParams {
    /// Construct parameters from explicit values, enforcing contract bounds.
    pub fn new(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        salt: &[u8],
    ) -> Result<Self, Error> {
        let params = Self {
            memory_kib,
            iterations,
            parallelism,
            salt: Zeroizing::new(salt.try_into().map_err(|_| Error::InvalidKdfParameters)?),
        };
        params.validate()?;
        Ok(params)
    }

    /// Construct parameters with a fresh OS-CSPRNG salt.
    pub fn generate(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, Error> {
        let mut salt = Zeroizing::new([0u8; SALT_LEN]);
        crate::aead::fill_random(salt.as_mut());
        Self::new(memory_kib, iterations, parallelism, salt.as_ref())
    }

    fn validate(&self) -> Result<(), Error> {
        if self.memory_kib < MIN_MEMORY_KIB {
            return Err(Error::InvalidKdfParameters);
        }
        if self.iterations < MIN_ITERATIONS {
            return Err(Error::InvalidKdfParameters);
        }
        if self.parallelism < MIN_PARALLELISM {
            return Err(Error::InvalidKdfParameters);
        }
        Ok(())
    }

    /// Enforce the physical-memory cap (contract: at most 25% of reported
    /// physical memory). The caller supplies the reported total, because the
    /// source of that figure is runtime-specific (protocol §4.5 of the
    /// calibration document records this decision).
    pub fn validate_against_memory_cap(
        &self,
        reported_physical_memory_kib: u64,
    ) -> Result<(), Error> {
        if u64::from(self.memory_kib) * 4 > reported_physical_memory_kib {
            return Err(Error::KdfResourceLimit);
        }
        Ok(())
    }

    #[must_use]
    pub fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    #[must_use]
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    #[must_use]
    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }

    #[must_use]
    pub fn salt(&self) -> &[u8] {
        self.salt.as_ref()
    }

    /// Canonical CBOR encoding of the parameter map
    /// `{1: "argon2id", 2: 19, 3: memoryKiB, 4: iterations, 5: parallelism,
    /// 6: salt, 7: 32}`.
    pub fn encode_canonical_cbor(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        canon::encode_owned(vec![
            canon::text(1, ALGORITHM),
            canon::int(2, ARGON2_VERSION),
            canon::int(3, i64::from(self.memory_kib)),
            canon::int(4, i64::from(self.iterations)),
            canon::int(5, i64::from(self.parallelism)),
            canon::bytes(6, self.salt.to_vec()),
            canon::int(7, OUTPUT_LEN as i64),
        ])
    }

    /// Strictly decode and validate a parameter map.
    ///
    /// Encoding violations (non-minimal integers, unordered keys, tags,
    /// floats, indefinite lengths) reject as [`Error::NonCanonicalCbor`];
    /// structurally canonical but semantically invalid values (wrong
    /// algorithm/version, out-of-bounds parameters, wrong salt or output
    /// length — including the historical G-11 `0x20` encoding of -1) reject
    /// as [`Error::InvalidKdfParameters`].
    pub fn decode_canonical_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let map = StrictMap::decode(bytes)?;
        map.require_keys(&[1, 2, 3, 4, 5, 6, 7])?;
        map.assert_canonical_bytes(bytes)?;
        if map.get_text(1) != Some(ALGORITHM) {
            return Err(Error::InvalidKdfParameters);
        }
        if map.get_int(2) != Some(ARGON2_VERSION) {
            return Err(Error::InvalidKdfParameters);
        }
        let memory_kib = positive_u32(map.get_int(3))?;
        let iterations = positive_u32(map.get_int(4))?;
        let parallelism = positive_u32(map.get_int(5))?;
        let salt = map.get_bytes(6).ok_or(Error::InvalidKdfParameters)?;
        if salt.len() != SALT_LEN {
            return Err(Error::InvalidKdfParameters);
        }
        if map.get_int(7) != Some(OUTPUT_LEN as i64) {
            return Err(Error::InvalidKdfParameters);
        }
        Self::new(memory_kib, iterations, parallelism, salt)
    }
}

fn positive_u32(value: Option<i64>) -> Result<u32, Error> {
    let value = value.ok_or(Error::InvalidKdfParameters)?;
    u32::try_from(value).map_err(|_| Error::InvalidKdfParameters)
}

/// Derive an [`UnlockKey`] from a password with Argon2id.
///
/// Output is 32 bytes in a zeroizing buffer. The caller supplies validated
/// parameters; persisted parameters must be decoded with
/// [`KdfParams::decode_canonical_cbor`] first, which enforces the bounds.
pub fn derive_unlock_key(password: &[u8], params: &KdfParams) -> Result<UnlockKey, Error> {
    params.validate()?;
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.parallelism)
        .output_len(OUTPUT_LEN);
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        builder.build().map_err(|_| Error::InvalidKdfParameters)?,
    );
    let mut out = Zeroizing::new([0u8; OUTPUT_LEN]);
    argon
        .hash_password_into(password, params.salt(), out.as_mut())
        .map_err(|_| Error::Internal)?;
    UnlockKey::from_bytes(out.as_ref())
}

/// Number of timed samples per candidate point during calibration.
const CALIBRATION_SAMPLES: usize = 5;
/// Warm-up derives discarded per candidate point.
const CALIBRATION_WARMUP: usize = 1;

/// First-setup calibration per the contract: find parameters whose median
/// derive time falls in `target_min_ms..=target_max_ms`.
///
/// Ladder (calibration protocol §4.3): memory descends over powers of two
/// from the largest allowed by `max_memory_kib` (the caller computes the 25%
/// physical-memory cap and passes it here) down to 64 MiB; for each memory
/// value iterations start at 3 and double until the median reaches the
/// window. Every returned candidate satisfies the contract minima by
/// construction; parameters are never weakened because no out-of-bounds
/// value can be produced.
///
/// `password` and `salt` are calibration inputs; they must be test-only or
/// at least not weakly-held production secrets, since derivation timing is
/// observable by the caller.
pub fn calibrate(
    target_min_ms: u64,
    target_max_ms: u64,
    max_memory_kib: u64,
    parallelism: u32,
    password: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<KdfParams, Error> {
    if parallelism < MIN_PARALLELISM {
        return Err(Error::InvalidKdfParameters);
    }
    if target_min_ms > target_max_ms {
        return Err(Error::InvalidKdfParameters);
    }
    let largest = largest_power_of_two_at_most(
        max_memory_kib.clamp(u64::from(MIN_MEMORY_KIB), u64::from(MAX_MEMORY_KIB)),
    );
    let mut memory_kib = largest;
    while memory_kib >= MIN_MEMORY_KIB {
        let mut iterations = MIN_ITERATIONS;
        loop {
            let params = KdfParams::new(memory_kib, iterations, parallelism, salt)?;
            let median = median_derive_ms(password, &params);
            if median > target_max_ms {
                // Over-window at this memory: step memory down, never below
                // the contract minimum.
                break;
            }
            if median >= target_min_ms {
                return KdfParams::new(memory_kib, iterations, parallelism, salt);
            }
            if iterations > u32::MAX / 2 {
                break;
            }
            iterations *= 2;
        }
        if memory_kib == MIN_MEMORY_KIB {
            break;
        }
        memory_kib /= 2;
    }
    Err(Error::KdfResourceLimit)
}

fn largest_power_of_two_at_most(cap: u64) -> u32 {
    let bits = 64 - cap.leading_zeros();
    let exponent = if (1u64 << (bits - 1)) > cap {
        bits - 2
    } else {
        bits - 1
    };
    // cap >= 65536 is guaranteed by clamp in calibrate, so exponent >= 16.
    1u32 << exponent
}

fn median_derive_ms(password: &[u8], params: &KdfParams) -> u64 {
    for _ in 0..CALIBRATION_WARMUP {
        let _ = derive_unlock_key(password, params);
    }
    let mut samples: Vec<u64> = Vec::with_capacity(CALIBRATION_SAMPLES);
    for _ in 0..CALIBRATION_SAMPLES {
        let start = std::time::Instant::now();
        let _ = derive_unlock_key(password, params);
        samples.push(start.elapsed().as_millis() as u64);
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const FIXTURE_CANONICAL: &str = "hex:a701686172676f6e3269640213031a00010000040305010650000102030405060708090a0b0c0d0e0f071820";

    #[test]
    fn positive_parameter_map_encodes_to_fixture_bytes() {
        let params =
            KdfParams::new(65_536, 3, 1, &hex("000102030405060708090a0b0c0d0e0f")).unwrap();
        assert_eq!(
            params.encode_canonical_cbor().unwrap(),
            hex(FIXTURE_CANONICAL.strip_prefix("hex:").unwrap())
        );
    }

    #[test]
    fn decode_accepts_fixture_bytes() {
        let params =
            KdfParams::decode_canonical_cbor(&hex(FIXTURE_CANONICAL.strip_prefix("hex:").unwrap()))
                .unwrap();
        assert_eq!(params.memory_kib(), 65_536);
        assert_eq!(params.iterations(), 3);
        assert_eq!(params.parallelism(), 1);
        assert_eq!(params.salt(), &hex("000102030405060708090a0b0c0d0e0f")[..]);
    }

    #[test]
    fn historical_g11_negative_one_rejects_as_invalid_kdf_parameters() {
        let bytes = hex("a701686172676f6e3269640213031a00010000040305010650000102030405060708090a0b0c0d0e0f0720");
        assert_eq!(
            KdfParams::decode_canonical_cbor(&bytes).unwrap_err(),
            Error::InvalidKdfParameters
        );
    }

    #[test]
    fn non_minimal_version_rejects_as_non_canonical() {
        let bytes = hex("a701686172676f6e326964021813031a00010000040305010650000102030405060708090a0b0c0d0e0f071820");
        assert_eq!(
            KdfParams::decode_canonical_cbor(&bytes).unwrap_err(),
            Error::NonCanonicalCbor
        );
    }

    #[test]
    fn parameter_bound_violations_reject() {
        let salt = [0u8; 16];
        assert_eq!(
            KdfParams::new(32_768, 3, 1, &salt).unwrap_err(),
            Error::InvalidKdfParameters
        );
        assert_eq!(
            KdfParams::new(65_536, 2, 1, &salt).unwrap_err(),
            Error::InvalidKdfParameters
        );
        assert_eq!(
            KdfParams::new(65_536, 3, 0, &salt).unwrap_err(),
            Error::InvalidKdfParameters
        );
        assert_eq!(
            KdfParams::new(65_536, 3, 1, &salt[..4]).unwrap_err(),
            Error::InvalidKdfParameters
        );
    }

    #[test]
    fn memory_cap_enforces_twenty_five_percent() {
        let params = KdfParams::new(65_536, 3, 1, &[0u8; 16]).unwrap();
        params.validate_against_memory_cap(65_536 * 4).unwrap();
        assert_eq!(
            params
                .validate_against_memory_cap(65_536 * 4 - 1)
                .unwrap_err(),
            Error::KdfResourceLimit
        );
    }

    #[test]
    fn derive_is_deterministic_and_salt_sensitive() {
        let p1 = KdfParams::new(65_536, 3, 1, &[1u8; 16]).unwrap();
        let p2 = KdfParams::new(65_536, 3, 1, &[2u8; 16]).unwrap();
        let a = derive_unlock_key(b"correct horse battery staple", &p1).unwrap();
        let a_again = derive_unlock_key(b"correct horse battery staple", &p1).unwrap();
        let b = derive_unlock_key(b"correct horse battery staple", &p2).unwrap();
        let c = derive_unlock_key(b"Correct horse battery staple", &p1).unwrap();
        assert_eq!(a.as_bytes(), a_again.as_bytes());
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn calibrate_returns_in_window_candidate_or_resource_limit() {
        let salt = [0u8; 16];
        // A window that is trivially reachable: minimum bounds land inside.
        let params = calibrate(0, 60_000, 65_536, 1, b"calibration-input", &salt).unwrap();
        assert!(params.memory_kib() >= MIN_MEMORY_KIB);
        assert!(params.iterations() >= MIN_ITERATIONS);
        assert_eq!(params.parallelism(), 1);
        // An unreachable window fails closed with KdfResourceLimit and never
        // violates the minima.
        assert_eq!(
            calibrate(0, 0, 65_536, 1, b"calibration-input", &salt).unwrap_err(),
            Error::KdfResourceLimit
        );
    }
}
