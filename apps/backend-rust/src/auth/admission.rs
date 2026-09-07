//! SEC-07: a coarse, in-process, IP-scoped admission control that runs ahead
//! of the durable per-account rate limiter and ahead of any persistent
//! write, so raw unauthenticated request volume (many distinct synthetic
//! account ids) cannot inflate `accounts`/`auth_rate_limits`. Ported
//! unchanged from the Bun reference's `auth/admission-limit.mjs`. Keyed only
//! by network origin, never by account id (must not become a new
//! account-enumeration oracle).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_MAX: u32 = 20;
const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

struct Bucket {
    count: u32,
    window_end: Instant,
}

pub struct AdmissionLimiter {
    max: u32,
    window: Duration,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl AdmissionLimiter {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX, DEFAULT_WINDOW)
    }

    pub fn with_limits(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true iff `key`'s coarse admission bucket is still within
    /// bound for this window; always records the attempt (even a rejected
    /// one still consumes its bucket slot), so persistent retrying cannot
    /// reset the window early.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("admission lock poisoned");
        buckets.retain(|_, bucket| bucket.window_end > now);
        let bucket = buckets.entry(key.to_owned()).or_insert_with(|| Bucket {
            count: 0,
            window_end: now + self.window,
        });
        bucket.count += 1;
        bucket.count <= self.max
    }
}

impl Default for AdmissionLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max_then_rejects() {
        let limiter = AdmissionLimiter::with_limits(2, Duration::from_secs(60));
        assert!(limiter.allow("1.2.3.4"));
        assert!(limiter.allow("1.2.3.4"));
        assert!(!limiter.allow("1.2.3.4"));
    }

    #[test]
    fn buckets_are_independent_per_key() {
        let limiter = AdmissionLimiter::with_limits(1, Duration::from_secs(60));
        assert!(limiter.allow("a"));
        assert!(limiter.allow("b"));
        assert!(!limiter.allow("a"));
    }
}
