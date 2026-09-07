//! Short-lived, in-process, bounded-TTL OPAQUE login state (ADR-0006 §6):
//! the frozen `api-v1` contract carries no login-attempt id to key a durable
//! store by, so pending server login state lives only in this process
//! (a known horizontal-scale limitation, ported unchanged from the Bun
//! reference's `auth/login-state.mjs`).
//!
//! Every read path evicts expired entries first, and `take` is a one-shot
//! atomic remove-and-return under a single mutex lock, so no caller can ever
//! observe (let alone reuse) an entry that another caller already consumed
//! or that has expired.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

const DEFAULT_TTL: Duration = Duration::from_secs(60);

pub enum PendingLogin {
    /// Real per-account server login state (opaque, zeroized on drop).
    Real(Zeroizing<Vec<u8>>),
    /// A decoy entry for an unknown-account login attempt (ADR-0006 §9).
    Fake,
}

struct Entry {
    pending: PendingLogin,
    expires_at: Instant,
}

pub struct LoginStateStore {
    ttl: Duration,
    pending: Mutex<HashMap<String, Entry>>,
}

impl LoginStateStore {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn evict_expired(map: &mut HashMap<String, Entry>, now: Instant) {
        map.retain(|_, entry| entry.expires_at > now);
    }

    pub fn set_real(&self, account_id: &str, state_bytes: Zeroizing<Vec<u8>>) {
        let now = Instant::now();
        let mut map = self.pending.lock().expect("login state lock poisoned");
        Self::evict_expired(&mut map, now);
        map.insert(
            account_id.to_owned(),
            Entry {
                pending: PendingLogin::Real(state_bytes),
                expires_at: now + self.ttl,
            },
        );
    }

    pub fn set_fake(&self, account_id: &str) {
        let now = Instant::now();
        let mut map = self.pending.lock().expect("login state lock poisoned");
        Self::evict_expired(&mut map, now);
        map.insert(
            account_id.to_owned(),
            Entry {
                pending: PendingLogin::Fake,
                expires_at: now + self.ttl,
            },
        );
    }

    pub fn has_pending(&self, account_id: &str) -> bool {
        let now = Instant::now();
        let mut map = self.pending.lock().expect("login state lock poisoned");
        Self::evict_expired(&mut map, now);
        map.contains_key(account_id)
    }

    /// One-shot: an entry is consumed (removed) the first time it's read.
    pub fn take(&self, account_id: &str) -> Option<PendingLogin> {
        let now = Instant::now();
        let mut map = self.pending.lock().expect("login state lock poisoned");
        Self::evict_expired(&mut map, now);
        map.remove(account_id).map(|entry| entry.pending)
    }
}

impl Default for LoginStateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_is_one_shot() {
        let store = LoginStateStore::new();
        store.set_fake("acct");
        assert!(store.has_pending("acct"));
        assert!(matches!(store.take("acct"), Some(PendingLogin::Fake)));
        assert!(store.take("acct").is_none());
        assert!(!store.has_pending("acct"));
    }

    #[test]
    fn expires_after_ttl() {
        let store = LoginStateStore::with_ttl(Duration::from_millis(1));
        store.set_fake("acct");
        std::thread::sleep(Duration::from_millis(20));
        assert!(!store.has_pending("acct"));
        assert!(store.take("acct").is_none());
    }
}
