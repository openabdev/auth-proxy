//! Per-page CSRF tokens (design 3.6): random, bound to one entry id, single use.
//!
//! A browser sends Basic credentials on every request to the origin, so a hostile page could
//! post to the approval listener. The token proves the POST came from a page the approver was
//! shown for that entry. The store is bounded: 4 tokens per entry, 256 in all, and the oldest
//! goes first. A token also dies with its entry or after `ttl`.

use std::fmt;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::time::Instant;

use crate::hold::digest::random_hex;

pub const MAX_PER_ENTRY: usize = 4;
pub const MAX_TOTAL: usize = 256;

struct Token {
    value: String,
    entry: String,
    expires: Instant,
}

#[derive(Default)]
pub struct Csrf {
    tokens: Mutex<Vec<Token>>,
}

impl fmt::Debug for Csrf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Csrf")
            .field("tokens", &self.len())
            .finish_non_exhaustive()
    }
}

impl Csrf {
    pub fn new() -> Csrf {
        Csrf::default()
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Token>> {
        match self.tokens.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A fresh token for `entry`. `live` says whether an entry id is still `Pending`; tokens of
    /// entries that are not are dropped here.
    pub fn issue(&self, entry: &str, ttl: Duration, live: impl Fn(&str) -> bool) -> String {
        let now = Instant::now();
        let mut g = self.lock();
        g.retain(|t| t.expires > now && live(&t.entry));
        let own = g.iter().filter(|t| t.entry == entry).count();
        if own >= MAX_PER_ENTRY {
            if let Some(i) = g.iter().position(|t| t.entry == entry) {
                g.remove(i);
            }
        }
        if g.len() >= MAX_TOTAL {
            g.remove(0);
        }
        let value = random_hex(16);
        g.push(Token {
            value: value.clone(),
            entry: entry.to_string(),
            expires: now + ttl,
        });
        value
    }

    /// Use `presented` for `entry`. The token is spent whenever it exists, whether or not it was
    /// issued for this entry, so a token cannot be retried against another entry. Returns `true`
    /// only for a live token issued for exactly `entry`.
    pub fn consume(&self, presented: &str, entry: &str) -> bool {
        let now = Instant::now();
        let mut g = self.lock();
        // Compare against every token, so the time does not depend on which one matched.
        let mut found = None;
        for (i, t) in g.iter().enumerate() {
            if bool::from(t.value.as_bytes().ct_eq(presented.as_bytes())) {
                found = Some(i);
            }
        }
        let Some(i) = found else {
            return false;
        };
        let t = g.remove(i);
        t.entry == entry && t.expires > now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(60);

    #[tokio::test]
    async fn a_token_works_once_for_its_entry() {
        let c = Csrf::new();
        let t = c.issue("e1", TTL, |_| true);
        assert!(c.consume(&t, "e1"));
        assert!(!c.consume(&t, "e1"), "single use");
    }

    #[tokio::test]
    async fn a_token_for_another_entry_is_refused_and_spent() {
        let c = Csrf::new();
        let t = c.issue("e1", TTL, |_| true);
        assert!(!c.consume(&t, "e2"));
        assert!(!c.consume(&t, "e1"), "the wrong-entry attempt spent it");
        assert!(!c.consume("", "e1"));
        assert!(!c.consume("nope", "e1"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_token_expires() {
        let c = Csrf::new();
        let t = c.issue("e1", TTL, |_| true);
        tokio::time::advance(TTL + Duration::from_secs(1)).await;
        assert!(!c.consume(&t, "e1"));
    }

    #[tokio::test]
    async fn tokens_of_a_dead_entry_are_dropped_on_the_next_issue() {
        let c = Csrf::new();
        let t = c.issue("gone", TTL, |_| true);
        let _ = c.issue("e2", TTL, |id| id != "gone");
        assert_eq!(c.len(), 1);
        assert!(!c.consume(&t, "gone"));
    }

    #[tokio::test]
    async fn the_store_is_bounded_per_entry_and_in_total() {
        let c = Csrf::new();
        let first = c.issue("e1", TTL, |_| true);
        for _ in 0..MAX_PER_ENTRY {
            c.issue("e1", TTL, |_| true);
        }
        assert_eq!(c.len(), MAX_PER_ENTRY);
        assert!(!c.consume(&first, "e1"), "the oldest was evicted");
        for i in 0..(MAX_TOTAL + 10) {
            c.issue(&format!("n{i}"), TTL, |_| true);
        }
        assert_eq!(c.len(), MAX_TOTAL);
    }

    #[tokio::test]
    async fn tokens_are_random_and_debug_shows_none() {
        let c = Csrf::new();
        let a = c.issue("e1", TTL, |_| true);
        let b = c.issue("e1", TTL, |_| true);
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        let text = format!("{c:?}");
        assert!(!text.contains(&a) && !text.contains(&b));
    }
}
