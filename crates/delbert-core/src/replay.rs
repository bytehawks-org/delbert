//! Replay protection for signed agent requests (docs/SECURITY-REVIEW.md F-05).
//!
//! A proof (`delbert-pki::authn`) is valid for ±`MAX_SKEW_SECS`. Without memory, a captured proof
//! could be presented again inside that window. This remembers the nonces of proofs that were
//! accepted, for a little longer than the window, and refuses a second use.
//!
//! The memory is per Core process (a second replica does not see the first one's nonces) and is
//! bounded; when it is full of still-fresh entries a new nonce is accepted rather than refused,
//! so a flood cannot lock agents out. It is applied only to the requests an agent builds afresh at
//! every attempt (policy pull, renewal, artifact download, delivery bundle). Reports and event
//! batches are not covered: they are idempotent (ordered by their own timestamp, events carry ids)
//! and a proxy legitimately forwards the same proof again when a delivery is retried.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use delbert_pki::authn::MAX_SKEW_SECS;

/// How long a nonce is remembered: the full window before and after, plus slack.
const KEEP_SECS: i64 = 2 * MAX_SKEW_SECS + 10;
const MAX_ENTRIES: usize = 200_000;

fn seen() -> &'static Mutex<HashMap<String, i64>> {
    static SEEN: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    SEEN.get_or_init(Default::default)
}

/// Record the use of `nonce` by `who` at `now`; `false` if it was already used inside the window.
pub fn first_use(who: &str, nonce: &str, now: i64) -> bool {
    let mut seen = seen().lock().unwrap_or_else(|e| e.into_inner());
    if seen.len() >= MAX_ENTRIES / 2 {
        seen.retain(|_, at| now - *at < KEEP_SECS);
    }
    if seen.len() >= MAX_ENTRIES {
        tracing::warn!("replay cache full of fresh entries: accepting an unrecorded nonce");
        return true;
    }
    let key = format!("{who}\n{nonce}");
    match seen.get(&key) {
        Some(at) if now - *at < KEEP_SECS => false,
        _ => {
            seen.insert(key, now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_is_accepted_once_per_window_and_per_agent() {
        assert!(first_use("acme/a1", "n1", 1_000));
        assert!(!first_use("acme/a1", "n1", 1_001), "replay");
        assert!(!first_use("acme/a1", "n1", 1_000 + MAX_SKEW_SECS), "still inside the window");
        assert!(first_use("acme/a2", "n1", 1_001), "another agent's identical nonce is another proof");
        assert!(first_use("acme/a1", "n2", 1_001));
        // Long after the window the proof is stale anyway (authn rejects it), so the entry may be reused.
        assert!(first_use("acme/a1", "n1", 1_000 + KEEP_SECS + 1));
    }
}
