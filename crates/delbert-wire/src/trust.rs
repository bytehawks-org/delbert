//! Rotation of the policy signing key (docs/ROTATION.md).
//!
//! Agents anchor trust in a list of public keys received at enrollment. To rotate without
//! touching every agent by hand, a policy signed by an already trusted key may carry a
//! [`TrustUpdate`]: keys to learn and key ids to forget. Because it travels inside the signed
//! payload it is exactly as authentic as the policy, and nothing else can change the list.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};

/// A public signing key and its id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub kid: String,
    /// Base64url (no padding) Ed25519 public key.
    pub public_key: String,
}

/// Changes to the agent's trusted keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustUpdate {
    #[serde(default)]
    pub add: Vec<TrustedKey>,
    #[serde(default)]
    pub remove: Vec<String>,
}

fn kid_ok(kid: &str) -> bool {
    (1..=64).contains(&kid.len()) && kid.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// Apply `update` to the text of a trusted-keys file (`<kid> <public key>` per line, `#` comments).
///
/// Rules, all of which fail closed: a key id already trusted with a *different* key is an error
/// (keys are never replaced silently); the key that signed the policy carrying the update is
/// never removed by it; the last key is never removed; malformed keys are errors. Returns the
/// new text when something changed, `None` otherwise.
pub fn apply(text: &str, update: &TrustUpdate, signed_by: &str) -> Result<Option<String>, String> {
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let entry = |l: &str| -> Option<(String, String)> {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            return None;
        }
        l.split_once(char::is_whitespace).map(|(k, v)| (k.to_owned(), v.trim().to_owned()))
    };
    let mut changed = false;
    for key in &update.add {
        if !kid_ok(&key.kid) {
            return Err(format!("invalid key id '{}'", key.kid));
        }
        let bytes = B64.decode(key.public_key.trim()).map_err(|_| format!("key '{}' is not base64url", key.kid))?;
        if bytes.len() != 32 {
            return Err(format!("key '{}' must be 32 bytes", key.kid));
        }
        match lines.iter().filter_map(|l| entry(l)).find(|(k, _)| *k == key.kid) {
            Some((_, existing)) if existing == key.public_key.trim() => {}
            Some(_) => return Err(format!("key id '{}' is already trusted with a different key", key.kid)),
            None => {
                lines.push(format!("{} {}", key.kid, key.public_key.trim()));
                changed = true;
            }
        }
    }
    for kid in &update.remove {
        if kid == signed_by {
            continue; // a key cannot retire itself in the very policy it signs
        }
        let before = lines.len();
        lines.retain(|l| entry(l).is_none_or(|(k, _)| k != *kid));
        changed |= lines.len() != before;
    }
    if lines.iter().filter_map(|l| entry(l)).count() == 0 {
        return Err("an update would leave no trusted key".into());
    }
    Ok(changed.then(|| lines.join("\n") + "\n"))
}

/// Key ids listed in a trusted-keys file.
pub fn kids(text: &str) -> Vec<String> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).filter_map(|l| l.split_whitespace().next().map(str::to_owned)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kid: &str, byte: u8) -> TrustedKey {
        TrustedKey { kid: kid.into(), public_key: B64.encode([byte; 32]) }
    }

    fn file(keys: &[TrustedKey]) -> String {
        keys.iter().map(|k| format!("{} {}\n", k.kid, k.public_key)).collect()
    }

    #[test]
    fn add_remove_and_idempotence() {
        let text = format!("# keys\n{}", file(&[key("k1", 1)]));
        let upd = TrustUpdate { add: vec![key("k2", 2)], remove: vec![] };
        let next = apply(&text, &upd, "k1").unwrap().unwrap();
        assert_eq!(kids(&next), ["k1", "k2"]);
        assert!(next.starts_with("# keys"));
        assert_eq!(apply(&next, &upd, "k1").unwrap(), None, "applying twice changes nothing");
        // k2 signs and retires k1.
        let next = apply(&next, &TrustUpdate { add: vec![], remove: vec!["k1".into()] }, "k2").unwrap().unwrap();
        assert_eq!(kids(&next), ["k2"]);
    }

    #[test]
    fn unsafe_updates_are_refused() {
        let text = file(&[key("k1", 1), key("k2", 2)]);
        // A known id with another key, a malformed key, a bad id.
        assert!(apply(&text, &TrustUpdate { add: vec![key("k1", 9)], remove: vec![] }, "k1").unwrap_err().contains("different key"));
        assert!(apply(&text, &TrustUpdate { add: vec![TrustedKey { kid: "k3".into(), public_key: "AAAA".into() }], remove: vec![] }, "k1").is_err());
        assert!(apply(&text, &TrustUpdate { add: vec![key("k 3", 3)], remove: vec![] }, "k1").is_err());
        // The signer is never removed by its own policy, and the last key is never removed.
        assert_eq!(apply(&text, &TrustUpdate { add: vec![], remove: vec!["k1".into()] }, "k1").unwrap(), None);
        assert!(apply(&file(&[key("k1", 1)]), &TrustUpdate { add: vec![], remove: vec!["k1".into()] }, "k2").unwrap_err().contains("no trusted key"));
    }
}
