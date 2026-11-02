//! Audit anchors: the signed head of the audit hash chain (docs/API.md "Audit anchors").
//!
//! The Core creates and signs them ([`document`] is what it signs); this module also lets
//! anyone check a copy of them **without the database**: [`check`] verifies the signatures
//! of an NDJSON file of anchors and, given an export of the audit trail, that every anchor
//! still matches the event at its position. That is what makes an external copy of the
//! anchors useful against someone who controls the database.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::json;

use crate::{Verifier, canonical};

/// Domain separation of anchor signatures from every other use of the signing key.
pub const DOMAIN: &str = "delbert-audit-anchor-v1";

/// The exact bytes an anchor signs: JCS of its fields (`hash_hex` lowercase hex, `at_micros` as stored).
pub fn document(seq: i64, hash_hex: &str, events: i64, at_micros: i64, kid: &str) -> Result<Vec<u8>, canonical::CanonError> {
    canonical::to_vec(&json!({ "v": 1, "seq": seq, "hash": hash_hex, "events": events, "at": at_micros, "kid": kid }))
}

/// One anchor as exported (a line of the anchors file, or an element of `GET /v1/audit/anchors`).
#[derive(Debug, Deserialize)]
pub struct Anchor {
    pub id: i64,
    pub at_micros: i64,
    pub seq: i64,
    pub hash: String,
    pub events: i64,
    pub kid: String,
    pub signature: String,
}

/// Check anchors (NDJSON, one object per line; blank lines ignored) and optionally the audit
/// export (NDJSON of `GET /v1/audit/export`). Returns the number of anchors checked and the
/// problems found; no problems means every anchor is validly signed, they never go backwards,
/// and (with an export) each one matches the hash of the event at its sequence number.
pub fn check(keys: &Verifier, anchors_ndjson: &str, export_ndjson: Option<&str>) -> (usize, Vec<String>) {
    let mut problems = Vec::new();
    let hashes: Option<HashMap<i64, String>> = export_ndjson.map(|text| {
        text.lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|e| Some((e["seq"].as_i64()?, e["hash"].as_str()?.to_owned())))
            .collect()
    });
    let (mut checked, mut last): (usize, Option<(i64, i64)>) = (0, None);
    for (n, line) in anchors_ndjson.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let line_no = n + 1;
        let Ok(a) = serde_json::from_str::<Anchor>(line) else {
            problems.push(format!("line {line_no}: not an anchor"));
            continue;
        };
        checked += 1;
        let signed = document(a.seq, &a.hash, a.events, a.at_micros, &a.kid).is_ok_and(|doc| keys.verify_detached(&a.kid, DOMAIN, &doc, &a.signature));
        if !signed {
            problems.push(format!("anchor {} (line {line_no}): bad signature or unknown key '{}'", a.id, a.kid));
        }
        if last.is_some_and(|(seq, events)| a.seq < seq || a.events < events) {
            problems.push(format!("anchor {} (line {line_no}): goes back in the chain", a.id));
        }
        last = Some((a.seq, a.events));
        if let Some(hashes) = &hashes {
            match hashes.get(&a.seq) {
                Some(h) if *h == a.hash => {}
                Some(_) => problems.push(format!("anchor {}: the audit export has a different event at seq {}", a.id, a.seq)),
                None => problems.push(format!("anchor {}: the audit export has no event at seq {} (truncated?)", a.id, a.seq)),
            }
        }
    }
    (checked, problems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signer;
    use ed25519_dalek::SigningKey;

    fn line(s: &Signer, id: i64, seq: i64, hash: &str, events: i64) -> String {
        let at = 1_000_000 + id;
        let sig = s.sign_detached(DOMAIN, &document(seq, hash, events, at, s.kid()).unwrap());
        json!({ "id": id, "at_micros": at, "seq": seq, "hash": hash, "events": events, "kid": s.kid(), "signature": sig }).to_string()
    }

    fn keys(s: &Signer) -> Verifier {
        let mut v = Verifier::default();
        v.add_key(s.kid(), &s.public_key_b64()).unwrap();
        v
    }

    #[test]
    fn signatures_order_and_export_are_checked_offline() {
        let s = Signer::new(SigningKey::from_bytes(&[1; 32]), "k1");
        let anchors = [line(&s, 1, 2, "aa", 2), line(&s, 2, 5, "bb", 5)].join("\n");
        let export = "{\"seq\":2,\"hash\":\"aa\"}\n{\"seq\":5,\"hash\":\"bb\"}\n";
        assert_eq!(check(&keys(&s), &anchors, Some(export)), (2, vec![]));
        assert_eq!(check(&keys(&s), &anchors, None), (2, vec![]));

        // Truncated export, different event, wrong key, reordered anchors, forged field.
        assert_eq!(check(&keys(&s), &anchors, Some("{\"seq\":2,\"hash\":\"aa\"}\n")).1.len(), 1);
        assert_eq!(check(&keys(&s), &anchors, Some("{\"seq\":2,\"hash\":\"aa\"}\n{\"seq\":5,\"hash\":\"xx\"}\n")).1.len(), 1);
        let other = Signer::new(SigningKey::from_bytes(&[2; 32]), "k1");
        assert_eq!(check(&keys(&other), &anchors, None).1.len(), 2);
        let reordered = [line(&s, 2, 5, "bb", 5), line(&s, 1, 2, "aa", 2)].join("\n");
        assert_eq!(check(&keys(&s), &reordered, None).1.len(), 1);
        assert_eq!(check(&keys(&s), &anchors.replace("\"seq\":5", "\"seq\":4"), None).1.len(), 1);
        assert_eq!(check(&keys(&s), "garbage\n", None), (0, vec!["line 1: not an anchor".to_string()]));
    }
}
