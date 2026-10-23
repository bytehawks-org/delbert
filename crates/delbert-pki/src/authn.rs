//! Proofs of agent identity carried by NATS requests and reports.
//!
//! A proof signs `kind | tenant | agent | timestamp | nonce | SHA-256(JCS(body))`
//! with the agent's identity key. The Core checks it against the public key it
//! certified at enrollment, so another enrolled agent (or anyone who can reach
//! the bus) cannot ask for, or report in the name of, someone else.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{PkiError, sign, verify};

/// Proofs older (or newer) than this are rejected.
pub const MAX_SKEW_SECS: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub ts: i64,
    pub nonce: String,
    pub sig: String,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("proof is outside the accepted time window")]
    Stale,
    #[error("bad signature")]
    Signature,
    #[error("body cannot be canonicalized")]
    Body,
}

fn signing_input(kind: &str, tenant: &str, agent: &str, ts: i64, nonce: &str, body: &Value) -> Result<Vec<u8>, AuthError> {
    let body = delbert_wire::canonical::to_vec(body).map_err(|_| AuthError::Body)?;
    let mut out = format!("delbert-v1\n{kind}\n{tenant}\n{agent}\n{ts}\n{nonce}\n").into_bytes();
    out.extend_from_slice(&Sha256::digest(body));
    Ok(out)
}

/// Create a proof for `body` (use `Value::Null` when there is nothing to send).
pub fn prove(key_pem: &str, kind: &str, tenant: &str, agent: &str, body: &Value, now: i64) -> Result<Proof, PkiError> {
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    let nonce = B64.encode(raw);
    let input = signing_input(kind, tenant, agent, now, &nonce, body).map_err(|e| PkiError::Invalid(e.to_string()))?;
    Ok(Proof { ts: now, nonce, sig: B64.encode(sign(key_pem, &input)?) })
}

/// Verify a proof against the agent's certified raw public key.
pub fn check(public_key: &[u8], kind: &str, tenant: &str, agent: &str, body: &Value, proof: &Proof, now: i64) -> Result<(), AuthError> {
    if (now - proof.ts).abs() > MAX_SKEW_SECS {
        return Err(AuthError::Stale);
    }
    let input = signing_input(kind, tenant, agent, proof.ts, &proof.nonce, body)?;
    let sig = B64.decode(&proof.sig).map_err(|_| AuthError::Signature)?;
    if verify(public_key, &input, &sig) { Ok(()) } else { Err(AuthError::Signature) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ca, new_identity};
    use serde_json::json;

    fn identity() -> (String, Vec<u8>) {
        let ca = Ca::create("CA", 1).unwrap();
        let (key, csr) = new_identity("a").unwrap();
        let signed = ca.sign_csr(&csr, "a1", "urn:x", 1).unwrap();
        (key, signed.public_key)
    }

    #[test]
    fn valid_proofs_pass_and_everything_else_fails() {
        let (key, public) = identity();
        let body = json!({ "compliant": true, "n": [1, 2] });
        let p = prove(&key, "report", "acme", "a1", &body, 1_000).unwrap();
        assert_eq!(check(&public, "report", "acme", "a1", &body, &p, 1_030), Ok(()));
        // Key order in the body does not matter (JCS)...
        assert_eq!(check(&public, "report", "acme", "a1", &json!({ "n": [1, 2], "compliant": true }), &p, 1_000), Ok(()));
        // ...but content, kind, tenant, agent and time do.
        assert_eq!(check(&public, "report", "acme", "a1", &json!({ "compliant": false }), &p, 1_000), Err(AuthError::Signature));
        assert_eq!(check(&public, "req", "acme", "a1", &body, &p, 1_000), Err(AuthError::Signature));
        assert_eq!(check(&public, "report", "other", "a1", &body, &p, 1_000), Err(AuthError::Signature));
        assert_eq!(check(&public, "report", "acme", "a2", &body, &p, 1_000), Err(AuthError::Signature));
        assert_eq!(check(&public, "report", "acme", "a1", &body, &p, 1_000 + MAX_SKEW_SECS + 1), Err(AuthError::Stale));
        // Someone else's key cannot forge it.
        let (_, other_public) = identity();
        assert_eq!(check(&other_public, "report", "acme", "a1", &body, &p, 1_000), Err(AuthError::Signature));
    }
}
