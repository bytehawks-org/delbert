//! Compact JWS (EdDSA / Ed25519) over a JCS payload.
//!
//! `BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)`
//!
//! Verification order matters: algorithm and key are checked, then the
//! signature, and only then is the payload parsed.

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde_json::{Value, json};

use crate::{
    EffectivePolicy, SCHEMA,
    canonical::{self, CanonError},
};

const TYP: &str = "delbert-policy+json";
/// Tolerated clock difference between Core and agent.
const SKEW_SECS: i64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported header (alg must be EdDSA, typ {TYP})")]
    Header,
    #[error("unknown signing key '{0}'")]
    UnknownKey(String),
    #[error("bad signature")]
    Signature,
    #[error("payload is not canonical JCS")]
    NotCanonical,
    #[error("invalid payload: {0}")]
    Payload(String),
    #[error("policy is for tenant '{0}' / agent '{1}', not for this agent")]
    WrongTarget(String, String),
    #[error("policy expired or not yet valid")]
    Time,
    #[error("rollback: version {got} is older than the last applied {last}")]
    Rollback { got: u64, last: u64 },
    #[error("invalid resources: {0}")]
    Resources(String),
}

/// Remove `null`s so the payload only carries what is set.
fn strip_nulls(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.retain(|_, x| !x.is_null());
            m.values_mut().for_each(strip_nulls);
        }
        Value::Array(a) => a.iter_mut().for_each(strip_nulls),
        _ => {}
    }
}

pub struct Signer {
    key: SigningKey,
    kid: String,
}

impl Signer {
    pub fn new(key: SigningKey, kid: impl Into<String>) -> Self {
        Signer { key, kid: kid.into() }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Public key as expected in a trusted-keys file (base64url, no padding).
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.key.verifying_key().to_bytes())
    }

    pub fn sign(&self, policy: &EffectivePolicy) -> Result<String, CanonError> {
        let header = canonical::to_vec(&json!({"alg": "EdDSA", "kid": self.kid, "typ": TYP}))?;
        let mut payload = serde_json::to_value(policy).expect("policy serializes");
        strip_nulls(&mut payload);
        let payload = canonical::to_vec(&payload)?;
        let input = format!("{}.{}", B64.encode(header), B64.encode(payload));
        let sig = self.key.sign(input.as_bytes());
        Ok(format!("{input}.{}", B64.encode(sig.to_bytes())))
    }
}

/// What the agent knows about itself and its history.
pub struct Expect<'a> {
    pub tenant: &'a str,
    pub agent: &'a str,
    /// Current Unix time in seconds.
    pub now: i64,
}

/// Trusted signing keys, anchored on the agent at onboarding.
#[derive(Default)]
pub struct Verifier {
    keys: HashMap<String, VerifyingKey>,
}

impl Verifier {
    pub fn add_key(&mut self, kid: &str, public_b64: &str) -> anyhow::Result<()> {
        let bytes: [u8; 32] = B64
            .decode(public_b64.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
        self.keys.insert(kid.to_owned(), VerifyingKey::from_bytes(&bytes)?);
        Ok(())
    }

    /// Parse lines of `<kid> <base64 public key>`; blank lines and `#` comments are ignored.
    pub fn from_trusted_keys(text: &str) -> anyhow::Result<Self> {
        let mut v = Verifier::default();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let (kid, key) = line.split_once(char::is_whitespace).ok_or_else(|| anyhow::anyhow!("bad key line: '{line}'"))?;
            v.add_key(kid, key)?;
        }
        Ok(v)
    }

    /// `last_version` maps a policy name to the highest version already applied
    /// (the name is only known once the payload is authenticated).
    pub fn verify(
        &self,
        token: &str,
        expect: &Expect,
        last_version: impl Fn(&str) -> Option<u64>,
    ) -> Result<EffectivePolicy, VerifyError> {
        let parts: Vec<&str> = token.trim().split('.').collect();
        let [h, p, s] = parts[..] else { return Err(VerifyError::Malformed) };
        let dec = |x: &str| B64.decode(x).map_err(|_| VerifyError::Malformed);

        let header: Value = serde_json::from_slice(&dec(h)?).map_err(|_| VerifyError::Malformed)?;
        if header["alg"] != "EdDSA" || header["typ"] != TYP {
            return Err(VerifyError::Header);
        }
        let kid = header["kid"].as_str().ok_or(VerifyError::Header)?;
        let key = self.keys.get(kid).ok_or_else(|| VerifyError::UnknownKey(kid.to_owned()))?;
        let sig = Signature::from_slice(&dec(s)?).map_err(|_| VerifyError::Malformed)?;
        key.verify_strict(format!("{h}.{p}").as_bytes(), &sig).map_err(|_| VerifyError::Signature)?;

        // Authentic from here on. Be strict anyway: exactly the canonical form.
        let payload = dec(p)?;
        let value: Value = serde_json::from_slice(&payload).map_err(|e| VerifyError::Payload(e.to_string()))?;
        if canonical::to_vec(&value).map_err(|e| VerifyError::Payload(e.to_string()))? != payload {
            return Err(VerifyError::NotCanonical);
        }
        let policy: EffectivePolicy = serde_json::from_value(value).map_err(|e| VerifyError::Payload(e.to_string()))?;

        if policy.schema != SCHEMA {
            return Err(VerifyError::Payload(format!("unsupported schema '{}'", policy.schema)));
        }
        if policy.tenant != expect.tenant || policy.agent != expect.agent {
            return Err(VerifyError::WrongTarget(policy.tenant, policy.agent));
        }
        if expect.now + SKEW_SECS < policy.issued_at || expect.now >= policy.expires_at {
            return Err(VerifyError::Time);
        }
        // Same version again is fine (periodic pull); older is a rollback.
        if let Some(last) = last_version(&policy.name).filter(|l| policy.version < *l) {
            return Err(VerifyError::Rollback { got: policy.version, last });
        }
        delbert_policy::validate_resources(&policy.resources).map_err(|e| {
            VerifyError::Resources(e.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))
        })?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn policy() -> EffectivePolicy {
        let yaml = "apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: p, tenant: t1 }\nspec:\n  resources:\n    - id: a\n      file: { path: /etc/a, mode: \"0644\" }\n";
        EffectivePolicy {
            schema: SCHEMA.into(),
            tenant: "t1".into(),
            agent: "agent-1".into(),
            name: "p".into(),
            version: 5,
            issued_at: 1_000,
            expires_at: 2_000,
            vars: Default::default(),
            artifacts: Default::default(),
            secrets: Default::default(),
            resources: delbert_policy::from_yaml(yaml).unwrap().spec.resources,
        }
    }

    fn setup() -> (Signer, Verifier) {
        let key = SigningKey::generate(&mut OsRng);
        let mut v = Verifier::default();
        v.add_key("k1", &B64.encode(key.verifying_key().to_bytes())).unwrap();
        (Signer::new(key, "k1"), v)
    }

    fn expect(now: i64) -> Expect<'static> {
        Expect { tenant: "t1", agent: "agent-1", now }
    }

    #[test]
    fn round_trip() {
        let (s, v) = setup();
        let token = s.sign(&policy()).unwrap();
        assert_eq!(v.verify(&token, &expect(1_500), |_| Some(5)).unwrap(), policy());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let (s, v) = setup();
        let token = s.sign(&policy()).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let evil = String::from_utf8(B64.decode(parts[1]).unwrap()).unwrap().replace("/etc/a", "/etc/b");
        let forged = format!("{}.{}.{}", parts[0], B64.encode(evil), parts[2]);
        assert!(matches!(v.verify(&forged, &expect(1_500), |_| None), Err(VerifyError::Signature)));
    }

    #[test]
    fn wrong_key_unknown_kid_and_alg_none_are_rejected() {
        let (s, _) = setup();
        let (_, other) = setup();
        let token = s.sign(&policy()).unwrap();
        assert!(matches!(other.verify(&token, &expect(1_500), |_| None), Err(VerifyError::Signature)));

        let parts: Vec<&str> = token.split('.').collect();
        let none = B64.encode(br#"{"alg":"none","kid":"k1","typ":"delbert-policy+json"}"#);
        let forged = format!("{none}.{}.", parts[1]);
        assert!(matches!(other.verify(&forged, &expect(1_500), |_| None), Err(VerifyError::Header)));

        let unknown = Signer::new(SigningKey::generate(&mut OsRng), "other").sign(&policy()).unwrap();
        assert!(matches!(other.verify(&unknown, &expect(1_500), |_| None), Err(VerifyError::UnknownKey(_))));
    }

    #[test]
    fn expiry_target_and_rollback_are_enforced() {
        let (s, v) = setup();
        let token = s.sign(&policy()).unwrap();
        assert!(matches!(v.verify(&token, &expect(2_000), |_| None), Err(VerifyError::Time)));
        assert!(matches!(v.verify(&token, &expect(100), |_| None), Err(VerifyError::Time)));
        assert!(matches!(v.verify(&token, &expect(1_500), |_| Some(6)), Err(VerifyError::Rollback { got: 5, last: 6 })));
        let other_agent = Expect { agent: "agent-2", ..expect(1_500) };
        assert!(matches!(v.verify(&token, &other_agent, |_| None), Err(VerifyError::WrongTarget(..))));
    }

    #[test]
    fn invalid_resources_are_rejected_even_when_signed() {
        let (s, v) = setup();
        let mut p = policy();
        p.resources.push(p.resources[0].clone()); // duplicate id and path
        let token = s.sign(&p).unwrap();
        assert!(matches!(v.verify(&token, &expect(1_500), |_| None), Err(VerifyError::Resources(_))));
    }

    #[test]
    fn trusted_keys_file_is_parsed() {
        let key = SigningKey::generate(&mut OsRng);
        let line = format!("# comment\n\nk1 {}\n", B64.encode(key.verifying_key().to_bytes()));
        let v = Verifier::from_trusted_keys(&line).unwrap();
        let token = Signer::new(key, "k1").sign(&policy()).unwrap();
        assert!(v.verify(&token, &expect(1_500), |_| None).is_ok());
    }
}
