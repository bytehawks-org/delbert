//! The Operator's identity: an agent enrolled in one tenant (docs/ABSTRACT.md §3).
//!
//! It is created once, from an enrollment key, and kept in a Kubernetes `Secret` of the
//! Operator's namespace, so a rescheduled pod finds it again. Losing the `Secret` means enrolling
//! again with a new key; nothing else is lost.
//!
//! | Key | Content |
//! |-----|---------|
//! | `key.pem` | Ed25519 identity key: signs the proofs sent to the Core |
//! | `enc.key` | age secret key: opens the sensitive values of a bundle |
//! | `hash.key` | random key of the content hash (see [`crate::render`]) |
//! | `tenant`, `agent` | where the Core knows this identity |
//!
//! One identity belongs to one tenant, so one Operator serves the bindings of that tenant only.

use std::{collections::BTreeMap, str::FromStr};

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, bail};
use k8s_openapi::{ByteString, api::core::v1::Secret};
use kube::{
    Api,
    api::{ObjectMeta, PostParams},
};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;

#[derive(Clone)]
pub struct Identity {
    pub tenant: String,
    pub agent: String,
    pub key_pem: String,
    pub age: std::sync::Arc<age::x25519::Identity>,
    pub hash_key: Vec<u8>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("tenant", &self.tenant)
            .field("agent", &self.agent)
            .finish_non_exhaustive()
    }
}

fn raw(data: &BTreeMap<String, ByteString>, key: &str) -> Result<String> {
    let value = data
        .get(key)
        .with_context(|| format!("identity secret has no '{key}'"))?;
    String::from_utf8(value.0.clone()).with_context(|| format!("'{key}' is not text"))
}

/// A single-line value: a trailing newline (e.g. from `kubectl create secret --from-file`) is not part of it.
fn text(data: &BTreeMap<String, ByteString>, key: &str) -> Result<String> {
    Ok(raw(data, key)?.trim().to_owned())
}

impl Identity {
    /// Read an identity from the data of its `Secret`.
    pub fn from_data(data: &BTreeMap<String, ByteString>) -> Result<Self> {
        let age = age::x25519::Identity::from_str(&text(data, "enc.key")?)
            .map_err(|e| anyhow::anyhow!("invalid enc.key: {e}"))?;
        let hash_key = data
            .get("hash.key")
            .map(|v| v.0.clone())
            .filter(|k| k.len() >= 16)
            .context("identity secret has no usable 'hash.key'")?;
        Ok(Identity {
            tenant: text(data, "tenant")?,
            agent: text(data, "agent")?,
            key_pem: raw(data, "key.pem")?,
            age: age.into(),
            hash_key,
        })
    }

    /// The `Secret` data of this identity.
    pub fn to_data(&self) -> BTreeMap<String, ByteString> {
        let bytes = |s: &str| ByteString(s.as_bytes().to_vec());
        BTreeMap::from([
            ("key.pem".to_owned(), bytes(&self.key_pem)),
            (
                "enc.key".to_owned(),
                bytes(self.age.to_string().expose_secret()),
            ),
            ("hash.key".to_owned(), ByteString(self.hash_key.clone())),
            ("tenant".to_owned(), bytes(&self.tenant)),
            ("agent".to_owned(), bytes(&self.agent)),
        ])
    }
}

#[derive(Deserialize)]
struct EnrollResponse {
    tenant: String,
    agent: String,
}

/// Enroll with the Core: keys are generated here, only the public parts are sent.
pub async fn enroll(
    http: &reqwest::Client,
    core_url: &str,
    psk: &str,
    name: &str,
) -> Result<Identity> {
    let (key_pem, csr_pem) = delbert_pki::new_identity(name)?;
    let age = age::x25519::Identity::generate();
    let resp = http
        .post(format!("{}/v1/enroll", core_url.trim_end_matches('/')))
        .json(&json!({ "psk": psk, "agent_name": name, "csr_pem": csr_pem, "enc_public_key": age.to_public().to_string() }))
        .send()
        .await
        .context("cannot reach the Core (check the URL and that the CA matches its certificate)")?;
    if !resp.status().is_success() {
        let status = resp.status();
        bail!(
            "enrollment refused ({status}): {}",
            resp.text().await.unwrap_or_default()
        );
    }
    let resp: EnrollResponse = resp
        .json()
        .await
        .context("unexpected enrollment response")?;
    let mut hash_key = vec![0u8; 32];
    OsRng.fill_bytes(&mut hash_key);
    Ok(Identity {
        tenant: resp.tenant,
        agent: resp.agent,
        key_pem,
        age: age.into(),
        hash_key,
    })
}

/// The stored identity, or a new one enrolled with `psk` and stored. Without a stored identity
/// and without a key there is nothing to do: that is an error, not a retry loop.
pub async fn load_or_enroll(
    secrets: &Api<Secret>,
    secret_name: &str,
    http: &reqwest::Client,
    core_url: &str,
    psk: Option<&str>,
    name: &str,
) -> Result<Identity> {
    if let Some(secret) = secrets
        .get_opt(secret_name)
        .await
        .context("reading the identity secret")?
    {
        return Identity::from_data(&secret.data.unwrap_or_default())
            .context("the identity secret is incomplete (delete it and enroll again)");
    }
    let psk = psk.context(
        "no identity secret and no enrollment key: set DELBERT_ENROLL_PSK for the first start",
    )?;
    let identity = enroll(http, core_url, psk, name).await?;
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_owned()),
            ..ObjectMeta::default()
        },
        data: Some(identity.to_data()),
        type_: Some("Opaque".to_owned()),
        ..Secret::default()
    };
    // `create` fails if another replica stored an identity in the meantime: better than overwriting it.
    secrets
        .create(&PostParams::default(), &secret)
        .await
        .context("storing the identity secret (the enrollment key is now used: do not reuse it)")?;
    tracing::info!(tenant = %identity.tenant, agent = %identity.agent, "enrolled and stored the identity");
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Identity {
        let (key_pem, _) = delbert_pki::new_identity("op").unwrap();
        Identity {
            tenant: "acme".into(),
            agent: "op-1".into(),
            key_pem,
            age: age::x25519::Identity::generate().into(),
            hash_key: vec![7; 32],
        }
    }

    #[test]
    fn identity_survives_a_round_trip_through_the_secret() {
        let id = sample();
        let back = Identity::from_data(&id.to_data()).unwrap();
        assert_eq!(
            (&back.tenant, &back.agent, &back.key_pem, &back.hash_key),
            (&id.tenant, &id.agent, &id.key_pem, &id.hash_key)
        );
        assert_eq!(
            back.age.to_public().to_string(),
            id.age.to_public().to_string()
        );
    }

    #[test]
    fn an_incomplete_or_weak_secret_is_refused() {
        let mut data = sample().to_data();
        data.remove("enc.key");
        assert!(Identity::from_data(&data).is_err());
        let mut data = sample().to_data();
        data.insert("hash.key".into(), ByteString(vec![1; 4]));
        assert!(Identity::from_data(&data).is_err());
    }

    #[test]
    fn debug_output_has_no_key_material() {
        let shown = format!("{:?}", sample());
        assert!(!shown.contains("PRIVATE") && !shown.contains("AGE-SECRET-KEY"));
    }
}
