//! Talking to the Core: fetching a delivery bundle, reporting audit events.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{identity::Identity, render::Bundle};

/// The Core's bundle as it travels (mirrors `delbert_core::deliveries::DeliveryBundle`).
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct WireBundle {
    pub version: i64,
    pub variables: BTreeMap<String, String>,
    pub files: BTreeMap<String, String>,
    /// Secret name → base64 of the age ciphertext for this Operator.
    pub sensitive: BTreeMap<String, String>,
}

impl WireBundle {
    /// Open the sensitive values with the Operator's age key. A value that does not open or is
    /// not text fails the whole bundle: no half configuration.
    pub fn open(self, age: &age::x25519::Identity) -> Result<Bundle> {
        let mut sensitive = BTreeMap::new();
        for (name, sealed) in self.sensitive {
            let cipher = B64
                .decode(sealed)
                .with_context(|| format!("sensitive value '{name}' is not base64"))?;
            let plain = age::decrypt(age, &cipher).map_err(|_| {
                anyhow::anyhow!(
                    "sensitive value '{name}' cannot be opened with this Operator's key"
                )
            })?;
            sensitive.insert(
                name.clone(),
                String::from_utf8(plain)
                    .with_context(|| format!("sensitive value '{name}' is not text"))?,
            );
        }
        Ok(Bundle {
            version: self.version,
            variables: self.variables,
            files: self.files,
            sensitive,
        })
    }
}

/// Talks to the Core as the enrolled identity.
pub struct CoreClient {
    http: reqwest::Client,
    base: String,
}

impl CoreClient {
    pub fn new(http: reqwest::Client, base: &str) -> Self {
        CoreClient {
            http,
            base: base.trim_end_matches('/').to_owned(),
        }
    }

    /// `GET /v1/agent/{tenant}/{agent}/deliveries/{name}` with a proof over the delivery name.
    pub async fn fetch(&self, id: &Identity, delivery: &str, now: i64) -> Result<WireBundle> {
        let proof = delbert_pki::authn::prove(
            &id.key_pem,
            "delivery",
            &id.tenant,
            &id.agent,
            &Value::String(delivery.to_owned()),
            now,
        )?;
        let header = format!("Delbert-Agent {}", B64.encode(serde_json::to_vec(&proof)?));
        let url = format!(
            "{}/v1/agent/{}/{}/deliveries/{}",
            self.base, id.tenant, id.agent, delivery
        );
        let resp = self
            .http
            .get(url)
            .header("authorization", header)
            .send()
            .await
            .context("cannot reach the Core")?;
        if !resp.status().is_success() {
            let status = resp.status();
            bail!(
                "the Core refused delivery '{delivery}' ({status}): {}",
                resp.text().await.unwrap_or_default()
            );
        }
        resp.json().await.context("unexpected bundle format")
    }
}

impl CoreClient {
    /// `POST /v1/agent/{tenant}/{agent}/events`: one audit event, proven over the `events` array
    /// (proof kind `event`, like the agents' bus batches). The id is random: a retry after a lost
    /// reply may be stored twice, never dropped.
    pub async fn report(
        &self,
        id: &Identity,
        kind: &str,
        resource: &str,
        version: Option<i64>,
        detail: &str,
        now: i64,
    ) -> Result<()> {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let events = json!([{
            "id": raw.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "kind": kind,
            "at": now,
            "resource": resource,
            "version": version,
            "detail": detail,
        }]);
        let proof =
            delbert_pki::authn::prove(&id.key_pem, "event", &id.tenant, &id.agent, &events, now)?;
        let url = format!("{}/v1/agent/{}/{}/events", self.base, id.tenant, id.agent);
        let resp = self
            .http
            .post(url)
            .json(&json!({ "proof": proof, "events": events }))
            .send()
            .await
            .context("cannot reach the Core")?;
        if !resp.status().is_success() {
            bail!("the Core refused the audit event ({})", resp.status());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(sensitive: BTreeMap<String, String>) -> WireBundle {
        WireBundle {
            version: 5,
            variables: BTreeMap::from([("A".into(), "1".into())]),
            files: BTreeMap::new(),
            sensitive,
        }
    }

    #[test]
    fn sensitive_values_are_opened_with_the_operators_key() {
        let me = age::x25519::Identity::generate();
        let sealed = B64.encode(age::encrypt(&me.to_public(), b"hunter2").unwrap());
        let bundle = wire(BTreeMap::from([("db".into(), sealed)]))
            .open(&me)
            .unwrap();
        assert_eq!(
            (
                bundle.sensitive["db"].as_str(),
                bundle.version,
                bundle.variables["A"].as_str()
            ),
            ("hunter2", 5, "1")
        );
    }

    #[test]
    fn a_value_for_someone_else_fails_the_whole_bundle() {
        let (me, other) = (
            age::x25519::Identity::generate(),
            age::x25519::Identity::generate(),
        );
        let sealed = B64.encode(age::encrypt(&other.to_public(), b"x").unwrap());
        let err = wire(BTreeMap::from([("db".into(), sealed)]))
            .open(&me)
            .unwrap_err()
            .to_string();
        assert!(err.contains("'db'") && !err.contains("AGE-SECRET"), "{err}");
        assert!(
            wire(BTreeMap::from([("db".into(), "%%%".into())]))
                .open(&me)
                .is_err()
        );
    }
}
