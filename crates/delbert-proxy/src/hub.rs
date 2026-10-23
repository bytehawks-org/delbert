//! The proxy's connection to the Core's NATS (the only link out of the site).

use std::time::Duration;

use anyhow::{Context, Result};
use async_nats::{Client, Subscriber};
use delbert_pki::authn::{self, Proof};
use serde_json::{Value, json};

use crate::identity::Identity;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Makes the proxy's proofs (kind, `proxy`, site, body), the same way agents make theirs.
#[derive(Clone)]
pub struct ProofMaker {
    key_pem: String,
    site: String,
}

impl ProofMaker {
    pub fn new(identity: &Identity) -> Result<Self> {
        Ok(ProofMaker { key_pem: identity.key_pem()?, site: identity.meta.site.clone() })
    }

    pub fn prove(&self, kind: &str, body: &Value) -> Result<Proof> {
        Ok(authn::prove(&self.key_pem, kind, "proxy", &self.site, body, now())?)
    }

    /// Value of an `Authorization: Delbert-Proxy ...` header.
    pub fn header(&self, kind: &str, body: &Value) -> Result<String> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        Ok(format!("Delbert-Proxy {}", STANDARD.encode(serde_json::to_vec(&json!({ "site": self.site, "proof": self.prove(kind, body)? }))?)))
    }
}

#[derive(Clone)]
pub struct Hub {
    client: Client,
    proofs: ProofMaker,
    site: String,
}

impl Hub {
    /// Connect with the proxy's certificate; the Core's callout confines the connection to the proxy's subjects.
    /// Starts even when the Core is unreachable and keeps retrying.
    pub async fn connect(identity: &Identity, url: &str) -> Result<Self> {
        let site = identity.meta.site.clone();
        let client = async_nats::ConnectOptions::new()
            .require_tls(true)
            .add_root_certificates(identity.path("ca.pem"))
            .add_client_certificate(identity.path("cert.pem"), identity.path("key.pem"))
            .custom_inbox_prefix(format!("_INBOX.proxy.{site}"))
            // Notice a dead link within about 30 s (the default is minutes): the proxy's job is to ride out outages.
            .ping_interval(Duration::from_secs(10))
            .retry_on_initial_connect()
            .connect(url)
            .await
            .context("connecting to the Core's NATS")?;
        Ok(Hub { client, proofs: ProofMaker::new(identity)?, site })
    }

    /// Notifications for agents and "refresh your list" hints for this proxy.
    pub async fn subscribe_notifications(&self) -> Result<(Subscriber, Subscriber)> {
        Ok((self.client.subscribe("delbert.notify.*.*").await?, self.client.subscribe(format!("delbert.proxy.{}.notify", self.site)).await?))
    }

    async fn request(&self, what: &str, payload: Value) -> Result<Value> {
        let reply = tokio::time::timeout(REQUEST_TIMEOUT, self.client.request(format!("delbert.proxy.{}.{what}", self.site), payload.to_string().into()))
            .await
            .context("timeout waiting for the Core")?
            .context("request to the Core failed")?;
        let body: Value = serde_json::from_slice(&reply.payload).context("malformed reply")?;
        if let Some(e) = body["error"].as_str() {
            anyhow::bail!("the Core refused: {e}");
        }
        Ok(body)
    }

    /// Relay an agent request (`kind` is `effective` or `renew`); `payload` is exactly what the agent sent.
    pub async fn relay(&self, kind: &str, tenant: &str, agent: &str, payload: Value) -> Result<Value> {
        let inner = json!({ "kind": kind, "tenant": tenant, "agent": agent, "payload": payload });
        self.request("relay", json!({ "proof": self.proofs.prove("relay", &inner)?, "inner": inner })).await
    }

    /// The agents this proxy serves, with their keys.
    pub async fn agents(&self) -> Result<Value> {
        self.request("agents", json!({ "proof": self.proofs.prove("agents", &Value::Null)? })).await
    }

    /// Forward queued reports; returns how many the Core stored. The caller keeps the queue until this succeeds.
    pub async fn forward_reports(&self, reports: Vec<Value>) -> Result<u64> {
        let inner = json!({ "reports": reports });
        let reply = self.request("report", json!({ "proof": self.proofs.prove("proxy-report", &inner)?, "inner": inner })).await?;
        reply["accepted"].as_u64().context("reply without a count")
    }
}
