//! The relay between the agents of the site (local NATS) and the Core (hub NATS).

use std::{fs, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use async_nats::{Client, Message};
use futures::StreamExt;
use serde_json::{Value, json};
use tokio::sync::Notify;

use crate::{
    allowlist::AllowList,
    hub::{Hub, now},
    queue::ReportQueue,
};

pub struct Relay {
    pub site: String,
    pub hub: Hub,
    /// The proxy's connection to the NATS server of its own site.
    pub local: Client,
    pub allow: AllowList,
    pub queue: ReportQueue,
    /// Last policy answer per agent, served when the Core cannot be reached.
    pub cache_dir: PathBuf,
    sync_now: Notify,
    flush_now: Notify,
}

/// `delbert.<kind>.<tenant>.<agent>...` -> (tenant, agent)
fn agent_of(subject: &str) -> Option<(&str, &str)> {
    let mut parts = subject.split('.');
    parts.next().filter(|p| *p == "delbert")?;
    parts.next()?;
    Some((parts.next()?, parts.next()?))
}

impl Relay {
    pub fn new(site: String, hub: Hub, local: Client, allow: AllowList, queue: ReportQueue, cache_dir: PathBuf) -> Result<Arc<Self>> {
        fs::create_dir_all(&cache_dir)?;
        Ok(Arc::new(Relay { site, hub, local, allow, queue, cache_dir, sync_now: Notify::new(), flush_now: Notify::new() }))
    }

    fn cache_file(&self, tenant: &str, agent: &str) -> PathBuf {
        self.cache_dir.join(format!("{tenant}.{agent}.json"))
    }

    /// Ask the Core for the agents of this site. A failure keeps the list we have.
    pub async fn sync(&self) {
        match self.hub.agents().await {
            Ok(reply) => match self.allow.replace_from(&reply) {
                Ok(n) => tracing::debug!("allow-list synchronized: {n} agents"),
                Err(e) => tracing::warn!("cannot use the agent list: {e}"),
            },
            Err(e) => tracing::warn!("cannot refresh the agent list ({e:#}); keeping the current one ({} agents)", self.allow.len()),
        }
    }

    async fn reply(&self, msg: &Message, body: Value) {
        if let Some(reply) = msg.reply.clone() {
            if let Err(e) = self.local.publish(reply, body.to_string().into()).await {
                tracing::warn!("cannot answer an agent: {e}");
            }
        }
    }

    /// A policy request or a renewal of an agent of the site.
    async fn request(self: Arc<Self>, msg: Message, kind: &'static str) {
        let Some((tenant, agent)) = agent_of(msg.subject.as_str()).map(|(t, a)| (t.to_owned(), a.to_owned())) else { return };
        let unauthorized = json!({ "error": "unauthorized" });
        let Ok(payload) = serde_json::from_slice::<Value>(&msg.payload) else { return self.reply(&msg, unauthorized).await };

        // Check the agent's proof here first: junk from the local network never reaches the Core.
        let (proof_kind, body, proof) = match kind {
            "renew" => ("renew", json!({ "csr_pem": payload["csr_pem"] }), &payload["proof"]),
            _ => ("req", Value::Null, &payload),
        };
        let proven = serde_json::from_value(proof.clone()).is_ok_and(|p| self.allow.verify(proof_kind, &tenant, &agent, &body, &p));
        if !proven {
            tracing::warn!("rejected an unauthenticated {kind} from {tenant}/{agent}");
            return self.reply(&msg, unauthorized).await;
        }

        match self.hub.relay(kind, &tenant, &agent, payload).await {
            Ok(answer) => {
                if kind == "effective" && answer["token"].is_string() {
                    let _ = fs::write(self.cache_file(&tenant, &agent), answer.to_string());
                }
                if kind == "renew" {
                    self.sync().await; // the agent reconnects with a new key right away: learn it first
                }
                self.reply(&msg, answer).await;
            }
            Err(e) => {
                tracing::warn!("cannot relay a {kind} of {tenant}/{agent}: {e:#}");
                // The cached token is signed by the Core; the agent checks signature, expiry and version itself.
                let cached = (kind == "effective").then(|| fs::read_to_string(self.cache_file(&tenant, &agent)).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok())).flatten();
                match cached {
                    Some(answer) => {
                        tracing::info!("answering {tenant}/{agent} from the cache");
                        self.reply(&msg, answer).await
                    }
                    None => self.reply(&msg, json!({ "error": "the Core is unreachable" })).await,
                }
            }
        }
    }

    /// A report of an agent of the site: keep the latest one until the Core has it.
    fn report(&self, msg: &Message) {
        let Some((tenant, agent)) = agent_of(msg.subject.as_str()) else { return };
        let Ok(envelope) = serde_json::from_slice::<Value>(&msg.payload) else { return };
        let proven = serde_json::from_value(envelope["proof"].clone()).is_ok_and(|p| self.allow.verify("report", tenant, agent, &envelope["report"], &p));
        if !proven {
            tracing::warn!("dropped a report of {tenant}/{agent} with an invalid proof");
            return;
        }
        match self.queue.push(tenant, agent, now(), &envelope) {
            Ok(()) => self.flush_now.notify_one(),
            Err(e) => tracing::error!("cannot queue a report: {e}"),
        }
    }

    /// Send what is queued; keep it if the Core does not acknowledge.
    pub async fn flush(&self) {
        loop {
            let batch = self.queue.pending(100);
            if batch.is_empty() {
                return;
            }
            let items = batch.iter().map(|p| p.item.clone()).collect();
            match self.hub.forward_reports(items).await {
                Ok(n) => {
                    tracing::debug!("forwarded {} reports ({n} stored)", batch.len());
                    self.queue.ack(&batch);
                }
                Err(e) => {
                    tracing::warn!("cannot forward {} queued reports ({e:#}); will retry", self.queue.len());
                    return;
                }
            }
        }
    }

    /// Run until the connections end.
    pub async fn run(self: Arc<Self>, sync_every: Duration, flush_every: Duration) -> Result<()> {
        let mut effective = self.local.subscribe("delbert.req.*.*.effective").await?;
        let mut renewals = self.local.subscribe("delbert.req.*.*.renew").await?;
        let mut reports = self.local.subscribe("delbert.report.*.*").await?;
        let (mut notifications, mut sync_hints) = self.hub.subscribe_notifications().await?;
        tracing::info!("relay running for site {} ({} agents known, {} reports queued)", self.site, self.allow.len(), self.queue.len());

        let me = self.clone();
        tokio::spawn(async move {
            while let Some(msg) = effective.next().await {
                tokio::spawn(me.clone().request(msg, "effective"));
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            while let Some(msg) = renewals.next().await {
                tokio::spawn(me.clone().request(msg, "renew"));
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            while let Some(msg) = reports.next().await {
                me.report(&msg);
            }
        });
        // Notifications for our agents are passed on locally; for anyone else they are ignored.
        let me = self.clone();
        tokio::spawn(async move {
            while let Some(msg) = notifications.next().await {
                if agent_of(msg.subject.as_str()).is_some_and(|(t, a)| me.allow.contains(t, a)) {
                    let _ = me.local.publish(msg.subject.clone(), msg.payload.clone()).await;
                }
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            while sync_hints.next().await.is_some() {
                me.sync_now.notify_one();
            }
        });

        let me = self.clone();
        let syncer = tokio::spawn(async move {
            loop {
                me.sync().await;
                tokio::select! { _ = tokio::time::sleep(sync_every) => {}, _ = me.sync_now.notified() => {} }
            }
        });
        let me = self.clone();
        let flusher = tokio::spawn(async move {
            loop {
                me.flush().await;
                tokio::select! { _ = tokio::time::sleep(flush_every) => {}, _ = me.flush_now.notified() => {} }
            }
        });
        let _ = tokio::join!(syncer, flusher);
        Ok(())
    }
}
