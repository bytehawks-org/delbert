//! NATS integration (docs/ABSTRACT.md §2).
//!
//! Subjects (`<t>` tenant, `<a>` agent, `<s>` proxy site; names never contain dots):
//!
//! | Subject | Direction | Purpose |
//! |---------|-----------|---------|
//! | `delbert.notify.<t>.<a>` | Core → agent | "pull again" hint, no secrets |
//! | `delbert.req.<t>.<a>.{effective,renew}` | agent → Core (request/reply) | fetch the signed policy / renew the certificate |
//! | `delbert.report.<t>.<a>` | agent → Core | latest compliance report |
//! | `delbert.event.<t>.<a>` | agent → Core (request/reply) | a batch of per-action audit events, acknowledged once stored |
//! | `delbert.proxy.<s>.relay` | proxy → Core (request/reply) | an agent request relayed by the proxy of its site |
//! | `delbert.proxy.<s>.report` | proxy → Core | a stored report forwarded by the proxy |
//! | `delbert.proxy.<s>.event` | proxy → Core (request/reply) | stored event batches forwarded by the proxy |
//! | `delbert.proxy.<s>.agents` | proxy → Core (request/reply) | the agents (and keys) the proxy serves |
//! | `delbert.proxy.<s>.notify` | Core → proxy | "refresh your agent list" |
//!
//! Transport: TLS with client certificates issued by the Delbert CA, so only enrolled components
//! can connect, and the authorization callout (`bus_auth.rs`) confines each connection to its own
//! subjects. On top of that every request and report carries a proof signed with the agent's
//! identity key (`delbert_pki::authn`), checked against the public key certified at enrollment;
//! proxies prove themselves the same way. Policies are signed and their secrets are encrypted
//! for the target agent.

use std::{future::Future, path::PathBuf};

use async_nats::{Client, Message, Subscriber};
use delbert_pki::authn::{self, Proof};
use futures::StreamExt;
use serde_json::{Value, json};

use crate::api::{self, AppState};

const MAX_REPORT_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct Bus {
    client: Client,
}

/// Files for TLS with client authentication.
pub struct BusTls {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

impl Bus {
    pub async fn connect(url: &str, credentials: Option<(String, String)>, tls: Option<BusTls>) -> anyhow::Result<Self> {
        let mut options = match credentials {
            Some((user, pass)) => async_nats::ConnectOptions::with_user_and_password(user, pass),
            None => async_nats::ConnectOptions::new(),
        };
        if let Some(tls) = tls {
            options = options.require_tls(true).add_root_certificates(tls.ca).add_client_certificate(tls.cert, tls.key);
        }
        Ok(Bus { client: options.connect(url).await? })
    }

    pub fn from_client(client: Client) -> Self {
        Bus { client }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Tell a proxy to refresh its list of agents.
    pub async fn notify_proxy(&self, site: &str) {
        if let Err(e) = self.client.publish(format!("delbert.proxy.{site}.notify"), "{}".into()).await {
            tracing::warn!("cannot notify proxy {site}: {e}");
        }
    }

    /// Hint an agent to pull its policy again. Failures are logged, never fatal.
    pub async fn notify(&self, tenant: &str, agent: &str) {
        let body = json!({ "event": "policy-changed" }).to_string();
        if let Err(e) = self.client.publish(format!("delbert.notify.{tenant}.{agent}"), body.into()).await {
            tracing::warn!("cannot notify {tenant}/{agent}: {e}");
        }
    }
}

/// `delbert.<kind>.<tenant>.<agent>[.suffix]` -> (tenant, agent)
pub fn parse_subject<'a>(subject: &'a str, kind: &str) -> Option<(&'a str, &'a str)> {
    let mut parts = subject.split('.');
    (parts.next()? == "delbert" && parts.next()? == kind).then_some(())?;
    Some((parts.next()?, parts.next()?))
}

/// `delbert.proxy.<site>.<what>` -> (site, what)
pub fn parse_proxy_subject(subject: &str) -> Option<(&str, &str)> {
    let mut parts = subject.split('.');
    (parts.next()? == "delbert" && parts.next()? == "proxy").then_some(())?;
    Some((parts.next()?, parts.next()?))
}

/// Run `handler` for every message of `sub`; when it returns a body, publish it to the reply subject.
fn respond<F, Fut>(client: Client, state: AppState, mut sub: Subscriber, handler: F)
where
    F: Fn(AppState, Message) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = Option<Value>> + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(msg) = sub.next().await {
            let (client, state, handler) = (client.clone(), state.clone(), handler.clone());
            tokio::spawn(async move {
                let reply = msg.reply.clone();
                let subject = msg.subject.to_string();
                let body = handler(state, msg).await;
                if let (Some(reply), Some(body)) = (reply, body) {
                    if let Err(e) = client.publish(reply, body.to_string().into()).await {
                        tracing::warn!("cannot reply on {subject}: {e}");
                    }
                }
            });
        }
    });
}

/// Policy request of an agent (direct, or relayed by its proxy).
pub(crate) async fn effective_reply(state: &AppState, tenant: &str, agent: &str, payload: &[u8]) -> Value {
    let proof: Option<Proof> = serde_json::from_slice(payload).ok();
    if !proven(state, "req", tenant, agent, &Value::Null, proof.as_ref()).await {
        tracing::warn!("rejected unauthenticated policy request for {tenant}/{agent}");
        return json!({ "error": "unauthorized" });
    }
    match api::issue(state, tenant.to_owned(), agent.to_owned(), &format!("agent:{tenant}/{agent}")).await {
        Ok(issued) => json!({ "token": issued.token, "version": issued.version }),
        Err(e) => json!({ "error": e.1 }),
    }
}

/// Start the responders and the report collectors; returns once the subscriptions exist.
pub async fn serve(state: AppState) -> anyhow::Result<()> {
    let client = state.bus.as_ref().expect("serve requires a bus").client().clone();

    // Agents talking to the Core directly.
    let sub = client.queue_subscribe("delbert.req.*.*.effective", "core".into()).await?;
    respond(client.clone(), state.clone(), sub, |state, msg| async move {
        let (tenant, agent) = parse_subject(msg.subject.as_str(), "req")?;
        Some(effective_reply(&state, tenant, agent, &msg.payload).await)
    });
    let sub = client.queue_subscribe("delbert.req.*.*.renew", "core".into()).await?;
    respond(client.clone(), state.clone(), sub, |state, msg| async move {
        let (tenant, agent) = parse_subject(msg.subject.as_str(), "req")?;
        Some(renew(&state, tenant, agent, &msg.payload).await)
    });
    // Events are acknowledged after they are in the audit trail: the agent keeps its spool until then.
    let sub = client.queue_subscribe("delbert.event.*.*", "core".into()).await?;
    respond(client.clone(), state.clone(), sub, |state, msg| async move {
        let (tenant, agent) = parse_subject(msg.subject.as_str(), "event")?;
        Some(events_reply(&state, tenant, agent, &msg.payload).await)
    });
    let mut reports = client.subscribe("delbert.report.*.*").await?;
    let report_state = state.clone();
    tokio::spawn(async move {
        while let Some(msg) = reports.next().await {
            let Some((tenant, agent)) = parse_subject(msg.subject.as_str(), "report") else { continue };
            if msg.payload.len() > MAX_REPORT_BYTES {
                tracing::warn!("oversized report from {tenant}/{agent} dropped");
                continue;
            }
            match serde_json::from_slice::<Value>(&msg.payload) {
                Ok(envelope) => {
                    if !ingest_report(&report_state, tenant, agent, &envelope, now()).await {
                        tracing::warn!("report from {tenant}/{agent} with a missing or invalid proof dropped");
                    }
                }
                Err(_) => tracing::warn!("malformed report from {tenant}/{agent} dropped"),
            }
        }
    });

    // Proxies relaying for the agents of their site.
    let sub = client.queue_subscribe("delbert.proxy.*.relay", "core".into()).await?;
    respond(client.clone(), state.clone(), sub, |state, msg| async move {
        let (site, _) = parse_proxy_subject(msg.subject.as_str())?;
        Some(crate::proxies::relay(&state, site, &msg.payload).await)
    });
    let sub = client.queue_subscribe("delbert.proxy.*.agents", "core".into()).await?;
    respond(client.clone(), state.clone(), sub, |state, msg| async move {
        let (site, _) = parse_proxy_subject(msg.subject.as_str())?;
        Some(crate::proxies::agents(&state, site, &msg.payload).await)
    });
    // The reply acknowledges the batch: the proxy keeps its queue until it has it.
    let sub = client.queue_subscribe("delbert.proxy.*.report", "core".into()).await?;
    respond(client.clone(), state.clone(), sub, |state, msg| async move {
        let (site, _) = parse_proxy_subject(msg.subject.as_str())?;
        if msg.payload.len() > MAX_REPORT_BYTES * 4 {
            tracing::warn!("oversized report batch from proxy {site} dropped");
            return Some(json!({ "error": "too large" }));
        }
        Some(crate::proxies::forwarded_reports(&state, site, &msg.payload).await)
    });
    // Same for the batches a proxy stored for its agents.
    let sub = client.queue_subscribe("delbert.proxy.*.event", "core".into()).await?;
    respond(client.clone(), state, sub, |state, msg| async move {
        let (site, _) = parse_proxy_subject(msg.subject.as_str())?;
        if msg.payload.len() > MAX_REPORT_BYTES * 8 {
            tracing::warn!("oversized event batch from proxy {site} dropped");
            return Some(json!({ "error": "too large" }));
        }
        Some(crate::proxies::forwarded_events(&state, site, &msg.payload).await)
    });
    Ok(())
}

/// An agent's event batch sent directly to the Core: `{proof, events}`.
async fn events_reply(state: &AppState, tenant: &str, agent: &str, payload: &[u8]) -> Value {
    if payload.len() > MAX_REPORT_BYTES {
        return json!({ "error": "too large" });
    }
    let Ok(batch) = serde_json::from_slice::<Value>(payload) else { return json!({ "error": "malformed" }) };
    match crate::agent_events::ingest(state, tenant, agent, &batch, now()).await {
        Some(stored) => json!({ "stored": stored }),
        None => {
            tracing::warn!("event batch from {tenant}/{agent} rejected");
            json!({ "error": "unauthorized" })
        }
    }
}

/// Verify the agent's proof on a report envelope (`{proof, report}`) as of `at`, and store it.
pub(crate) async fn ingest_report(state: &AppState, tenant: &str, agent: &str, envelope: &Value, at: i64) -> bool {
    let proof: Option<Proof> = serde_json::from_value(envelope["proof"].clone()).ok();
    let report = &envelope["report"];
    if !proven_at(state, "report", tenant, agent, report, proof.as_ref(), at).await {
        return false;
    }
    if let Err(e) = store_report(state, tenant, agent, report).await {
        tracing::warn!("cannot store report from {tenant}/{agent}: {e}");
    }
    true
}

/// Does `proof` show that `agent` of `tenant` really sent `body`?
///
/// The current key is tried first, then the previous one (kept while a renewal is being
/// confirmed). The first proof made with the new key retires the old one.
pub(crate) async fn proven(state: &AppState, kind: &str, tenant: &str, agent: &str, body: &Value, proof: Option<&Proof>) -> bool {
    proven_at(state, kind, tenant, agent, body, proof, now()).await
}

/// Like [`proven`], judging freshness as of `at` (a proxy vouches for when it received a report).
pub(crate) async fn proven_at(state: &AppState, kind: &str, tenant: &str, agent: &str, body: &Value, proof: Option<&Proof>, at: i64) -> bool {
    let Some(proof) = proof else { return false };
    let keys: Result<Option<(Option<Vec<u8>>, Option<Vec<u8>>)>, _> = sqlx::query_as(
        "SELECT a.public_key, a.previous_public_key FROM agents a JOIN tenants t ON t.id = a.tenant_id WHERE t.name = $1 AND a.name = $2",
    )
    .bind(tenant)
    .bind(agent)
    .fetch_optional(&state.pool)
    .await;
    let Ok(Some((Some(current), previous))) = keys else { return false }; // unknown or not enrolled
    if authn::check(&current, kind, tenant, agent, body, proof, at).is_ok() {
        if previous.is_some() {
            let _ = sqlx::query("UPDATE agents SET previous_public_key = NULL WHERE public_key = $1 AND previous_public_key IS NOT NULL").bind(&current).execute(&state.pool).await;
        }
        return true;
    }
    previous.is_some_and(|old| authn::check(&old, kind, tenant, agent, body, proof, at).is_ok())
}

/// Certificate renewal: the agent sends a CSR for a NEW key, proving itself with the current one.
pub(crate) async fn renew(state: &AppState, tenant: &str, agent: &str, payload: &[u8]) -> Value {
    let unauthorized = json!({ "error": "unauthorized" });
    let Ok(request) = serde_json::from_slice::<Value>(payload) else { return unauthorized };
    let proof: Option<Proof> = serde_json::from_value(request["proof"].clone()).ok();
    let Some(csr) = request["csr_pem"].as_str() else { return unauthorized };
    if !proven(state, "renew", tenant, agent, &json!({ "csr_pem": csr }), proof.as_ref()).await {
        tracing::warn!("rejected unauthenticated renewal for {tenant}/{agent}");
        return unauthorized;
    }
    let Some(ca) = &state.pki else { return json!({ "error": "renewal is not configured" }) };
    let signed = match ca.sign_csr(csr, agent, &delbert_pki::agent_uri(tenant, agent), state.agent_cert_days) {
        Ok(s) => s,
        Err(e) => return json!({ "error": format!("invalid CSR: {e}") }),
    };
    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
        let mut tx = state.pool.begin().await?;
        let tid: sqlx::types::Uuid = sqlx::query_scalar("SELECT id FROM tenants WHERE name = $1").bind(tenant).fetch_one(&mut *tx).await?;
        sqlx::query("UPDATE agents SET previous_public_key = public_key, public_key = $3 WHERE tenant_id = $1 AND name = $2")
            .bind(tid)
            .bind(agent)
            .bind(&signed.public_key)
            .execute(&mut *tx)
            .await?;
        crate::audit::append(&mut tx, &crate::audit::NewEvent { tenant_id: Some(tid), actor: &format!("agent:{tenant}/{agent}"), action: "agent.renew", target: Some(agent), outcome: "ok", details: json!({ "cert_days": state.agent_cert_days }) }).await?;
        tx.commit().await?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            api::notify_proxy_of(state, tenant, agent).await; // the site must learn the new key
            json!({ "cert_pem": signed.cert_pem })
        }
        Err(e) => {
            tracing::error!("renewal of {tenant}/{agent} failed: {e}");
            json!({ "error": "internal error" })
        }
    }
}

async fn store_report(state: &AppState, tenant: &str, agent: &str, report: &serde_json::Value) -> Result<(), sqlx::Error> {
    let compliant = report["compliant"].as_bool().unwrap_or(false);
    let version = report["version"].as_i64();
    // Unknown agents are ignored: reports never create anything.
    sqlx::query(
        "INSERT INTO agent_reports (agent_id, version, compliant, report) \
         SELECT a.id, $3, $4, $5 FROM agents a JOIN tenants t ON t.id = a.tenant_id WHERE t.name = $1 AND a.name = $2 \
         ON CONFLICT (agent_id) DO UPDATE SET received_at = now(), version = $3, compliant = $4, report = $5 \
         WHERE COALESCE((agent_reports.report->>'at')::bigint, 0) <= COALESCE(($5::jsonb->>'at')::bigint, 0)",
    )
    .bind(tenant)
    .bind(agent)
    .bind(version)
    .bind(compliant)
    .bind(report)
    .execute(&state.pool)
    .await?;
    sqlx::query("SELECT pg_notify($3, json_build_object('t', t.id, 'k', 'report')::text) FROM tenants t WHERE t.name = $1 AND EXISTS (SELECT 1 FROM agents a WHERE a.tenant_id = t.id AND a.name = $2)")
        .bind(tenant)
        .bind(agent)
        .bind(crate::stream::CHANNEL)
        .execute(&state.pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_are_parsed_strictly() {
        assert_eq!(parse_subject("delbert.req.acme.agent-1.effective", "req"), Some(("acme", "agent-1")));
        assert_eq!(parse_subject("delbert.report.acme.a", "report"), Some(("acme", "a")));
        assert_eq!(parse_subject("delbert.report.acme.a", "req"), None);
        assert_eq!(parse_subject("other.req.acme.a", "req"), None);
        assert_eq!(parse_subject("delbert.req.acme", "req"), None);
        assert_eq!(parse_proxy_subject("delbert.proxy.branch-a.relay"), Some(("branch-a", "relay")));
        assert_eq!(parse_proxy_subject("delbert.req.branch-a.relay"), None);
    }
}
