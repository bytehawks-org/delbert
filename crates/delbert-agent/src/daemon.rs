//! Long-running agent: pull the signed policy over NATS, verify it, converge
//! the host, report. Outbound-only: the agent never listens on a port.
//!
//! * A notification (`delbert.notify.<t>.<a>`) or the periodic timer triggers a cycle.
//! * Every cycle re-applies the policy, so drift is corrected even when nothing changed.
//! * If the Core is unreachable the last verified policy is used until it expires;
//!   after that the agent applies nothing (fail safe) and keeps reporting the error.

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use sha2::{Digest, Sha256};
use delbert_wire::{EffectivePolicy, Expect, Verifier};
use futures::StreamExt;
use serde_json::{Value, json};

use crate::{
    engine::{Ctx, Mode, Report, Status, run},
    events,
    remediation,
    identity::Identity,
    state::State,
};

pub struct DaemonConfig {
    /// Enrolled identity (see `identity.rs`).
    pub identity: Identity,
    /// Overrides the NATS URL received at enrollment.
    pub nats_url: Option<String>,
    /// Holds `state.json` (anti-rollback) and `policy.jws` (last verified policy).
    pub state_dir: PathBuf,
    pub interval: Duration,
    pub artifacts: PathBuf,
    pub root: PathBuf,
    /// Renew the certificate when less than this many seconds remain
    /// (default: when a third of its lifetime is left).
    pub renew_before_secs: Option<i64>,
    /// Custom facts (`*.yaml|yml|json`), kept on the host and never reported.
    pub facts_dir: PathBuf,
    /// Executables `cron` resources may schedule (local allow-list; empty = cron refused).
    pub cron_allow: Vec<String>,
    /// Executables `command` resources may run (`path` or `path@sha256`; empty = commands refused).
    pub command_allow: Vec<String>,
    /// The shared facts are sent to the Core when they change and at least this often.
    pub facts_interval: Duration,
}

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Event batches sent in one cycle (a long backlog drains over several cycles).
const MAX_BATCHES_PER_CYCLE: usize = 10;
/// Never renew twice within this time: a threshold longer than the certificates the Core
/// issues would otherwise make the agent renew on every cycle.
const MIN_RENEWAL_GAP: Duration = Duration::from_secs(3600);

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn write_atomic(path: &std::path::Path, data: &[u8]) -> Result<()> {
    Ok(delbert_fs::write_private(path, data)?)
}

/// JSON sent to the Core after every cycle.
pub fn report_json(report: Option<&Report>, version: Option<u64>, error: Option<&str>, trusted_kids: &[String]) -> Value {
    let resources: Vec<Value> = report
        .map(|r| {
            r.resources
                .iter()
                .map(|x| {
                    let (status, detail) = match &x.status {
                        Status::Compliant => ("ok", String::new()),
                        Status::Drifted(d) => ("drift", d.join(", ")),
                        Status::Changed(d) => ("changed", d.join(", ")),
                        Status::Idle => ("idle", String::new()),
                        Status::Unsupported(m) => ("unsupported", m.clone()),
                        Status::Skipped(m) => ("skipped", m.clone()),
                        Status::NotApplicable(m) => ("not_applicable", m.clone()),
                        Status::Failed(m) => ("failed", m.clone()),
                    };
                    json!({ "id": x.id, "status": status, "detail": detail })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "version": version,
        "at": now(),
        "compliant": error.is_none() && report.is_some_and(Report::is_compliant),
        "error": error,
        "resources": resources,
        // Key ids this agent trusts: the Core uses them to know when a signing-key rotation is safe.
        "trusted_kids": trusted_kids,
    })
}

struct Agent<'a> {
    /// Set from the signed policy: replace certificates issued before this Unix time (0 = no request).
    renew_issued_before: std::sync::atomic::AtomicI64,
    cfg: &'a DaemonConfig,
    client: async_nats::Client,
    key_pem: String,
    /// The shared facts last sent and when: in memory only, a restart simply sends them again.
    facts_sent: std::sync::Mutex<Option<(Value, std::time::Instant)>>,
}

impl Agent<'_> {
    /// Facts go with the report when they changed, or when the last time is older than the interval.
    fn facts_due(&self, facts: &Value) -> bool {
        match &*self.facts_sent.lock().expect("facts lock") {
            Some((sent, at)) => sent != facts || at.elapsed() >= self.cfg.facts_interval,
            None => true,
        }
    }

    /// Ask the Core for the current signed policy; on success remember it.
    async fn fetch(&self) -> Result<String> {
        let (tenant, agent) = (&self.cfg.identity.meta.tenant, &self.cfg.identity.meta.agent);
        let subject = format!("delbert.req.{tenant}.{agent}.effective");
        let proof = delbert_pki::authn::prove(&self.key_pem, "req", tenant, agent, &Value::Null, now())?;
        let reply = tokio::time::timeout(REQUEST_TIMEOUT, self.client.request(subject, serde_json::to_vec(&proof)?.into()))
            .await
            .context("timeout waiting for the Core")?
            .context("request failed")?;
        let body: Value = serde_json::from_slice(&reply.payload).context("malformed reply")?;
        if let Some(e) = body["error"].as_str() {
            anyhow::bail!("Core refused: {e}");
        }
        let token = body["token"].as_str().context("reply without token")?.to_owned();
        Ok(token)
    }

    /// Verify a token against trusted keys (re-read each cycle so keys can rotate).
    fn verify(&self, token: &str, state: &State) -> Result<EffectivePolicy> {
        let keys = fs::read_to_string(self.cfg.identity.trusted_keys()).context("reading trusted keys")?;
        let verifier = Verifier::from_trusted_keys(&keys)?;
        let meta = &self.cfg.identity.meta;
        let expect = Expect { tenant: &meta.tenant, agent: &meta.agent, now: now() };
        let policy = verifier.verify(token, &expect, |name| state.versions.get(name).copied())?;
        // The policy is authentic: honour the key rotation it announces (docs/ROTATION.md).
        if let (Some(update), Some(signed_by)) = (&policy.trust, delbert_wire::jws::token_kid(token)) {
            match delbert_wire::trust::apply(&keys, update, &signed_by) {
                Ok(Some(next)) => {
                    delbert_fs::write_public(&self.cfg.identity.trusted_keys(), next.as_bytes()).context("updating trusted keys")?;
                    tracing::info!("trusted signing keys are now: {}", delbert_wire::trust::kids(&next).join(", "));
                }
                Ok(None) => {}
                Err(e) => tracing::error!("ignoring the key update of the policy: {e}"),
            }
        }
        // CA rotation (docs/ROTATION.md): learn or forget CAs, and replace old certificates.
        if let Some(update) = &policy.trust {
            if !update.ca_add.is_empty() || !update.ca_remove.is_empty() {
                let path = self.cfg.identity.path("ca.pem");
                let bundle = fs::read_to_string(&path).context("reading ca.pem")?;
                match delbert_pki::bundle::apply(&bundle, &update.ca_add, &update.ca_remove) {
                    Ok(Some(next)) => {
                        delbert_fs::write_public(&path, next.as_bytes()).context("updating ca.pem")?;
                        tracing::info!("trusted CAs are now: {}", delbert_pki::bundle::fingerprints(&next).iter().map(|f| &f[..12]).collect::<Vec<_>>().join(", "));
                    }
                    Ok(None) => {}
                    Err(e) => tracing::error!("ignoring the CA update of the policy: {e}"),
                }
            }
            self.renew_issued_before.store(update.renew_issued_before.unwrap_or(0), std::sync::atomic::Ordering::Relaxed);
        }
        Ok(policy)
    }

    /// Fingerprints of the CAs this agent trusts, and of the one that issued its own certificate.
    fn ca_report(&self) -> (Vec<String>, Option<String>) {
        let bundle = fs::read_to_string(self.cfg.identity.path("ca.pem")).unwrap_or_default();
        let cert = fs::read_to_string(self.cfg.identity.path("cert.pem")).unwrap_or_default();
        (delbert_pki::bundle::fingerprints(&bundle), delbert_pki::bundle::issuer_of(&cert, &bundle))
    }

    /// Key ids currently trusted, for the report.
    fn trusted_kids(&self) -> Vec<String> {
        fs::read_to_string(self.cfg.identity.trusted_keys()).map(|t| delbert_wire::trust::kids(&t)).unwrap_or_default()
    }

    /// Replace the certificate with a new one for a NEW key; the Core authenticates the
    /// request with the current key. Returns after the files are in place: the caller must
    /// reconnect so that NATS sees the new certificate.
    async fn renew(&self) -> Result<()> {
        let id = &self.cfg.identity;
        let (tenant, agent) = (&id.meta.tenant, &id.meta.agent);
        let (new_key, csr) = delbert_pki::new_identity(agent)?;
        let proof = delbert_pki::authn::prove(&self.key_pem, "renew", tenant, agent, &json!({ "csr_pem": csr }), now())?;
        let payload = serde_json::to_vec(&json!({ "proof": proof, "csr_pem": csr }))?;
        let reply = tokio::time::timeout(REQUEST_TIMEOUT, self.client.request(format!("delbert.req.{tenant}.{agent}.renew"), payload.into()))
            .await
            .context("timeout waiting for the Core")?
            .context("renewal request failed")?;
        let body: Value = serde_json::from_slice(&reply.payload).context("malformed reply")?;
        if let Some(e) = body["error"].as_str() {
            anyhow::bail!("Core refused the renewal: {e}");
        }
        let cert = body["cert_pem"].as_str().context("reply without certificate")?;
        crate::identity::install_renewed(&id.dir, &new_key, cert)
    }

    /// The execution context of a policy.
    fn context(&self, policy: &EffectivePolicy, secrets: BTreeMap<String, String>, artifacts_dir: PathBuf) -> Ctx {
        let mut ctx = Ctx::new(self.cfg.root.clone(), artifacts_dir);
        ctx.facts_dir = self.cfg.facts_dir.clone();
        ctx.cron_allow = self.cfg.cron_allow.clone();
        ctx.command_allow = self.cfg.command_allow.clone();
        // Keyed with something only this agent has, so a container label cannot be used to test guesses.
        ctx.hash_key = Sha256::digest(format!("delbert-container-hash-v1\n{}", self.key_pem)).to_vec();
        ctx.vars = policy.vars.clone();
        ctx.secrets = secrets;
        ctx.artifact_hashes = policy.artifacts.iter().map(|(n, a)| (n.clone(), a.sha256.clone())).collect();
        ctx
    }

    /// The last known good policy, verified again (signature, target, canonical form) but judged as
    /// of its own issue time: it has expired by now and it is older than the version that failed,
    /// which is exactly the case this is for. Secrets and artifacts come from the policy itself and
    /// the content-addressed cache.
    async fn prepare_lkg(&self) -> Option<(EffectivePolicy, Ctx)> {
        let token = fs::read_to_string(self.cfg.state_dir.join("policy.lkg.jws")).ok()?;
        let issued_at = {
            let payload = token.trim().split('.').nth(1)?;
            let bytes = B64.decode(payload).ok()?;
            serde_json::from_slice::<Value>(&bytes).ok()?["issued_at"].as_i64()?
        };
        let keys = fs::read_to_string(self.cfg.identity.trusted_keys()).ok()?;
        let verifier = Verifier::from_trusted_keys(&keys).ok()?;
        let meta = &self.cfg.identity.meta;
        let policy = match verifier.verify(&token, &Expect { tenant: &meta.tenant, agent: &meta.agent, now: issued_at }, |_| None) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("the last known good policy is not usable: {e}");
                return None;
            }
        };
        let secrets = self.decrypt_secrets(&policy).unwrap_or_default();
        let artifacts_dir = if policy.artifacts.is_empty() { self.cfg.artifacts.clone() } else { self.stage_artifacts(&policy).await };
        let ctx = self.context(&policy, secrets, artifacts_dir);
        Some((policy, ctx))
    }

    /// Steady state while a version is quarantined: apply the last known good again (no remediation).
    async fn enforce_lkg(&self) -> Option<Report> {
        let (policy, ctx) = self.prepare_lkg().await?;
        tokio::task::spawn_blocking(move || run(&policy.resources, &ctx, Mode::Apply)).await.ok()
    }

    /// Decrypt the secrets addressed to this agent.
    fn decrypt_secrets(&self, policy: &EffectivePolicy) -> Result<BTreeMap<String, String>> {
        if policy.secrets.is_empty() {
            return Ok(BTreeMap::new());
        }
        let identity = self.cfg.identity.age_identity()?;
        policy
            .secrets
            .iter()
            .map(|(name, b64)| {
                let ciphertext = B64.decode(b64).with_context(|| format!("secret '{name}' is not base64"))?;
                let plain = age::decrypt(&identity, &ciphertext).map_err(|e| anyhow::anyhow!("cannot decrypt secret '{name}': {e}"))?;
                Ok((name.clone(), String::from_utf8(plain).with_context(|| format!("secret '{name}' is not UTF-8"))?))
            })
            .collect()
    }

    /// Make the pinned artifacts available under `<state_dir>/stage/<name>`, downloading
    /// the ones missing from the content-addressed cache. Every file is checked against
    /// the SHA-256 in the signed policy; failures are logged and the resources that need
    /// the artifact fail on their own.
    async fn stage_artifacts(&self, policy: &EffectivePolicy) -> PathBuf {
        let stage = self.cfg.state_dir.join("stage");
        let cache = self.cfg.state_dir.join("artifacts");
        let _ = fs::remove_dir_all(&stage);
        let _ = fs::create_dir_all(&stage);
        let _ = fs::create_dir_all(&cache);
        for (name, pinned) in &policy.artifacts {
            let cached = cache.join(&pinned.sha256);
            let have = fs::read(&cached).ok().filter(|b| sha_hex(b) == pinned.sha256);
            let bytes = match have {
                Some(b) => b,
                None => match self.download(name, &pinned.sha256, pinned.size).await {
                    Ok(b) => {
                        let _ = write_atomic(&cached, &b);
                        b
                    }
                    Err(e) => {
                        tracing::warn!("cannot get artifact '{name}': {e:#}");
                        continue;
                    }
                },
            };
            let _ = delbert_fs::write_private(&stage.join(name), &bytes);
        }
        stage
    }

    async fn download(&self, name: &str, sha256: &str, size: u64) -> Result<Vec<u8>> {
        let id = &self.cfg.identity;
        let base = id.meta.core_url.as_deref().context("no Core URL in the identity (enroll again)")?;
        if !base.starts_with("https://") {
            anyhow::bail!("artifacts are only downloaded over HTTPS");
        }
        let (tenant, agent) = (&id.meta.tenant, &id.meta.agent);
        let proof = delbert_pki::authn::prove(&self.key_pem, "artifact", tenant, agent, &Value::String(format!("{name}:{sha256}")), now())?;
        let ca = fs::read(id.path("ca.pem"))?;
        let client = reqwest::Client::builder().tls_certs_only(reqwest::Certificate::from_pem_bundle(&ca)?).timeout(Duration::from_secs(120)).build()?;
        let resp = client
            .get(format!("{base}/v1/agent/{tenant}/{agent}/artifacts/{name}?sha256={sha256}")) // hex: no escaping needed
            .header("Authorization", format!("Delbert-Agent {}", B64.encode(serde_json::to_vec(&proof)?)))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("download refused ({})", resp.status());
        }
        let bytes = resp.bytes().await?.to_vec();
        if bytes.len() as u64 != size || sha_hex(&bytes) != sha256 {
            anyhow::bail!("downloaded content does not match the pinned size/SHA-256");
        }
        Ok(bytes)
    }

    /// One full cycle. Never returns an error: problems go into the report.
    /// Returns whether a valid policy was available (and applied).
    async fn cycle(&self) -> bool {
        let state_path = self.cfg.state_dir.join("state.json");
        let cache_path = self.cfg.state_dir.join("policy.jws");
        let mut state = State::load(&state_path).unwrap_or_default();

        let fetched = self.fetch().await;
        let (token, from_cache) = match fetched {
            Ok(t) => (Some(t), false),
            Err(e) => {
                tracing::warn!("cannot fetch policy ({e:#}); trying the cached one");
                (fs::read_to_string(&cache_path).ok(), true)
            }
        };

        let outcome: Result<EffectivePolicy> = match &token {
            Some(t) => self.verify(t, &state),
            None => Err(anyhow::anyhow!("no policy available")),
        };

        let has_policy = outcome.is_ok();
        let events: Vec<events::Event>;
        let payload = match outcome {
            Ok(policy) => {
                if !from_cache {
                    if let Some(t) = &token {
                        let _ = write_atomic(&cache_path, t.as_bytes());
                    }
                }
                let previous = state.versions.insert(policy.name.clone(), policy.version);
                let at = now();

                // A version that was rolled back stays out until a newer one arrives or the Core
                // releases it with a signed `force` (each decision is obeyed once).
                let hold = remediation::gate(&mut state, policy.version, policy.force.as_ref());
                let _ = state.save(&state_path);

                if let Some(q) = hold {
                    // Quarantined: keep the last known good in force (drift is corrected), change nothing else.
                    let report = match q.state {
                        remediation::State::RolledBack => self.enforce_lkg().await,
                        _ => None,
                    };
                    events = Vec::new();
                    report_json(report.as_ref(), q.running_version, Some(&format!("version {} is quarantined: {}", q.failed_version, q.reason)), &self.trusted_kids())
                } else {
                    let secrets = match self.decrypt_secrets(&policy) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("{e:#}");
                            BTreeMap::new()
                        }
                    };
                    // Pinned artifacts come from the verified cache; unpinned ones (none in signed
                    // policies) would use the configured directory.
                    let artifacts_dir = if policy.artifacts.is_empty() { self.cfg.artifacts.clone() } else { self.stage_artifacts(&policy).await };
                    let ctx = self.context(&policy, secrets, artifacts_dir);
                    let resources = policy.resources.clone();
                    let managed = state.managed.clone();
                    // Only an update can be undone: steady-state cycles just correct drift.
                    let update = state.lkg_version != Some(policy.version);
                    let applied = tokio::task::spawn_blocking(move || {
                        let mut report = run(&resources, &ctx, Mode::Apply);
                        let failures = if update { remediation::evaluate(&resources, &report, &ctx, &|d| std::thread::sleep(d)) } else { Vec::new() };
                        // End of a clean cycle: remove what this version dropped (and remember what it manages).
                        let record = if failures.is_empty() { crate::orphans::commit(&ctx, &resources, &managed, &mut report) } else { None };
                        (report, record, failures, ctx)
                    })
                    .await;
                    match applied {
                        Ok((report, record, failures, ctx)) => {
                            if let Some(record) = record {
                                state.managed = record;
                            }
                            let mut evs = events::derive(&events::Outcome::Applied { policy: &policy.name, version: policy.version, previous, report: &report }, at, &mut state.events);
                            if failures.is_empty() && !report.has_failures() && token.is_some() {
                                // A clean cycle: this is the new last known good.
                                if let Some(t) = &token {
                                    if write_atomic(&self.cfg.state_dir.join("policy.lkg.jws"), t.as_bytes()).is_ok() {
                                        state.lkg_version = Some(policy.version);
                                    }
                                }
                            } else if !failures.is_empty() {
                                for f in &failures {
                                    tracing::warn!("{}: {}", f.id, f.reason);
                                }
                                let lkg = self.prepare_lkg().await;
                                let version = policy.version;
                                let remedy = tokio::task::spawn_blocking(move || {
                                    let lkg_ref = lkg.as_ref().map(|(p, c)| remediation::Lkg { version: p.version, resources: &p.resources, ctx: c });
                                    remediation::remediate(&ctx, &failures, version, lkg_ref, at, &|d| std::thread::sleep(d))
                                })
                                .await
                                .ok()
                                .flatten();
                                if let Some(remedy) = remedy {
                                    tracing::warn!("remediation of v{}: {:?}: {}", version, remedy.quarantine.state, remedy.quarantine.steps.join("; "));
                                    evs.extend(events::remediation_events(&remedy.quarantine, at));
                                    if remedy.quarantine.state != remediation::State::Skipped {
                                        state.quarantine = Some(remedy.quarantine);
                                    }
                                }
                            }
                            events = evs;
                            tracing::info!("applied policy v{} ({} resources, compliant: {})", policy.version, report.resources.len(), report.is_compliant());
                            report_json(Some(&report), Some(policy.version), None, &self.trusted_kids())
                        }
                        Err(e) => {
                            let error = format!("apply task failed: {e}");
                            events = events::derive(&events::Outcome::ApplyCrashed { policy: &policy.name, version: policy.version, error: &error }, at, &mut state.events);
                            report_json(None, Some(policy.version), Some(&error), &self.trusted_kids())
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("no valid policy: {e:#}");
                // A policy that arrived and was refused is an event; not reaching the Core is not.
                let reason = format!("{e:#}");
                let outcome = if token.is_some() { events::Outcome::Rejected { reason: &reason } } else { events::Outcome::NoPolicy };
                events = events::derive(&outcome, now(), &mut state.events);
                report_json(None, None, Some(&reason), &self.trusted_kids())
            }
        };
        // The failure memo lives in the state file; the events go to the spool and are sent below.
        let _ = state.save(&state_path);
        let spool = events::Spool::new(self.cfg.state_dir.join("events"));
        match &spool {
            Ok(spool) => {
                if let Err(e) = spool.push(&events) {
                    tracing::error!("cannot spool {} audit events: {e:#}", events.len());
                }
            }
            Err(e) => tracing::error!("cannot open the event spool: {e:#}"),
        }

        let mut payload = payload;
        // The agent is inconsistent with the Core while a failed version is quarantined: say what
        // happened, report the version that actually runs, and never claim to be compliant.
        payload["remediation"] = json!(state.quarantine);
        if let Some(q) = &state.quarantine {
            payload["compliant"] = json!(false);
            if q.state != remediation::State::Stopped {
                payload["version"] = json!(q.running_version);
            }
        }
        let (trusted_cas, cert_issuer) = self.ca_report();
        payload["trusted_cas"] = json!(trusted_cas);
        payload["cert_issuer"] = json!(cert_issuer);
        let facts = crate::facts::shared(&self.cfg.root);
        let send_facts = self.facts_due(&facts);
        if send_facts {
            payload["facts"] = facts.clone();
        }
        let meta = &self.cfg.identity.meta;
        let subject = format!("delbert.report.{}.{}", meta.tenant, meta.agent);
        match delbert_pki::authn::prove(&self.key_pem, "report", &meta.tenant, &meta.agent, &payload, now()) {
            Ok(proof) => {
                let envelope = json!({ "proof": proof, "report": payload });
                match self.client.publish(subject, envelope.to_string().into()).await {
                    Ok(()) if send_facts => *self.facts_sent.lock().expect("facts lock") = Some((facts, std::time::Instant::now())),
                    Ok(()) => {}
                    Err(e) => tracing::warn!("cannot publish report: {e}"),
                }
            }
            Err(e) => tracing::error!("cannot sign the report: {e}"),
        }
        if let Ok(spool) = &spool {
            self.send_events(spool).await;
        }
        has_policy
    }

    /// Send what is in the spool, oldest first, and forget what the Core (or the site proxy)
    /// acknowledges. Anything unacknowledged stays for the next cycle.
    async fn send_events(&self, spool: &events::Spool) {
        let meta = &self.cfg.identity.meta;
        let subject = format!("delbert.event.{}.{}", meta.tenant, meta.agent);
        for _ in 0..MAX_BATCHES_PER_CYCLE {
            let (batch, paths) = spool.pending(events::BATCH);
            if batch.is_empty() {
                return;
            }
            let events = Value::Array(batch);
            let sent = async {
                let proof = delbert_pki::authn::prove(&self.key_pem, "event", &meta.tenant, &meta.agent, &events, now())?;
                let payload = json!({ "proof": proof, "events": events });
                let reply = tokio::time::timeout(REQUEST_TIMEOUT, self.client.request(subject.clone(), payload.to_string().into())).await.context("timeout")?.context("request failed")?;
                let body: Value = serde_json::from_slice(&reply.payload).context("malformed reply")?;
                match body["error"].as_str() {
                    Some(e) => anyhow::bail!("refused: {e}"),
                    None => Ok(()),
                }
            }
            .await;
            match sent {
                Ok(()) => spool.ack(&paths),
                Err(e) => {
                    tracing::warn!("cannot deliver {} audit events ({e:#}); {} waiting", paths.len(), spool.len());
                    return;
                }
            }
        }
    }
}

/// SIGTERM (container or service stop) or Ctrl-C; on Windows also a stop request from the
/// Service Control Manager (see `winsvc`).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(windows)]
    tokio::select! {
        _ = crate::winsvc::stop_requested() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

enum SessionEnd {
    Stop,
    /// The identity changed: connect again with the new certificate.
    Reconnect,
}

/// One NATS connection: cycles until stopped, or until a renewal needs a new connection.
async fn session(cfg: &DaemonConfig, last_renewal: &mut Option<std::time::Instant>) -> Result<SessionEnd> {
    let id = &cfg.identity;
    let nats_url = cfg.nats_url.clone().or_else(|| id.meta.nats_url.clone()).context("no NATS URL: pass --nats-url or enroll against a Core that publishes one")?;
    // mTLS: the server must be signed by the Delbert CA and so must we. The inbox prefix is
    // per agent because that is all the Core's authorization lets this connection subscribe to.
    // Keep working (with the cached policy) even if the Core is down at start.
    let client = async_nats::ConnectOptions::new()
        .require_tls(true)
        .add_root_certificates(id.path("ca.pem"))
        .add_client_certificate(id.path("cert.pem"), id.path("key.pem"))
        .custom_inbox_prefix(format!("_INBOX.{}.{}", id.meta.tenant, id.meta.agent))
        // Notice a dead link (a proxy or Core outage) within about 30 s.
        .ping_interval(Duration::from_secs(10))
        .retry_on_initial_connect()
        .connect(&nats_url)
        .await?;
    let mut notifications = client.subscribe(format!("delbert.notify.{}.{}", id.meta.tenant, id.meta.agent)).await?;
    tracing::info!("agent {}/{} connected, interval {:?}", id.meta.tenant, id.meta.agent, cfg.interval);

    let key_pem = id.key_pem()?;
    let agent = Agent { cfg, client, key_pem, renew_issued_before: std::sync::atomic::AtomicI64::new(0), facts_sent: std::sync::Mutex::new(None) };
    // Right after start the proxy or the Core may not be answering yet: without a policy, retry soon.
    const RETRY_WITHOUT_POLICY: Duration = Duration::from_secs(5);
    loop {
        let has_policy = agent.cycle().await;

        let cert = fs::read_to_string(id.path("cert.pem")).unwrap_or_default();
        let gap_ok = last_renewal.is_none_or(|t| t.elapsed() >= MIN_RENEWAL_GAP);
        // The Core can ask for certificates issued before a moment to be replaced (a CA rotation).
        let cutoff = agent.renew_issued_before.load(std::sync::atomic::Ordering::Relaxed);
        let too_old = cutoff > 0 && delbert_pki::cert_validity(&cert).is_ok_and(|(not_before, _)| not_before < cutoff);
        if gap_ok && (too_old || crate::identity::renewal_due(&cert, now(), cfg.renew_before_secs)) {
            match agent.renew().await {
                Ok(()) => {
                    *last_renewal = Some(std::time::Instant::now());
                    tracing::info!("certificate renewed, reconnecting");
                    return Ok(SessionEnd::Reconnect);
                }
                Err(e) => tracing::warn!("certificate renewal failed ({e:#}); will retry"),
            }
        }

        tokio::select! {
            _ = shutdown_signal() => return Ok(SessionEnd::Stop),
            _ = tokio::time::sleep(if has_policy { cfg.interval } else { cfg.interval.min(RETRY_WITHOUT_POLICY) }) => {}
            msg = notifications.next() => {
                if msg.is_none() { anyhow::bail!("notification subscription closed"); }
                tracing::info!("notification received");
                // Several notifications in a burst trigger a single cycle.
                tokio::time::sleep(Duration::from_millis(200)).await;
                while tokio::time::timeout(Duration::ZERO, notifications.next()).await.is_ok() {}
            }
        }
    }
}

/// Run until stopped.
pub async fn run_daemon(cfg: DaemonConfig) -> Result<()> {
    fs::create_dir_all(&cfg.state_dir).context("creating state dir")?;
    let mut last_renewal = None;
    loop {
        crate::identity::recover(&cfg.identity.dir)?; // finish a renewal interrupted by a crash
        match session(&cfg, &mut last_renewal).await? {
            SessionEnd::Stop => {
                tracing::info!("stopping");
                return Ok(());
            }
            SessionEnd::Reconnect => continue,
        }
    }
}
