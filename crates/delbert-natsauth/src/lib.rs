//! NATS authorization callout building blocks (docs/ABSTRACT.md §2).
//!
//! NATS authenticates every client with mutual TLS and asks a service, on
//! `$SYS.REQ.USER.AUTH`, what the client may do. This crate holds what the Core and the
//! Proxy have in common: the JWT format NATS expects, the subject permissions of the
//! different kinds of clients, and the request/response loop. Each side supplies its own
//! *decider*: given the client's certificate, who is it and may it connect?
//!
//! Permissions (`t` tenant, `a` agent, `s` proxy site):
//!
//! | Who | May publish | May subscribe |
//! |-----|-------------|---------------|
//! | agent `t/a` | `delbert.req.t.a.{effective,renew}`, `delbert.report.t.a` | `delbert.notify.t.a`, `_INBOX.t.a.>` |
//! | the Core | `delbert.notify.*.*`, `delbert.proxy.*.notify`, `_INBOX.>` | `delbert.req.*.*.{effective,renew}`, `delbert.report.*.*`, `delbert.proxy.*.{relay,report,agents}` |
//! | proxy `s` towards the Core | `delbert.proxy.s.{relay,report,agents}` | `delbert.notify.*.*`, `delbert.proxy.s.notify`, `_INBOX.proxy.s.>` |
//! | proxy `s` on its own site | `delbert.notify.*.*`, `_INBOX.>` | `delbert.req.*.*.{effective,renew}`, `delbert.report.*.*` |

use std::{future::Future, sync::Arc};

use async_nats::Client;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use futures::StreamExt;
use serde_json::{Value, json};

pub struct Callout {
    pub issuer: nkeys::KeyPair,
    /// Name of the NATS account clients are placed in.
    pub account: String,
    /// How long a connection may live before it must be authorized again.
    pub session_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permissions {
    pub publish: Vec<String>,
    pub subscribe: Vec<String>,
}

/// `(display name, permissions)` or a short reason.
pub type Decision = Result<(String, Permissions), &'static str>;

/// Reason shown (briefly) to the NATS server; nothing more is leaked to the client.
pub const DENIED: &str = "not authorized";

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn random_id() -> String {
    use rand_core::{OsRng, RngCore};
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    B64.encode(raw)
}

// --- JWT (NATS flavour: ed25519-nkey) ---------------------------------------------------

/// `base64url(header).base64url(claims).base64url(signature)` signed with an nkey.
pub fn jwt_encode(claims: &Value, signer: &nkeys::KeyPair) -> Result<String, String> {
    let header = B64.encode(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let payload = B64.encode(serde_json::to_vec(claims).map_err(|e| e.to_string())?);
    let input = format!("{header}.{payload}");
    let sig = signer.sign(input.as_bytes()).map_err(|e| e.to_string())?;
    Ok(format!("{input}.{}", B64.encode(sig)))
}

/// Claims of a JWT without verifying it (the authorization request comes from the server itself).
pub fn jwt_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&B64.decode(payload).ok()?).ok()
}

// --- permissions ----------------------------------------------------------------------------

pub fn agent_permissions(tenant: &str, agent: &str) -> Permissions {
    Permissions {
        publish: vec![format!("delbert.req.{tenant}.{agent}.effective"), format!("delbert.req.{tenant}.{agent}.renew"), format!("delbert.report.{tenant}.{agent}")],
        // The inbox prefix is per agent; the agent configures it on its connection.
        subscribe: vec![format!("delbert.notify.{tenant}.{agent}"), format!("_INBOX.{tenant}.{agent}.>")],
    }
}

pub fn core_permissions() -> Permissions {
    Permissions {
        publish: vec!["delbert.notify.*.*".into(), "delbert.proxy.*.notify".into(), "_INBOX.>".into()],
        subscribe: vec![
            "delbert.req.*.*.effective".into(),
            "delbert.req.*.*.renew".into(),
            "delbert.report.*.*".into(),
            "delbert.proxy.*.relay".into(),
            "delbert.proxy.*.report".into(),
            "delbert.proxy.*.agents".into(),
        ],
    }
}

/// A proxy's connection to the Core: only its own relay subjects.
pub fn proxy_hub_permissions(site: &str) -> Permissions {
    Permissions {
        publish: vec![format!("delbert.proxy.{site}.relay"), format!("delbert.proxy.{site}.report"), format!("delbert.proxy.{site}.agents")],
        subscribe: vec!["delbert.notify.*.*".into(), format!("delbert.proxy.{site}.notify"), format!("_INBOX.proxy.{site}.>")],
    }
}

/// A proxy's connection to the NATS server of its own site (the relay between agents and the Core).
pub fn proxy_site_permissions() -> Permissions {
    Permissions {
        publish: vec!["delbert.notify.*.*".into(), "_INBOX.>".into()],
        subscribe: vec!["delbert.req.*.*.effective".into(), "delbert.req.*.*.renew".into(), "delbert.report.*.*".into()],
    }
}

// --- the NATS wire format -----------------------------------------------------------------

pub fn response(callout: &Callout, user_nkey: &str, server_id: &str, outcome: Decision) -> Result<String, String> {
    let issuer = callout.issuer.public_key();
    let iat = now();
    let nats = match outcome {
        Ok((name, perms)) => {
            let user = json!({
                "jti": random_id(), "iat": iat, "exp": iat + callout.session_secs,
                "iss": issuer, "sub": user_nkey, "name": name, "aud": callout.account,
                "nats": {
                    "pub": { "allow": perms.publish }, "sub": { "allow": perms.subscribe },
                    "subs": -1, "data": -1, "payload": -1, "type": "user", "version": 2
                }
            });
            json!({ "jwt": jwt_encode(&user, &callout.issuer)?, "type": "authorization_response", "version": 2 })
        }
        Err(reason) => json!({ "error": reason, "type": "authorization_response", "version": 2 }),
    };
    jwt_encode(&json!({ "jti": random_id(), "iat": iat, "iss": issuer, "sub": user_nkey, "aud": server_id, "nats": nats }), &callout.issuer)
}

/// The client's certificate (PEM). NATS puts it in `verified_chains` once it has verified the
/// chain against the CA, and in `certs` otherwise.
pub fn client_certificate(nats: &Value) -> Option<&str> {
    let tls = &nats["client_tls"];
    tls["verified_chains"][0][0].as_str().or_else(|| tls["certs"][0].as_str())
}

async fn handle<F, Fut>(callout: &Callout, decider: &F, payload: &[u8]) -> Option<String>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Decision>,
{
    let claims = jwt_claims(std::str::from_utf8(payload).ok()?)?;
    let nats = &claims["nats"];
    let user_nkey = nats["user_nkey"].as_str()?;
    let server_id = nats["server_id"]["id"].as_str()?;
    let outcome = match client_certificate(nats) {
        Some(cert) => decider(cert.to_owned()).await,
        None => {
            tracing::warn!("nats: authorization request without a client certificate: {}", nats["client_tls"].to_string().chars().take(300).collect::<String>());
            Err(DENIED) // clients without a certificate never get here (TLS verify), but be explicit
        }
    };
    match &outcome {
        Ok((name, _)) => tracing::info!("nats: {name} authorized"),
        Err(why) => tracing::warn!("nats: connection refused ({why})"),
    }
    response(callout, user_nkey, server_id, outcome).map_err(|e| tracing::error!("cannot build the authorization response: {e}")).ok()
}

/// Subscribe to authorization requests and answer them in the background with `decider`.
/// Subscribing completes before this returns, so clients can connect right after.
pub async fn start<F, Fut>(client: Client, callout: Arc<Callout>, decider: F) -> anyhow_free::Result<()>
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Decision> + Send + 'static,
{
    let mut requests = client.queue_subscribe("$SYS.REQ.USER.AUTH", "delbert-auth".into()).await.map_err(|e| e.to_string())?;
    tracing::info!("NATS authorization callout active (account {}, sessions {}s)", callout.account, callout.session_secs);
    let decider = Arc::new(decider);
    tokio::spawn(async move {
        while let Some(msg) = requests.next().await {
            let (client, callout, decider) = (client.clone(), callout.clone(), decider.clone());
            tokio::spawn(async move {
                let Some(reply) = msg.reply.clone() else { return };
                if let Some(token) = handle(&callout, &*decider, &msg.payload).await {
                    if let Err(e) = client.publish(reply, token.into()).await {
                        tracing::warn!("cannot answer an authorization request: {e}");
                    }
                }
            });
        }
    });
    Ok(())
}

/// Tiny local `Result` alias so this crate does not need `anyhow`.
pub mod anyhow_free {
    pub type Result<T> = std::result::Result<T, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_round_trips_and_is_signed_by_the_issuer() {
        let issuer = nkeys::KeyPair::new_account();
        let token = jwt_encode(&json!({ "iss": issuer.public_key(), "nats": { "x": 1 } }), &issuer).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(B64.decode(parts[0]).unwrap(), br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
        assert_eq!(jwt_claims(&token).unwrap()["nats"]["x"], 1);
        let sig = B64.decode(parts[2]).unwrap();
        let verifier = nkeys::KeyPair::from_public_key(&issuer.public_key()).unwrap();
        assert!(verifier.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).is_ok());
        assert!(verifier.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn the_client_certificate_is_found_where_nats_puts_it() {
        let verified = json!({ "client_tls": { "verified_chains": [["LEAF", "ROOT"]] } });
        let raw = json!({ "client_tls": { "certs": ["RAW"] } });
        assert_eq!(client_certificate(&verified), Some("LEAF"));
        assert_eq!(client_certificate(&raw), Some("RAW"));
        assert_eq!(client_certificate(&json!({})), None);
    }

    #[test]
    fn agent_permissions_are_confined_to_the_agent() {
        let p = agent_permissions("acme", "agent-1");
        assert!(p.publish.iter().chain(&p.subscribe).all(|s| !s.contains('*') && s != "_INBOX.>" && !s.starts_with('$')), "{p:?}");
        assert!(p.subscribe.contains(&"_INBOX.acme.agent-1.>".to_string()));
        assert!(!p.publish.iter().any(|s| s.contains("agent-2")));
    }

    #[test]
    fn a_proxy_towards_the_core_only_touches_its_own_relay_subjects() {
        let p = proxy_hub_permissions("branch-a");
        assert!(p.publish.iter().all(|s| s.starts_with("delbert.proxy.branch-a.")), "{p:?}");
        assert!(p.subscribe.iter().all(|s| s == "delbert.notify.*.*" || s.contains("branch-a")), "{p:?}");
        assert!(!p.publish.iter().chain(&p.subscribe).any(|s| s == "_INBOX.>"));
    }

    #[test]
    fn the_response_carries_the_user_jwt_with_account_expiry_and_permissions() {
        let callout = Callout { issuer: nkeys::KeyPair::new_account(), account: "APP".into(), session_secs: 900 };
        let user = nkeys::KeyPair::new_user();
        let token = response(&callout, &user.public_key(), "SERVERID", Ok(("agent:acme/a".into(), agent_permissions("acme", "a")))).unwrap();
        let claims = jwt_claims(&token).unwrap();
        assert_eq!((claims["sub"].as_str(), claims["aud"].as_str()), (Some(user.public_key().as_str()), Some("SERVERID")));
        let inner = jwt_claims(claims["nats"]["jwt"].as_str().unwrap()).unwrap();
        assert_eq!((inner["aud"].as_str(), inner["sub"].as_str()), (Some("APP"), Some(user.public_key().as_str())));
        assert_eq!(inner["exp"].as_i64().unwrap() - inner["iat"].as_i64().unwrap(), 900);
        assert_eq!(inner["nats"]["pub"]["allow"][2], "delbert.report.acme.a");
        let denied = jwt_claims(&response(&callout, &user.public_key(), "S", Err("nope")).unwrap()).unwrap();
        assert!(denied["nats"]["jwt"].is_null() && denied["nats"]["error"] == "nope");
    }
}
