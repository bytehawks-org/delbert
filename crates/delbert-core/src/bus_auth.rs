//! The Core's side of the NATS authorization callout (docs/ABSTRACT.md §2).
//!
//! NATS authenticates every client with mutual TLS and asks the Core what each may do. The
//! Core reads the identity from the certificate, checks that it is still the one on record
//! (so deleted, key-rotated or unknown agents and proxies are refused) and answers with a
//! short-lived user JWT whose permissions confine the connection to its own subjects (see
//! `delbert-natsauth` for the table). Sessions expire; NATS disconnects the client then and
//! the next connection goes through the callout again, which is how revocation takes effect
//! on connections that are already open.

use std::sync::Arc;

use async_nats::Client;
use delbert_natsauth::{DENIED, Decision};
use delbert_pki::CertIdentity;
use sqlx::PgPool;

pub use delbert_natsauth::{Callout, Permissions, agent_permissions, core_permissions, proxy_hub_permissions};

/// What a connection presenting this certificate may do.
pub async fn decide(pool: &PgPool, cert_pem: &str) -> Decision {
    let identity = delbert_pki::identity_from_pem(cert_pem).map_err(|_| DENIED)?;
    let db_error = |e: sqlx::Error| {
        tracing::error!("callout lookup failed: {e}");
        DENIED
    };
    match identity {
        CertIdentity::Agent { tenant, agent, public_key } => {
            // The certificate must carry the key on record (the current one, or the previous one
            // while a renewal is being confirmed); deleted or rotated agents are refused.
            let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
                "SELECT a.public_key, a.previous_public_key FROM agents a JOIN tenants t ON t.id = a.tenant_id WHERE t.name = $1 AND a.name = $2",
            )
            .bind(&tenant)
            .bind(&agent)
            .fetch_optional(pool)
            .await
            .map_err(db_error)?;
            let (current, previous) = row.ok_or(DENIED)?;
            if current.as_deref() == Some(public_key.as_slice()) || previous.as_deref() == Some(public_key.as_slice()) {
                Ok((format!("agent:{tenant}/{agent}"), agent_permissions(&tenant, &agent)))
            } else {
                Err(DENIED)
            }
        }
        CertIdentity::Component { name } if name == "core-nats" => Ok(("core".into(), core_permissions())),
        CertIdentity::Component { name } => match name.strip_prefix("proxy:") {
            Some(site) => {
                // The certificate must carry the key enrolled for this proxy.
                let key = delbert_pki::public_key_from_pem(cert_pem).ok_or(DENIED)?;
                let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as("SELECT public_key, previous_public_key FROM proxies WHERE name = $1").bind(site).fetch_optional(pool).await.map_err(db_error)?;
                let (current, previous) = row.ok_or(DENIED)?;
                if current.as_deref() == Some(key.as_slice()) || previous.as_deref() == Some(key.as_slice()) { Ok((format!("proxy:{site}"), proxy_hub_permissions(site))) } else { Err(DENIED) }
            }
            None => Err(DENIED),
        },
    }
}

/// Subscribe to authorization requests and answer them in the background.
pub async fn start(pool: PgPool, client: Client, callout: Arc<Callout>) -> anyhow::Result<()> {
    delbert_natsauth::start(client, callout, move |cert| {
        let pool = pool.clone();
        async move { decide(&pool, &cert).await }
    })
    .await
    .map_err(anyhow::Error::msg)
}
