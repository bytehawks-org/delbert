//! Development probe: connects with an enrolled identity and tries things the Core's
//! NATS authorization must refuse, printing what the server answers.
//!
//!   cargo run -p delbert-agent --example probe -- <identity dir> <nats url> <other agent>

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use delbert_agent::identity::Identity;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider().install_default().ok();
    let args: Vec<String> = std::env::args().collect();
    let (dir, url, other) = (PathBuf::from(&args[1]), args[2].clone(), args[3].clone());
    let id = Identity::load(&dir)?;
    let (tenant, me) = (id.meta.tenant.clone(), id.meta.agent.clone());

    let events: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = events.clone();
    let client = async_nats::ConnectOptions::new()
        .require_tls(true)
        .add_root_certificates(id.path("ca.pem"))
        .add_client_certificate(id.path("cert.pem"), id.path("key.pem"))
        .custom_inbox_prefix(format!("_INBOX.{tenant}.{me}"))
        .event_callback(move |event| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(format!("{event}"));
            }
        })
        .connect(&url)
        .await?;
    println!("connected as {tenant}/{me}");

    // 1. Allowed: my own report subject and my own notifications.
    client.publish(format!("delbert.report.{tenant}.{me}"), "{}".into()).await?;
    client.subscribe(format!("delbert.notify.{tenant}.{me}")).await?;
    client.flush().await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("allowed actions produced {} server errors", events.lock().unwrap().iter().filter(|e| e.to_lowercase().contains("permission")).count());
    events.lock().unwrap().clear();

    // 2. Forbidden: everything about somebody else, and wildcards.
    let attempts: [(&str, String); 6] = [
        ("publish another agent's report", format!("delbert.report.{tenant}.{other}")),
        ("request another agent's policy", format!("delbert.req.{tenant}.{other}.effective")),
        ("subscribe another agent's notifications", format!("delbert.notify.{tenant}.{other}")),
        ("subscribe to all notifications", "delbert.notify.*.*".into()),
        ("subscribe to everything", ">".into()),
        ("spy on other inboxes", "_INBOX.>".into()),
    ];
    for (what, subject) in attempts {
        events.lock().unwrap().clear();
        if what.starts_with("publish") || what.starts_with("request") {
            let _ = client.publish(subject.clone(), "{}".into()).await;
        } else {
            let _ = client.subscribe(subject.clone()).await;
        }
        let _ = client.flush().await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let denied = events.lock().unwrap().iter().any(|e| e.to_lowercase().contains("permission"));
        println!("{what:<42} -> {}", if denied { "DENIED by the server" } else { "ALLOWED (!)" });
    }
    Ok(())
}
