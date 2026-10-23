//! `delbert-proxy`: enrollment and the long-running relay of a branch office.

use std::{fs, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use delbert_natsauth::Callout;
use delbert_proxy::{
    allowlist::AllowList,
    hub::{Hub, ProofMaker},
    identity::{self, Identity},
    queue::ReportQueue,
    relay::Relay,
    web::{self, Web},
};

#[derive(Parser)]
#[command(name = "delbert-proxy", version, about = "Delbert Proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct EnrollArgs {
    /// HTTPS URL of the Core.
    #[arg(long, env = "DELBERT_CORE_URL")]
    core_url: String,
    /// Delbert CA certificate (PEM).
    #[arg(long, env = "DELBERT_CA_FILE")]
    ca_file: PathBuf,
    /// Enrollment key created with `POST /v1/proxies`.
    #[arg(long, env = "DELBERT_ENROLL_PSK", hide_env_values = true)]
    psk: String,
    /// Site name of this proxy.
    #[arg(long, env = "DELBERT_SITE")]
    site: String,
    #[arg(long, env = "DELBERT_IDENTITY_DIR", default_value = "/var/lib/delbert-proxy/identity")]
    identity_dir: PathBuf,
}

#[derive(Args)]
struct RunArgs {
    #[arg(long, env = "DELBERT_IDENTITY_DIR", default_value = "/var/lib/delbert-proxy/identity")]
    identity_dir: PathBuf,
    /// Allow-list, report queue and caches.
    #[arg(long, env = "DELBERT_STATE_DIR", default_value = "/var/lib/delbert-proxy")]
    state_dir: PathBuf,
    /// Overrides the Core's NATS URL received at enrollment.
    #[arg(long, env = "DELBERT_HUB_NATS_URL")]
    hub_nats_url: Option<String>,
    /// NATS server of this site, as the proxy reaches it.
    #[arg(long, env = "DELBERT_LOCAL_NATS_URL")]
    local_nats_url: String,
    /// Static user of the site's NATS for the callout service.
    #[arg(long, env = "DELBERT_LOCAL_AUTH_USER", default_value = "auth")]
    local_auth_user: String,
    #[arg(long, env = "DELBERT_LOCAL_AUTH_PASSWORD", hide_env_values = true)]
    local_auth_password: String,
    /// NATS URL that agents of the site are told to use.
    #[arg(long, env = "DELBERT_PUBLIC_NATS_URL")]
    public_nats_url: String,
    /// NATS account of the site that agents are placed in.
    #[arg(long, env = "DELBERT_LOCAL_NATS_ACCOUNT", default_value = "APP")]
    local_account: String,
    #[arg(long, env = "DELBERT_LISTEN", default_value = "0.0.0.0:8443")]
    listen: std::net::SocketAddr,
    /// Seconds between agent-list synchronizations (besides Core hints).
    #[arg(long, env = "DELBERT_SYNC_SECS", default_value_t = 30)]
    sync_secs: u64,
    /// Seconds between attempts to forward queued reports.
    #[arg(long, env = "DELBERT_FLUSH_SECS", default_value_t = 10)]
    flush_secs: u64,
    /// How long a connection to the site's NATS lives before being authorized again.
    #[arg(long, env = "DELBERT_LOCAL_SESSION_SECS", default_value_t = 900)]
    session_secs: i64,
    /// Renew the certificate when less than this many seconds remain (default: a third of its lifetime).
    #[arg(long, env = "DELBERT_RENEW_BEFORE_SECS")]
    renew_before_secs: Option<i64>,
    /// Seconds between checks whether the certificate is due for renewal.
    #[arg(long, env = "DELBERT_RENEW_CHECK_SECS", default_value_t = 3600)]
    renew_check_secs: u64,
}

#[derive(Subcommand)]
enum Command {
    /// Create this proxy's identity with the one-time key from the Core.
    Enroll(EnrollArgs),
    /// Run the relay.
    Run(RunArgs),
}

fn tls_files(id: &Identity) -> (PathBuf, PathBuf, PathBuf) {
    (id.path("ca.pem"), id.path("cert.pem"), id.path("key.pem"))
}

async fn run(a: RunArgs) -> Result<()> {
    identity::recover(&a.identity_dir)?; // finish an interrupted renewal first
    let id = Identity::load(&a.identity_dir)?;
    fs::create_dir_all(&a.state_dir)?;
    let own_key = delbert_pki::public_key_from_pem(&id.cert_pem()?).context("unreadable proxy certificate")?;
    let allow = AllowList::load(a.state_dir.join("agents.json"), &id.meta.site, own_key);
    tracing::info!("proxy {} starting, {} agents in the allow-list", id.meta.site, allow.len());

    // 1. The site's NATS asks this process who may connect (authorization callout).
    let (ca, cert, key) = tls_files(&id);
    let auth_client = async_nats::ConnectOptions::with_user_and_password(a.local_auth_user.clone(), a.local_auth_password.clone())
        .require_tls(true)
        .add_root_certificates(ca.clone())
        .add_client_certificate(cert.clone(), key.clone())
        .retry_on_initial_connect()
        .connect(&a.local_nats_url)
        .await
        .context("connecting the callout service to the site's NATS")?;
    let callout = Callout { issuer: id.local_issuer()?, account: a.local_account.clone(), session_secs: a.session_secs };
    let decider_list = allow.clone();
    delbert_natsauth::start(auth_client, Arc::new(callout), move |cert| {
        let list = decider_list.clone();
        async move { list.decide(&cert) }
    })
    .await
    .map_err(anyhow::Error::msg)?;

    // 2. The relay connects to the site's NATS (through that callout) and to the Core.
    let local = async_nats::ConnectOptions::new()
        .require_tls(true)
        .add_root_certificates(ca.clone())
        .add_client_certificate(cert.clone(), key.clone())
        .ping_interval(Duration::from_secs(10))
        .retry_on_initial_connect()
        .connect(&a.local_nats_url)
        .await
        .context("connecting to the site's NATS")?;
    let hub_url = a.hub_nats_url.clone().or_else(|| id.meta.hub_nats_url.clone()).context("no NATS URL of the Core: enroll against a Core that publishes one or pass --hub-nats-url")?;
    let hub = Hub::connect(&id, &hub_url).await?;
    let relay = Relay::new(id.meta.site.clone(), hub, local, allow.clone(), ReportQueue::new(a.state_dir.join("reports"))?, a.state_dir.join("policies"))?;

    // 3. HTTPS for the agents: enrollment relay and artifact cache. Same certificate, also valid for servers.
    let ca_pem = fs::read(&ca)?;
    let web = Arc::new(Web {
        core_url: id.meta.core_url.clone(),
        site: id.meta.site.clone(),
        http: reqwest::Client::builder().tls_certs_only(reqwest::Certificate::from_pem_bundle(&ca_pem)?).timeout(Duration::from_secs(120)).build()?,
        proofs: ProofMaker::new(&id)?,
        allow,
        public_nats_url: a.public_nats_url.clone(),
        artifact_dir: a.state_dir.join("artifacts"),
    });
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key).await.context("loading the proxy certificate")?;
    let handle = axum_server::Handle::<std::net::SocketAddr>::new();
    let h = handle.clone();
    let relay_task = tokio::spawn(relay.run(Duration::from_secs(a.sync_secs), Duration::from_secs(a.flush_secs)));
    // Certificate renewal. A new key means new connections everywhere, so after installing it the
    // proxy stops cleanly and its supervisor (systemd, the container runtime, Kubernetes) restarts it;
    // the site's NATS server, which shares the certificate files, is restarted or reloaded with it.
    let (renew_id, renew_handle) = (id.clone(), handle.clone());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(a.renew_check_secs));
        loop {
            tick.tick().await;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
            let due = renew_id.cert_pem().is_ok_and(|c| identity::renewal_due(&c, now, a.renew_before_secs));
            if !due {
                continue;
            }
            match identity::renew(&renew_id).await {
                Ok(()) => {
                    tracing::info!("certificate renewed with a new key; restarting to use it");
                    renew_handle.graceful_shutdown(Some(Duration::from_secs(10)));
                    return;
                }
                Err(e) => tracing::warn!("certificate renewal failed (will retry): {e:#}"),
            }
        }
    });
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
        h.graceful_shutdown(Some(Duration::from_secs(10)));
    });
    tracing::info!("HTTPS for agents on {}", a.listen);
    axum_server::bind_rustls(a.listen, tls).handle(handle).serve(web::router(web).into_make_service()).await?;
    relay_task.abort();
    tracing::info!("stopped");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider().install_default().ok();
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    match Cli::parse().command {
        Command::Enroll(a) => {
            let id = identity::enroll(identity::EnrollArgs { core_url: a.core_url, ca_file: a.ca_file, psk: a.psk, site: a.site, identity_dir: a.identity_dir }).await?;
            println!("enrolled proxy '{}'; identity in {}", id.meta.site, id.dir.display());
            println!("NATS issuer public key for the site's NATS server: {}", fs::read_to_string(id.path("local-issuer.pub"))?);
        }
        Command::Run(a) => run(a).await?,
    }
    Ok(())
}
