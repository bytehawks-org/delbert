//! Delbert Core Server entry point. Configuration: environment variables, optionally layered over a
//! TOML file (`--config <file>` or `DELBERT_CONFIG`, see `config.rs`); `--check-config` validates
//! and prints the effective configuration (secrets masked) without starting anything.

use std::{fs, sync::Arc};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use delbert_core::{
    api::{AppState, router},
    config::Config,
    bus::{Bus, BusTls},
    compile::{self, Strategy},
};
use delbert_wire::Signer;
use ed25519_dalek::SigningKey;
use sqlx::postgres::PgPoolOptions;

static CONFIG: std::sync::OnceLock<Config> = std::sync::OnceLock::new();

fn var(name: &str) -> Option<String> {
    CONFIG.get().and_then(|c| c.get(name))
}

/// `--config <file>` / `--config=<file>` / `DELBERT_CONFIG`, and `--check-config`.
fn parse_args() -> anyhow::Result<(Option<String>, bool)> {
    let mut path = std::env::var("DELBERT_CONFIG").ok().filter(|v| !v.is_empty());
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--check-config" => check = true,
            "--config" => path = Some(args.next().context("--config needs a file")?),
            _ if a.starts_with("--config=") => path = Some(a["--config=".len()..].to_owned()),
            _ => anyhow::bail!("unknown argument '{a}' (usage: delbert-core [--config <file>] [--check-config])"),
        }
    }
    Ok((path, check))
}

fn load_signer() -> anyhow::Result<Option<Arc<Signer>>> {
    let (Some(path), Some(kid)) = (var("DELBERT_SIGNING_KEY_FILE"), var("DELBERT_SIGNING_KID")) else {
        tracing::warn!("DELBERT_SIGNING_KEY_FILE / DELBERT_SIGNING_KID not set: signed policies cannot be issued");
        return Ok(None);
    };
    let seed: [u8; 32] = B64
        .decode(fs::read_to_string(&path).with_context(|| format!("reading {path}"))?.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
    Ok(Some(Arc::new(Signer::new(SigningKey::from_bytes(&seed), kid))))
}

/// SIGTERM (container stop) or Ctrl-C. As PID 1 a container ignores both unless handled.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    rustls::crypto::ring::default_provider().install_default().ok();

    let (config_path, check_only) = parse_args()?;
    let config = match &config_path {
        Some(p) => Config::load(std::path::Path::new(p)).map_err(anyhow::Error::msg)?,
        None => Config::default(),
    };
    if check_only {
        print!("{}", config.effective());
        let problems = config.problems();
        problems.iter().for_each(|p| eprintln!("problem: {p}"));
        std::process::exit(if problems.is_empty() { 0 } else { 1 });
    }
    CONFIG.set(config).expect("configuration is set once");

    let database_url = var("DATABASE_URL").context("DATABASE_URL is required (environment or [database] url)")?;
    let bind = var("DELBERT_BIND").unwrap_or_else(|| "0.0.0.0:8080".into());
    let ttl_secs = var("DELBERT_POLICY_TTL_SECS").map(|v| v.parse()).transpose().context("DELBERT_POLICY_TTL_SECS")?.unwrap_or(86_400);
    let strategies = compile::parse_chain(&var("DELBERT_CONFLICT_STRATEGY").unwrap_or_else(|| "error".into())).map_err(anyhow::Error::msg)?;
    let strategies: Vec<Strategy> = strategies;

    // Schema changes happen only through migrations (crates/delbert-core/migrations),
    // run as the schema owner. The Core itself runs as a least-privilege role.
    let migrate_url = var("DATABASE_MIGRATE_URL").unwrap_or_else(|| database_url.clone());
    let migrator = PgPoolOptions::new().max_connections(1).connect(&migrate_url).await.context("connecting to the database for migrations")?;
    sqlx::migrate!().run(&migrator).await?;
    migrator.close().await;

    let pool = PgPoolOptions::new().max_connections(5).connect(&database_url).await?;
    delbert_core::auth::bootstrap_admin(&pool, var("DELBERT_BOOTSTRAP_ADMIN_PASSWORD").as_deref()).await?;

    let bus = match var("NATS_URL") {
        Some(url) => {
            // Authorization callout: the Core answers NATS' questions about who may do what.
            // It uses its own, statically authorized connection; everything else goes through the callout.
            if let Some(seed_file) = var("DELBERT_NATS_ISSUER_SEED_FILE") {
                let seed = fs::read_to_string(&seed_file).with_context(|| format!("reading {seed_file}"))?;
                let issuer = nkeys::KeyPair::from_seed(seed.trim()).map_err(|e| anyhow::anyhow!("invalid issuer seed: {e}"))?;
                let credentials = var("NATS_AUTH_USER").zip(var("NATS_AUTH_PASSWORD")).context("NATS_AUTH_USER and NATS_AUTH_PASSWORD are required with DELBERT_NATS_ISSUER_SEED_FILE")?;
                let tls = match (var("NATS_CA_FILE"), var("NATS_CLIENT_CERT_FILE"), var("NATS_CLIENT_KEY_FILE")) {
                    (Some(ca), Some(cert), Some(key)) => Some(BusTls { ca: ca.into(), cert: cert.into(), key: key.into() }),
                    _ => None,
                };
                let auth_bus = Bus::connect(&url, Some(credentials), tls).await.context("connecting the callout service to NATS")?;
                let callout = delbert_core::bus_auth::Callout {
                    issuer,
                    account: var("DELBERT_NATS_ACCOUNT").unwrap_or_else(|| "APP".into()),
                    session_secs: var("DELBERT_NATS_SESSION_SECS").map(|v| v.parse()).transpose().context("DELBERT_NATS_SESSION_SECS")?.unwrap_or(900),
                };
                delbert_core::bus_auth::start(pool.clone(), auth_bus.client().clone(), Arc::new(callout)).await?;
            } else {
                tracing::warn!("DELBERT_NATS_ISSUER_SEED_FILE not set: no authorization callout, NATS does not restrict subjects per agent");
            }
            let credentials = var("NATS_USER").zip(var("NATS_PASSWORD"));
            let tls = match (var("NATS_CA_FILE"), var("NATS_CLIENT_CERT_FILE"), var("NATS_CLIENT_KEY_FILE")) {
                (Some(ca), Some(cert), Some(key)) => Some(BusTls { ca: ca.into(), cert: cert.into(), key: key.into() }),
                _ => {
                    tracing::warn!("NATS_CA_FILE / NATS_CLIENT_CERT_FILE / NATS_CLIENT_KEY_FILE not set: connecting to NATS without TLS");
                    None
                }
            };
            Some(Bus::connect(&url, credentials, tls).await.with_context(|| format!("connecting to NATS at {url}"))?)
        }
        None => {
            tracing::warn!("NATS_URL not set: no notifications, no agent pull over the bus");
            None
        }
    };

    let pki = match (var("DELBERT_CA_CERT_FILE"), var("DELBERT_CA_KEY_FILE")) {
        (Some(cert), Some(key)) => Some(Arc::new(
            delbert_pki::Ca::load(&fs::read_to_string(&cert).with_context(|| format!("reading {cert}"))?, &fs::read_to_string(&key).with_context(|| format!("reading {key}"))?)
                .context("loading the CA")?,
        )),
        _ => {
            tracing::warn!("DELBERT_CA_CERT_FILE / DELBERT_CA_KEY_FILE not set: agent enrollment is disabled");
            None
        }
    };
    let secrets_key = match var("DELBERT_SECRETS_KEY_FILE") {
        Some(path) => {
            let text = fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
            let key = <age::x25519::Identity as std::str::FromStr>::from_str(text.trim()).map_err(|e| anyhow::anyhow!("invalid secrets key: {e}"))?;
            Some(Arc::new(key))
        }
        None => {
            tracing::warn!("DELBERT_SECRETS_KEY_FILE not set: the secret store is disabled");
            None
        }
    };
    let agent_cert_days = var("DELBERT_AGENT_CERT_DAYS").map(|v| v.parse()).transpose().context("DELBERT_AGENT_CERT_DAYS")?.unwrap_or(365);

    let blobs = match var("DELBERT_ARTIFACT_STORE").as_deref().unwrap_or("local") {
        "local" => {
            let dir = var("DELBERT_ARTIFACT_DIR").unwrap_or_else(|| "./data/artifacts".into());
            tracing::info!("artifact store: local directory {dir}");
            delbert_core::blobs::Blobs::local(dir)?
        }
        "s3" => {
            let need = |k: &str| var(k).with_context(|| format!("{k} is required with DELBERT_ARTIFACT_STORE=s3"));
            let secret_key = match var("DELBERT_S3_SECRET_KEY_FILE") {
                Some(f) => fs::read_to_string(&f).with_context(|| format!("reading {f}"))?.trim().to_owned(),
                None => need("DELBERT_S3_SECRET_KEY")?,
            };
            let blobs = delbert_core::blobs::Blobs::s3(delbert_core::blobs::S3Config {
                endpoint: need("DELBERT_S3_ENDPOINT")?,
                bucket: need("DELBERT_S3_BUCKET")?,
                region: var("DELBERT_S3_REGION").unwrap_or_else(|| "garage".into()),
                access_key: need("DELBERT_S3_ACCESS_KEY")?,
                secret_key,
            })?;
            blobs.probe().await.context("the S3 artifact store is not reachable with these settings")?;
            tracing::info!("artifact store: S3-compatible");
            blobs
        }
        other => anyhow::bail!("DELBERT_ARTIFACT_STORE must be 'local' or 's3', not '{other}'"),
    };

    let state = AppState { pool, signer: load_signer()?, ttl_secs, strategies: Arc::new(strategies), bus, docs: var("DELBERT_API_DOCS").as_deref() != Some("false"), secrets_key, pki, agent_cert_days, public_nats_url: var("DELBERT_PUBLIC_NATS_URL"), approval_default: var("DELBERT_APPROVAL_DEFAULT").as_deref() == Some("true"), blobs, content: delbert_core::api::ContentConfig {
        dir: var("DELBERT_CONTENT_DIR").unwrap_or_else(|| "./data/content".into()).into(),
        allow_tenant_git: var("DELBERT_CONTENT_ALLOW_TENANT_GIT").as_deref() == Some("true"),
        allow_file: var("DELBERT_CONTENT_ALLOW_FILE").as_deref() == Some("true"),
        poll: var("DELBERT_CONTENT_POLL").as_deref() != Some("false"),
    }, auth: delbert_core::api::AuthConfig {
        cookie_secure: var("DELBERT_COOKIE_INSECURE").as_deref() != Some("true"),
        trust_forwarded: var("DELBERT_TRUST_FORWARDED").as_deref() == Some("true"),
        mfa: match var("DELBERT_MFA_REQUIRED").as_deref().unwrap_or("none") {
            "none" => delbert_core::api::MfaPolicy::Optional,
            "admins" => delbert_core::api::MfaPolicy::Admins,
            "all" => delbert_core::api::MfaPolicy::All,
            other => anyhow::bail!("DELBERT_MFA_REQUIRED must be none, admins or all, not '{other}'"),
        },
        public_url: var("DELBERT_PUBLIC_URL"),
        ui_url: var("DELBERT_UI_URL"),
        local_login: match var("DELBERT_LOCAL_LOGIN").as_deref().unwrap_or("all") {
            "all" => delbert_core::api::LocalLogin::All,
            "admins" => delbert_core::api::LocalLogin::Admins,
            other => anyhow::bail!("DELBERT_LOCAL_LOGIN must be all or admins, not '{other}'"),
        },
    } };
    if state.content.poll {
        tokio::spawn(delbert_core::content::poller(state.clone()));
    }
    if state.bus.is_some() {
        tokio::spawn(delbert_core::bus::serve(state.clone()));
    }
    let app = router(state);
    match (var("DELBERT_TLS_CERT_FILE"), var("DELBERT_TLS_KEY_FILE")) {
        (Some(cert), Some(key)) => {
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await.context("loading the API TLS certificate")?;
            let handle = axum_server::Handle::<std::net::SocketAddr>::new();
            let h = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                h.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            });
            tracing::info!("delbert-core listening on {bind} (HTTPS)");
            let addr: std::net::SocketAddr = bind.parse().context("DELBERT_BIND must be host:port with an IP address")?;
            axum_server::bind_rustls(addr, config).handle(handle).serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
        }
        _ => {
            tracing::warn!("DELBERT_TLS_CERT_FILE / DELBERT_TLS_KEY_FILE not set: serving plain HTTP (development only)");
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!("delbert-core listening on {bind}");
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).with_graceful_shutdown(shutdown_signal()).await?;
        }
    }
    tracing::info!("shut down");
    Ok(())
}
