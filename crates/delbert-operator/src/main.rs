//! `delbert-operator`: `crd` prints the CustomResourceDefinition, `run` starts the controller.

use std::{sync::Arc, time::Duration};

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use delbert_operator::{core::CoreClient, identity, reconcile};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client, CustomResourceExt,
    runtime::{Controller, watcher},
};

const NAMESPACE_FILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

#[derive(Parser)]
#[command(
    name = "delbert-operator",
    version,
    about = "Delbert Kubernetes Operator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the DelbertBinding CustomResourceDefinition (YAML).
    Crd,
    /// Run the controller.
    Run(Run),
}

#[derive(clap::Args)]
struct Run {
    /// HTTPS URL of the Core.
    #[arg(long, env = "DELBERT_CORE_URL")]
    core_url: String,
    /// Delbert CA (PEM): the only trust anchor for the Core.
    #[arg(long, env = "DELBERT_CA_FILE")]
    ca_file: std::path::PathBuf,
    /// Enrollment key: needed for the first start only, ignored once the identity secret exists.
    #[arg(long, env = "DELBERT_ENROLL_PSK", hide_env_values = true)]
    enroll_psk: Option<String>,
    /// Name this Operator takes in the Core when it enrolls.
    #[arg(long, env = "DELBERT_OPERATOR_NAME")]
    name: String,
    /// Namespace holding the identity secret (default: the pod's own).
    #[arg(long, env = "DELBERT_NAMESPACE")]
    namespace: Option<String>,
    #[arg(
        long,
        env = "DELBERT_IDENTITY_SECRET",
        default_value = "delbert-operator-identity"
    )]
    identity_secret: String,
    /// Seconds between two passes over each binding.
    #[arg(long, env = "DELBERT_RESYNC_SECS", default_value_t = 60)]
    resync_secs: u64,
}

async fn run(args: Run) -> Result<()> {
    let ca = std::fs::read(&args.ca_file)
        .with_context(|| format!("reading {}", args.ca_file.display()))?;
    let http = reqwest::Client::builder()
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(&ca).context("invalid CA file")?)
        .build()?;
    let client = Client::try_default()
        .await
        .context("no Kubernetes configuration")?;
    let namespace = match args.namespace {
        Some(ns) => ns,
        None => std::fs::read_to_string(NAMESPACE_FILE)
            .context("not running in a pod: set DELBERT_NAMESPACE")?
            .trim()
            .to_owned(),
    };

    let secrets: Api<Secret> = Api::namespaced(client.clone(), &namespace);
    let identity = identity::load_or_enroll(
        &secrets,
        &args.identity_secret,
        &http,
        &args.core_url,
        args.enroll_psk.as_deref(),
        &args.name,
    )
    .await?;
    tracing::info!(tenant = %identity.tenant, agent = %identity.agent, "operator identity ready");

    let ctx = Arc::new(reconcile::Context {
        client: client.clone(),
        core: CoreClient::new(http, &args.core_url),
        identity,
        resync: Duration::from_secs(args.resync_secs.max(10)),
    });
    Controller::new(
        Api::<delbert_operator::crd::DelbertBinding>::all(client),
        watcher::Config::default(),
    )
    .shutdown_on_signal()
    .run(reconcile::reconcile, reconcile::error_policy, ctx)
    .for_each(|result| async move {
        if let Err(e) = result {
            tracing::warn!("controller: {e}");
        }
    })
    .await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Cli::parse().command {
        Command::Crd => {
            print!(
                "{}",
                serde_yaml_ng::to_string(&delbert_operator::crd::DelbertBinding::crd())?
            );
            Ok(())
        }
        Command::Run(args) => run(args).await,
    }
}
