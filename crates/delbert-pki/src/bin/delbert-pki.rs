//! `delbert-pki`: administrator tool for the internal CA.
//!
//! Creates the CA and issues the certificates of the infrastructure components
//! (NATS server, Core client, Core HTTPS). Agent certificates are issued by the
//! Core at enrollment, never with this tool.

use std::{fs, path::{Path, PathBuf}};

use clap::{Parser, Subcommand};
use delbert_pki::{CertificateAuthority, RcgenCa};

#[derive(Parser)]
#[command(name = "delbert-pki", version, about = "Delbert internal CA tool")]
struct Cli {
    /// Directory holding ca.pem and ca.key.
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the CA (ca.pem, ca.key with mode 0600).
    Init {
        #[arg(long, default_value = "Delbert CA")]
        name: String,
        #[arg(long, default_value_t = 3650)]
        days: i64,
    },
    /// Issue a server certificate: <name>.pem / <name>.key.
    IssueServer {
        name: String,
        /// DNS names (repeat the flag).
        #[arg(long = "dns", required = true)]
        dns: Vec<String>,
        #[arg(long, default_value_t = 365)]
        days: i64,
    },
    /// Generate the NATS authorization-callout issuer (nats-issuer.seed 0600, nats-issuer.pub).
    NatsIssuer,
    /// Generate the Core's secrets key (age identity) at <dir>/secrets.key, mode 0600.
    SecretsKey,
    /// Issue a client certificate for a component, e.g. the Core: <name>.pem / <name>.key.
    IssueClient {
        name: String,
        #[arg(long, default_value_t = 365)]
        days: i64,
    },
}

fn write(path: &Path, data: &str, private: bool) -> anyhow::Result<()> {
    if path.exists() {
        anyhow::bail!("refusing to overwrite {}", path.display());
    }
    // Private keys are 0600; in development containers may need 0644 (see docs/TESTING.md).
    delbert_fs::replace_file(path, data.as_bytes(), if private { 0o600 } else { 0o644 }, None, None)?;
    println!("wrote {}", path.display());
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let (cert, key) = (cli.dir.join("ca.pem"), cli.dir.join("ca.key"));
    let load = || -> anyhow::Result<RcgenCa> { Ok(RcgenCa::load(&fs::read_to_string(&cert)?, &fs::read_to_string(&key)?)?) };
    match cli.command {
        Cmd::Init { name, days } => {
            let ca = RcgenCa::create(&name, days)?;
            write(&cert, ca.cert_pem(), false)?;
            write(&key, ca.key_pem(), true)?;
        }
        Cmd::IssueServer { name, dns, days } => {
            let issued = load()?.issue_server(&name, &dns, days)?;
            write(&cli.dir.join(format!("{name}.pem")), &issued.cert_pem, false)?;
            write(&cli.dir.join(format!("{name}.key")), &issued.key_pem, true)?;
        }
        Cmd::NatsIssuer => {
            let pair = nkeys::KeyPair::new_account();
            write(&cli.dir.join("nats-issuer.seed"), &pair.seed()?, true)?;
            write(&cli.dir.join("nats-issuer.pub"), &pair.public_key(), false)?;
        }
        Cmd::SecretsKey => {
            use age::secrecy::ExposeSecret;
            write(&cli.dir.join("secrets.key"), age::x25519::Identity::generate().to_string().expose_secret(), true)?;
        }
        Cmd::IssueClient { name, days } => {
            let issued = load()?.issue_client(&name, &format!("urn:delbert:component:{name}"), days)?;
            write(&cli.dir.join(format!("{name}.pem")), &issued.cert_pem, false)?;
            write(&cli.dir.join(format!("{name}.key")), &issued.key_pem, true)?;
        }
    }
    Ok(())
}
