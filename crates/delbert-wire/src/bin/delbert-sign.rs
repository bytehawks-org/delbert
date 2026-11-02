//! `delbert-sign`: key generation and offline policy signing.
//!
//! This is the tool for the `external` signing mode (docs/ABSTRACT.md §3): run it
//! on an admin workstation (or behind an HSM wrapper) so that the signing key
//! never lives on the Core.

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use clap::{Parser, Subcommand};
use delbert_wire::{EffectivePolicy, SCHEMA, Signer};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

#[derive(Parser)]
#[command(name = "delbert-sign", version, about = "Delbert policy signing tool")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a key pair: <dir>/<kid>.key (private, 0600) and <dir>/<kid>.pub.
    Keygen {
        kid: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Compile a policy YAML for one agent and print the signed token (JWS).
    Sign {
        policy: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        kid: String,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        version: u64,
        /// Validity in seconds from now.
        #[arg(long, default_value_t = 86_400)]
        ttl_secs: i64,
    },
    /// Check a copy of the audit anchors (NDJSON) offline: signatures, order and, with an export
    /// of the audit trail, that each anchor matches the event at its position. Exit 3 on a problem.
    VerifyAnchors {
        /// NDJSON anchors: the file the Core appends to (`DELBERT_AUDIT_ANCHOR_FILE`) or the collected log lines.
        anchors: PathBuf,
        /// Trusted keys file (`<kid> <base64 public key>` per line), as for agents.
        #[arg(long)]
        trusted_keys: PathBuf,
        /// NDJSON export of the audit trail (`GET /v1/audit/export`).
        #[arg(long)]
        audit_export: Option<PathBuf>,
    },
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Cmd::Keygen { kid, dir } => {
            let key = SigningKey::generate(&mut OsRng);
            let (private, public) = (dir.join(format!("{kid}.key")), dir.join(format!("{kid}.pub")));
            if private.exists() || public.exists() {
                bail!("refusing to overwrite an existing key");
            }
            let public_b64 = B64.encode(key.verifying_key().to_bytes());
            fs::write(&private, B64.encode(key.to_bytes()))?;
            fs::set_permissions(&private, fs::Permissions::from_mode(0o600))?;
            fs::write(&public, &public_b64)?;
            // Line to put in the agent's trusted keys file.
            println!("{kid} {public_b64}");
        }
        Cmd::Sign { policy, key, kid, agent, version, ttl_secs } => {
            let seed: [u8; 32] = B64
                .decode(fs::read_to_string(&key).with_context(|| format!("reading {}", key.display()))?.trim())?
                .try_into()
                .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?;
            let parsed = delbert_policy::from_yaml(&fs::read_to_string(&policy)?)?;
            let issued_at = now();
            let effective = EffectivePolicy {
                schema: SCHEMA.into(),
                tenant: parsed.metadata.tenant,
                agent,
                name: parsed.metadata.name,
                version,
                issued_at,
                expires_at: issued_at + ttl_secs,
                vars: parsed.spec.vars,
                artifacts: Default::default(),
                secrets: Default::default(),
                resources: parsed.spec.resources,
                trust: None,
                force: None,
            };
            println!("{}", Signer::new(SigningKey::from_bytes(&seed), kid).sign(&effective)?);
        }
        Cmd::VerifyAnchors { anchors, trusted_keys, audit_export } => {
            let keys = delbert_wire::Verifier::from_trusted_keys(&fs::read_to_string(&trusted_keys).with_context(|| format!("reading {}", trusted_keys.display()))?)?;
            let export = audit_export.map(|p| fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))).transpose()?;
            let (checked, problems) = delbert_wire::anchor::check(&keys, &fs::read_to_string(&anchors).with_context(|| format!("reading {}", anchors.display()))?, export.as_deref());
            for p in &problems {
                eprintln!("PROBLEM: {p}");
            }
            if checked == 0 && problems.is_empty() {
                eprintln!("no anchors in {}", anchors.display());
                std::process::exit(3);
            }
            if !problems.is_empty() {
                std::process::exit(3);
            }
            println!("{checked} anchors verified");
        }
    }
    Ok(())
}
