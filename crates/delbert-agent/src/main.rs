//! Delbert Agent CLI (early skeleton).
//!
//! `check` / `apply` run a policy YAML locally (development and testing only).
//! `check-signed` / `apply-signed` accept only signed effective policies, which
//! is how the agent will receive policies from the Core in production.

use std::{collections::BTreeMap, fs, path::PathBuf, process::ExitCode};

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use delbert_agent::{Ctx, Mode, Report, Status, run, state::State};
use delbert_policy::Resource;
use delbert_wire::{Expect, Verifier};

// Default locations: FHS on Unix; `C:\ProgramData\Delbert` on Windows (the installer and
// `service install` make that directory private to SYSTEM and Administrators).
#[cfg(not(windows))]
const IDENTITY_DIR: &str = "/var/lib/delbert/identity";
#[cfg(not(windows))]
const STATE_DIR: &str = "/var/lib/delbert";
#[cfg(not(windows))]
const FACTS_DIR: &str = "/etc/delbert/facts.d";
#[cfg(windows)]
const IDENTITY_DIR: &str = r"C:\ProgramData\Delbert\identity";
#[cfg(windows)]
const STATE_DIR: &str = r"C:\ProgramData\Delbert";
#[cfg(windows)]
const FACTS_DIR: &str = r"C:\ProgramData\Delbert\facts.d";

#[derive(Parser)]
#[command(name = "delbert-agent", version, about = "Delbert Agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct HostArgs {
    /// Directory with the artifacts referenced as artifact://<name>.
    #[arg(long, default_value = "artifacts")]
    artifacts: PathBuf,
    /// Treat this directory as `/` (sandbox for experiments and tests).
    #[arg(long, default_value = "/")]
    root: PathBuf,
}

#[derive(Args)]
struct RunArgs {
    /// Policy YAML file (development only).
    file: PathBuf,
    #[command(flatten)]
    host: HostArgs,
}

#[derive(Args)]
struct SignedArgs {
    /// File containing the signed policy token (JWS).
    token: PathBuf,
    /// Trusted signing keys: lines of `<kid> <base64 public key>`.
    #[arg(long)]
    trusted_keys: PathBuf,
    #[arg(long)]
    agent_id: String,
    #[arg(long)]
    tenant: String,
    /// Local state file (anti-rollback).
    #[arg(long, default_value = "delbert-state.json")]
    state: PathBuf,
    #[command(flatten)]
    host: HostArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Parse and validate a policy YAML file.
    Validate { file: PathBuf },
    /// Print the JSON Schema of the policy format.
    Schema,
    /// Report drift from a policy YAML without changing anything (exit 2 if drift).
    Check(RunArgs),
    /// Converge the host to a policy YAML, then verify.
    Apply(RunArgs),
    /// Verify a signed policy, then report drift.
    CheckSigned(SignedArgs),
    /// Verify a signed policy, then converge.
    ApplySigned(SignedArgs),
    /// Create this host's identity (keys, certificate) with an enrollment key.
    Enroll(EnrollCmdArgs),
    /// Run as a daemon: pull signed policies over NATS, apply, report.
    Run(DaemonArgs),
    /// Windows Service management (docs/WINDOWS.md).
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
}

#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceCmd {
    /// Register the agent as an automatic Windows Service (run as Administrator). With the four
    /// enrollment options it also enrolls and starts the service; the key is not stored anywhere.
    Install {
        #[arg(long, env = "DELBERT_CORE_URL", requires_all = ["ca_file", "psk", "agent_id"])]
        core_url: Option<String>,
        #[arg(long, env = "DELBERT_CA_FILE")]
        ca_file: Option<PathBuf>,
        #[arg(long, env = "DELBERT_ENROLL_PSK", hide_env_values = true)]
        psk: Option<String>,
        #[arg(long, env = "DELBERT_AGENT_ID")]
        agent_id: Option<String>,
    },
    /// Stop and remove the service; the data directory (identity included) is kept.
    Uninstall,
    /// Entry point used by the Service Control Manager (not for interactive use).
    #[command(hide = true)]
    Run,
}

#[derive(Args)]
struct DaemonArgs {
    /// Enrolled identity (created by `enroll`).
    #[arg(long, env = "DELBERT_IDENTITY_DIR", default_value = IDENTITY_DIR)]
    identity_dir: PathBuf,
    /// Overrides the NATS URL received at enrollment.
    #[arg(long, env = "DELBERT_NATS_URL")]
    nats_url: Option<String>,
    /// Directory for anti-rollback state and the cached policy.
    #[arg(long, env = "DELBERT_STATE_DIR", default_value = STATE_DIR)]
    state_dir: PathBuf,
    /// Seconds between cycles when no notification arrives.
    #[arg(long, env = "DELBERT_INTERVAL_SECS", default_value_t = 300)]
    interval_secs: u64,
    #[arg(long, default_value = "artifacts")]
    artifacts: PathBuf,
    #[arg(long, default_value = "/")]
    root: PathBuf,
    /// Renew the certificate when less than this many seconds remain (default: a third of its lifetime).
    #[arg(long, env = "DELBERT_RENEW_BEFORE_SECS")]
    renew_before_secs: Option<i64>,
    /// Directory of custom facts (YAML/JSON files); they stay on this host.
    #[arg(long, env = "DELBERT_FACTS_DIR", default_value = FACTS_DIR)]
    facts_dir: PathBuf,
    /// The host facts (OS, kernel, hostname, addresses) are sent to the Core when they change and at least this often (minimum 60).
    #[arg(long, env = "DELBERT_FACTS_INTERVAL_SECS", default_value_t = 900)]
    facts_interval_secs: u64,
    // Unattended installs: if there is no identity yet, enroll with these first.
    #[arg(long, env = "DELBERT_CORE_URL")]
    core_url: Option<String>,
    #[arg(long, env = "DELBERT_CA_FILE")]
    ca_file: Option<PathBuf>,
    #[arg(long, env = "DELBERT_ENROLL_PSK", hide_env_values = true)]
    psk: Option<String>,
    #[arg(long, env = "DELBERT_AGENT_ID")]
    agent_id: Option<String>,
}

#[derive(Args)]
struct EnrollCmdArgs {
    /// HTTPS URL of the Core, e.g. https://core.example.com:8080
    #[arg(long, env = "DELBERT_CORE_URL")]
    core_url: String,
    /// Delbert CA certificate (PEM) shipped with the installer.
    #[arg(long, env = "DELBERT_CA_FILE")]
    ca_file: PathBuf,
    /// Enrollment key created by an administrator.
    #[arg(long, env = "DELBERT_ENROLL_PSK", hide_env_values = true)]
    psk: String,
    /// Name of this agent (letters, digits, - _).
    #[arg(long, env = "DELBERT_AGENT_ID")]
    agent_id: String,
    #[arg(long, env = "DELBERT_IDENTITY_DIR", default_value = IDENTITY_DIR)]
    identity_dir: PathBuf,
}

fn load(file: &PathBuf) -> anyhow::Result<delbert_policy::Policy> {
    let text = fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    Ok(delbert_policy::from_yaml(&text)?)
}

fn print(report: &Report) {
    for r in &report.resources {
        let (label, detail) = match &r.status {
            Status::Compliant => ("ok", String::new()),
            Status::Drifted(d) => ("drift", d.join(", ")),
            Status::Changed(d) => ("changed", d.join(", ")),
            Status::Idle => ("idle", String::new()),
            Status::Unsupported(m) => ("unsupported", m.clone()),
            Status::Skipped(m) => ("skipped", m.clone()),
            Status::NotApplicable(m) => ("n/a", m.clone()),
            Status::Failed(m) => ("FAILED", m.clone()),
        };
        println!("{label:<12} {:<24} {detail}", r.id);
    }
}

fn execute(resources: &[Resource], vars: BTreeMap<String, serde_json::Value>, host: HostArgs, mode: Mode) -> ExitCode {
    let mut ctx = Ctx::new(host.root, host.artifacts);
    ctx.vars = vars;
    let report = run(resources, &ctx, mode);
    print(&report);
    if report.has_failures() {
        ExitCode::from(1)
    } else if report.has_drift() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn execute_signed(args: SignedArgs, mode: Mode) -> anyhow::Result<ExitCode> {
    let verifier = Verifier::from_trusted_keys(&fs::read_to_string(&args.trusted_keys).context("reading trusted keys")?)?;
    let token = fs::read_to_string(&args.token).with_context(|| format!("reading {}", args.token.display()))?;
    let mut state = State::load(&args.state)?;

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
    let expect = Expect { tenant: &args.tenant, agent: &args.agent_id, now };
    let policy = match verifier.verify(&token, &expect, |name| state.versions.get(name).copied()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("REJECTED: {e}");
            return Ok(ExitCode::from(3));
        }
    };

    println!("verified: policy '{}' v{} for agent '{}'", policy.name, policy.version, policy.agent);
    if mode == Mode::Apply {
        state.versions.insert(policy.name.clone(), policy.version);
        state.save(&args.state)?;
    }
    Ok(execute(&policy.resources, policy.vars.clone(), args.host, mode))
}

/// The daemon: load the identity (enrolling first on an unattended install), then run until stopped.
async fn daemon(a: DaemonArgs) -> anyhow::Result<()> {
    let identity = match delbert_agent::identity::Identity::load(&a.identity_dir) {
        Ok(id) => id,
        Err(load_error) => match (a.core_url, a.ca_file, a.psk, a.agent_id) {
            (Some(core_url), Some(ca_file), Some(psk), Some(agent_name)) => {
                tracing::info!("no identity yet: enrolling as {agent_name}");
                delbert_agent::identity::enroll(delbert_agent::identity::EnrollArgs { core_url, ca_file, psk, agent_name, identity_dir: a.identity_dir.clone() }).await?
            }
            _ => return Err(load_error),
        },
    };
    delbert_agent::daemon::run_daemon(delbert_agent::daemon::DaemonConfig {
        identity,
        nats_url: a.nats_url,
        state_dir: a.state_dir,
        interval: std::time::Duration::from_secs(a.interval_secs),
        artifacts: a.artifacts,
        root: a.root,
        renew_before_secs: a.renew_before_secs,
        facts_dir: a.facts_dir,
        facts_interval: std::time::Duration::from_secs(a.facts_interval_secs.max(60)),
    })
    .await
}

fn log_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())
}

/// The agent under the Windows Service Control Manager.
#[cfg(windows)]
mod service {
    use std::{ffi::OsString, fs, sync::Mutex, time::Duration};

    use anyhow::Context;
    use clap::Parser;
    use delbert_agent::winsvc;
    use windows_service::{
        define_windows_service,
        service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    use super::{Cli, Command, ServiceCmd};

    /// A service has no console: the log goes to `<data dir>\logs\agent.log`. One previous
    /// file is kept; the file is rotated at start when it is larger than this.
    const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

    pub async fn command(action: ServiceCmd) -> anyhow::Result<()> {
        match action {
            ServiceCmd::Install { core_url, ca_file, psk, agent_id } => {
                let data_dir = winsvc::data_dir();
                winsvc::install(&data_dir)?;
                println!("service {} installed; data directory {}", winsvc::SERVICE_NAME, data_dir.display());
                let identity_dir = data_dir.join("identity");
                if let (Some(core_url), Some(ca_file), Some(psk), Some(agent_name)) = (core_url, ca_file, psk, agent_id) {
                    if delbert_agent::identity::Identity::load(&identity_dir).is_err() {
                        let id = delbert_agent::identity::enroll(delbert_agent::identity::EnrollArgs { core_url, ca_file, psk, agent_name, identity_dir: identity_dir.clone() }).await?;
                        println!("enrolled as {}/{}", id.meta.tenant, id.meta.agent);
                    }
                }
                if delbert_agent::identity::Identity::load(&identity_dir).is_ok() {
                    winsvc::start_own()?;
                    println!("service started");
                } else {
                    println!("not enrolled yet: run `delbert-agent enroll ...`, then `sc.exe start {}`", winsvc::SERVICE_NAME);
                }
            }
            ServiceCmd::Uninstall => {
                winsvc::uninstall()?;
                println!("service {} removed", winsvc::SERVICE_NAME);
            }
            // Blocks until the service stops; the daemon runs on its own runtime in `service_main`.
            ServiceCmd::Run => tokio::task::spawn_blocking(|| service_dispatcher::start(winsvc::SERVICE_NAME, ffi_service_main)).await?.context("not started by the Service Control Manager")?,
        }
        Ok(())
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        let status = |state, exit| ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() },
            exit_code: ServiceExitCode::Win32(exit),
            checkpoint: 0,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        };
        let Ok(handle) = service_control_handler::register(winsvc::SERVICE_NAME, |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                winsvc::request_stop();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) else {
            return;
        };
        let _ = handle.set_service_status(status(ServiceState::Running, 0));
        let result = run();
        if let Err(e) = &result {
            tracing::error!("agent stopped with an error: {e:#}");
        }
        // A non-zero exit code makes the SCM apply the restart-on-failure actions.
        let _ = handle.set_service_status(status(ServiceState::Stopped, u32::from(result.is_err())));
    }

    /// Same as `delbert-agent run` with the service's environment (the `Environment` value of
    /// the service's registry key) and the default directories.
    fn run() -> anyhow::Result<()> {
        let logs = winsvc::data_dir().join("logs");
        fs::create_dir_all(&logs)?;
        let path = logs.join("agent.log");
        if fs::metadata(&path).is_ok_and(|m| m.len() > MAX_LOG_BYTES) {
            let _ = fs::rename(&path, logs.join("agent.log.1"));
        }
        let file = fs::OpenOptions::new().create(true).append(true).open(&path)?;
        tracing_subscriber::fmt().with_ansi(false).with_writer(Mutex::new(file)).with_env_filter(super::log_filter()).init();
        let Command::Run(args) = Cli::try_parse_from(["delbert-agent", "run"])?.command else { unreachable!("parsed `run`") };
        tokio::runtime::Runtime::new()?.block_on(super::daemon(args))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    rustls::crypto::ring::default_provider().install_default().ok();
    // The service entry point logs to a file instead (see `service::run`).
    #[cfg(windows)]
    let console = !std::env::args().skip(1).take(2).eq(["service", "run"]);
    #[cfg(not(windows))]
    let console = true;
    if console {
        tracing_subscriber::fmt().with_env_filter(log_filter()).init();
    }
    match Cli::parse().command {
        Command::Validate { file } => {
            let policy = load(&file)?;
            println!(
                "OK: policy '{}' (tenant '{}'), {} resources",
                policy.metadata.name,
                policy.metadata.tenant,
                policy.spec.resources.len()
            );
        }
        Command::Schema => println!("{}", serde_json::to_string_pretty(&delbert_policy::json_schema())?),
        Command::Check(a) => {
            let p = load(&a.file)?;
            return Ok(execute(&p.spec.resources, p.spec.vars, a.host, Mode::Check));
        }
        Command::Apply(a) => {
            let p = load(&a.file)?;
            return Ok(execute(&p.spec.resources, p.spec.vars, a.host, Mode::Apply));
        }
        Command::CheckSigned(a) => return execute_signed(a, Mode::Check),
        Command::ApplySigned(a) => return execute_signed(a, Mode::Apply),
        Command::Enroll(a) => {
            let id = delbert_agent::identity::enroll(delbert_agent::identity::EnrollArgs {
                core_url: a.core_url,
                ca_file: a.ca_file,
                psk: a.psk,
                agent_name: a.agent_id,
                identity_dir: a.identity_dir,
            })
            .await?;
            println!("enrolled as {}/{}; identity in {}", id.meta.tenant, id.meta.agent, id.dir.display());
        }
        Command::Run(a) => daemon(a).await?,
        #[cfg(windows)]
        Command::Service { action } => service::command(action).await?,
    }
    Ok(ExitCode::SUCCESS)
}
