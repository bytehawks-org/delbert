//! Windows integration (docs/WINDOWS.md): the agent as a Windows Service, and the `service` verb
//! on the Service Control Manager (SCM).
//!
//! Everything goes through the safe API of the `windows-service` crate; the only external tool
//! is `sc.exe config` (by full path, exit code only) to change a start type, because rewriting a
//! whole service configuration through the API could alter its image path.

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use delbert_policy::{ServiceSpec, ServiceState as Want};
use windows_service::{
    service::{
        Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        ServiceState, ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::engine::Ctx;
use crate::runner::Refused;
use crate::verbs::Check;

/// Name of the agent's own service in the SCM.
pub const SERVICE_NAME: &str = "DelbertAgent";
/// How long a start or stop may take before the resource fails.
const TRANSITION_TIMEOUT: Duration = Duration::from_secs(60);

// --- stop request (SCM -> daemon) -------------------------------------------------

static STOP: AtomicBool = AtomicBool::new(false);

/// Called by the service control handler on Stop / Shutdown.
pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}

/// Completes when the SCM asked the service to stop. A console run never sees it (Ctrl-C ends that).
pub async fn stop_requested() {
    while !STOP.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

// --- the agent's own service --------------------------------------------------------

/// Default data directory: identity, state, cached policy, logs (`%ProgramData%\Delbert`).
pub fn data_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into())).join("Delbert")
}

/// Register this executable as an automatic service running as LocalSystem, restarted by the
/// SCM when it fails, and make the data directory private. Idempotent: an existing service is
/// left as it is.
pub fn install(data_dir: &Path) -> Result<()> {
    delbert_fs::create_private_dir(data_dir).with_context(|| format!("preparing {}", data_dir.display()))?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE).context("connecting to the Service Control Manager (run as Administrator)")?;
    if manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).is_ok() {
        return Ok(());
    }
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: "Delbert Agent".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec!["service".into(), "run".into()],
        dependencies: vec![],
        account_name: None, // LocalSystem: the agent changes the host it runs on
        account_password: None,
    };
    let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START).context("creating the service")?;
    service.set_description("Applies the signed policies of the Delbert Core to this host. Outbound connections only.")?;
    service.set_delayed_auto_start(true)?;
    let restart = |secs| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(secs) };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(5), restart(30), restart(60)]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    Ok(())
}

/// Start the agent's service (after `install`, once an identity exists).
pub fn start_own() -> Result<()> {
    let service = open(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
    start(&service, SERVICE_NAME)
}

/// Stop and remove the service. The data directory (identity included) is left in place.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).context("connecting to the Service Control Manager (run as Administrator)")?;
    let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE) else {
        return Ok(()); // not installed
    };
    stop(&service, SERVICE_NAME)?;
    service.delete().context("deleting the service")
}

// --- the `service` verb ---------------------------------------------------------------

fn open(name: &str, access: ServiceAccess) -> Result<Service> {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("connecting to the Service Control Manager")?
        .open_service(name, access)
        .with_context(|| format!("opening service '{name}'"))
}

fn state(service: &Service) -> Result<ServiceState> {
    Ok(service.query_status()?.current_state)
}

fn wait_for(service: &Service, name: &str, want: ServiceState) -> Result<()> {
    let deadline = Instant::now() + TRANSITION_TIMEOUT;
    while state(service)? != want {
        if Instant::now() > deadline {
            bail!("service '{name}' did not reach {want:?} within {}s", TRANSITION_TIMEOUT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}

fn start(service: &Service, name: &str) -> Result<()> {
    if !matches!(state(service)?, ServiceState::Running | ServiceState::StartPending) {
        service.start::<&OsStr>(&[]).with_context(|| format!("starting service '{name}'"))?;
    }
    wait_for(service, name, ServiceState::Running)
}

fn stop(service: &Service, name: &str) -> Result<()> {
    if !matches!(state(service)?, ServiceState::Stopped | ServiceState::StopPending) {
        service.stop().with_context(|| format!("stopping service '{name}'"))?;
    }
    wait_for(service, name, ServiceState::Stopped)
}

/// `enabled` in a policy means "starts with the system" (automatic start).
fn is_enabled(service: &Service) -> Result<bool> {
    Ok(matches!(service.query_config()?.start_type, ServiceStartType::AutoStart | ServiceStartType::BootStart | ServiceStartType::SystemStart))
}

/// A sandbox root must not touch the real host's services.
fn refuse_in_sandbox(ctx: &Ctx, what: &str) -> Result<()> {
    if ctx.root != Path::new("/") {
        return Err(Refused(what.to_string()).into());
    }
    Ok(())
}

pub fn service_check(spec: &ServiceSpec, ctx: &Ctx) -> Result<Check> {
    refuse_in_sandbox(ctx, "service query")?;
    let mut drift = Vec::new();
    match spec.state {
        Some(Want::Restarted) => return Ok(Check::Drift(vec!["action".into()])),
        Some(Want::Reloaded) => bail!("'reloaded' is not available for Windows services (use 'restarted')"),
        _ => {}
    }
    let service = open(&spec.name, ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG)?;
    let running = state(&service)? == ServiceState::Running;
    match (spec.state, running) {
        (Some(Want::Started), false) => drift.push("not running".to_string()),
        (Some(Want::Stopped), true) => drift.push("running".to_string()),
        _ => {}
    }
    if let Some(want) = spec.enabled {
        if is_enabled(&service)? != want {
            drift.push(if want { "not enabled" } else { "enabled" }.to_string());
        }
    }
    Ok(if drift.is_empty() { Check::Compliant } else { Check::Drift(drift) })
}

pub fn service_apply(spec: &ServiceSpec, ctx: &Ctx) -> Result<()> {
    refuse_in_sandbox(ctx, "service control")?;
    let service = open(&spec.name, ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG | ServiceAccess::START | ServiceAccess::STOP)?;
    // The start type first: a disabled service cannot be started.
    if let Some(want) = spec.enabled {
        if is_enabled(&service)? != want {
            let sc = PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into())).join(r"System32\sc.exe");
            let sc = sc.to_string_lossy();
            let argv = [sc.as_ref(), "config", spec.name.as_str(), "start=", if want { "auto" } else { "demand" }];
            ctx.runner.run(&argv)?.check(&argv)?;
        }
    }
    match spec.state {
        Some(Want::Started) => start(&service, &spec.name)?,
        Some(Want::Stopped) => stop(&service, &spec.name)?,
        Some(Want::Restarted) => {
            stop(&service, &spec.name)?;
            start(&service, &spec.name)?;
        }
        Some(Want::Reloaded) => bail!("'reloaded' is not available for Windows services (use 'restarted')"),
        None => {}
    }
    Ok(())
}
