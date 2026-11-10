//! Verbs for the system itself: `package` and `service` (through system tools), `sysctl`.

use anyhow::{Context, Result, bail};
use delbert_policy::{PackageSpec, PackageState, ServiceSpec, ServiceState, SysctlSpec};

use crate::engine::Ctx;
use crate::runner::Refused;
use crate::verbs::{Check, Verb};

// --- package -------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Apt,
    Dnf,
    Zypper,
    Apk,
}

impl Backend {
    /// First package manager that answers `--version`.
    fn detect(ctx: &Ctx) -> Result<Self> {
        for (backend, tool) in [(Backend::Apt, "apt-get"), (Backend::Dnf, "dnf"), (Backend::Zypper, "zypper"), (Backend::Apk, "apk")] {
            match ctx.runner.run(&[tool, "--version"]) {
                Ok(out) if out.ok() => return Ok(backend),
                Err(e) if e.downcast_ref::<Refused>().is_some() => return Err(e),
                _ => {} // tool missing: try the next one
            }
        }
        bail!("no supported package manager found (apt, dnf, zypper, apk)")
    }

    fn is_installed(self, ctx: &Ctx, name: &str) -> Result<bool> {
        Ok(match self {
            Backend::Apt => {
                let out = ctx.runner.run(&["dpkg-query", "-W", "-f=${Status}", name])?;
                out.ok() && out.stdout.contains("install ok installed")
            }
            Backend::Dnf | Backend::Zypper => ctx.runner.run(&["rpm", "-q", name])?.ok(),
            Backend::Apk => ctx.runner.run(&["apk", "info", "-e", name])?.ok(),
        })
    }

    fn install_argv<'a>(self, name: &'a str) -> Vec<&'a str> {
        match self {
            Backend::Apt => vec!["apt-get", "install", "-y", name],
            Backend::Dnf => vec!["dnf", "install", "-y", name],
            Backend::Zypper => vec!["zypper", "--non-interactive", "install", name],
            Backend::Apk => vec!["apk", "add", name],
        }
    }

    /// Metadata refresh to try once when an install fails (stale or empty indexes).
    /// dnf and zypper refresh on their own.
    fn refresh_argv(self) -> Option<Vec<&'static str>> {
        match self {
            Backend::Apt => Some(vec!["apt-get", "update"]),
            Backend::Apk => Some(vec!["apk", "update"]),
            Backend::Dnf | Backend::Zypper => None,
        }
    }

    fn remove_argv<'a>(self, name: &'a str) -> Vec<&'a str> {
        match self {
            Backend::Apt => vec!["apt-get", "remove", "-y", name],
            Backend::Dnf => vec!["dnf", "remove", "-y", name],
            Backend::Zypper => vec!["zypper", "--non-interactive", "remove", name],
            Backend::Apk => vec!["apk", "del", name],
        }
    }
}

impl Verb for PackageSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        if self.state == PackageState::Latest {
            bail!("package state 'latest' is not implemented yet");
        }
        let installed = Backend::detect(ctx)?.is_installed(ctx, &self.name)?;
        Ok(match (self.state, installed) {
            (PackageState::Present, false) => Check::Drift(vec![format!("{} not installed", self.name)]),
            (PackageState::Absent, true) => Check::Drift(vec![format!("{} installed", self.name)]),
            _ => Check::Compliant,
        })
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        let backend = Backend::detect(ctx)?;
        let argv = match self.state {
            PackageState::Present => backend.install_argv(&self.name),
            PackageState::Absent => backend.remove_argv(&self.name),
            PackageState::Latest => bail!("package state 'latest' is not implemented yet"),
        };
        let first = ctx.runner.run(&argv)?;
        if first.ok() {
            return Ok(());
        }
        // A fresh host often has no package index: refresh once and retry (installs only).
        match (self.state, backend.refresh_argv()) {
            (PackageState::Present, Some(refresh)) => {
                ctx.runner.run(&refresh)?.check(&refresh)?;
                ctx.runner.run(&argv)?.check(&argv)?;
                Ok(())
            }
            _ => first.check(&argv).map(drop),
        }
    }
}

// --- service (systemd; Windows services are in `winsvc`) ---------------------------------------------------------

fn systemctl(ctx: &Ctx, args: &[&str]) -> Result<crate::runner::CmdOutput> {
    let mut argv = vec!["systemctl"];
    argv.extend_from_slice(args);
    ctx.runner.run(&argv)
}

/// Compiled everywhere (its tests run on every platform), used on Unix only.
#[cfg_attr(windows, allow(dead_code))]
fn systemd_check(spec: &ServiceSpec, ctx: &Ctx) -> Result<Check> {
    let mut drift = Vec::new();
    match spec.state {
        Some(ServiceState::Restarted | ServiceState::Reloaded) => return Ok(Check::Drift(vec!["action".into()])),
        Some(want @ (ServiceState::Started | ServiceState::Stopped)) => {
            let active = systemctl(ctx, &["is-active", "--quiet", &spec.name])?.ok();
            match (want, active) {
                (ServiceState::Started, false) => drift.push("not running".to_string()),
                (ServiceState::Stopped, true) => drift.push("running".to_string()),
                _ => {}
            }
        }
        None => {}
    }
    if let Some(want) = spec.enabled {
        let enabled = systemctl(ctx, &["is-enabled", "--quiet", &spec.name])?.ok();
        if enabled != want {
            drift.push(if want { "not enabled" } else { "enabled" }.to_string());
        }
    }
    Ok(if drift.is_empty() { Check::Compliant } else { Check::Drift(drift) })
}

#[cfg_attr(windows, allow(dead_code))]
fn systemd_apply(spec: &ServiceSpec, ctx: &Ctx) -> Result<()> {
    let run = |args: &[&str]| -> Result<()> {
        let mut argv = vec!["systemctl"];
        argv.extend_from_slice(args);
        ctx.runner.run(&argv)?.check(&argv).map(drop)
    };
    let is_active = || systemctl(ctx, &["is-active", "--quiet", &spec.name]).map(|o| o.ok());
    match spec.state {
        Some(ServiceState::Started) if !is_active()? => run(&["start", &spec.name])?,
        Some(ServiceState::Stopped) if is_active()? => run(&["stop", &spec.name])?,
        Some(ServiceState::Restarted) => run(&["restart", &spec.name])?,
        Some(ServiceState::Reloaded) => run(&["reload", &spec.name])?,
        _ => {}
    }
    if let Some(want) = spec.enabled {
        let enabled = systemctl(ctx, &["is-enabled", "--quiet", &spec.name])?.ok();
        if enabled != want {
            run(&[if want { "enable" } else { "disable" }, &spec.name])?;
        }
    }
    Ok(())
}

impl Verb for ServiceSpec {
    /// systemd on Unix, the Service Control Manager on Windows.
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        #[cfg(windows)]
        return crate::winsvc::service_check(self, ctx);
        #[cfg(not(windows))]
        systemd_check(self, ctx)
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        #[cfg(windows)]
        return crate::winsvc::service_apply(self, ctx);
        #[cfg(not(windows))]
        systemd_apply(self, ctx)
    }

    /// `restarted` / `reloaded` have no observable state to verify afterwards.
    fn is_action(&self) -> bool {
        matches!(self.state, Some(ServiceState::Restarted | ServiceState::Reloaded))
    }
}

// --- sysctl ---------------------------------------------------------------------

/// Values compare with any run of blanks as one (multi-valued parameters use tabs).
fn squeeze(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The parameter under `/proc/sys`.
fn sysctl_live_path(spec: &SysctlSpec) -> String {
    format!("/proc/sys/{}", spec.key.replace('.', "/"))
}

/// The file that sets it at boot.
fn sysctl_persist_path(spec: &SysctlSpec) -> String {
    format!("/etc/sysctl.d/90-delbert-{}.conf", spec.key)
}

fn sysctl_persist_content(spec: &SysctlSpec) -> String {
    format!("# Managed by Delbert: do not edit, changes are overwritten.\n{} = {}\n", spec.key, squeeze(&spec.value))
}

/// (value differs now, boot file differs)
fn sysctl_drift(spec: &SysctlSpec, ctx: &Ctx) -> Result<(bool, bool)> {
    if cfg!(windows) {
        bail!("sysctl is not supported on Windows");
    }
    let live = std::fs::read_to_string(ctx.path(&sysctl_live_path(spec))).with_context(|| format!("unknown kernel parameter '{}'", spec.key))?;
    let persisted = std::fs::read_to_string(ctx.path(&sysctl_persist_path(spec))).is_ok_and(|c| c == sysctl_persist_content(spec));
    Ok((squeeze(&live) != squeeze(&spec.value), spec.persist && !persisted))
}

/// The kernel parameter is read and written directly in `/proc/sys`: no command is run.
impl Verb for SysctlSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        let (now, boot) = sysctl_drift(self, ctx)?;
        let drift: Vec<String> = [(now, "value differs"), (boot, "not set at boot")].into_iter().filter_map(|(d, what)| d.then(|| what.to_string())).collect();
        Ok(if drift.is_empty() { Check::Compliant } else { Check::Drift(drift) })
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        let (now, boot) = sysctl_drift(self, ctx)?;
        // The boot file first: if the kernel refuses the value the resource fails, and the next
        // cycle finds the same drift again.
        if boot {
            let attrs = crate::fsutil::Attrs { owner: None, group: None, mode: Some("0644") };
            crate::fsutil::write_atomic(ctx, &ctx.path(&sysctl_persist_path(self)), sysctl_persist_content(self).as_bytes(), attrs)?;
        }
        if now {
            // Not a file to replace: the kernel takes the value from a plain write.
            std::fs::write(ctx.path(&sysctl_live_path(self)), format!("{}\n", squeeze(&self.value))).with_context(|| format!("setting {}", self.key))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::FakeRunner;
    use std::sync::Arc;

    fn ctx_with(runner: FakeRunner) -> (Ctx, Arc<FakeRunner>) {
        let r = Arc::new(runner);
        let mut ctx = Ctx::new("/".into(), "artifacts".into());
        ctx.runner = r.clone();
        (ctx, r)
    }

    #[test]
    fn package_present_installs_when_missing() {
        let (ctx, r) = ctx_with(FakeRunner::new(vec![
            (&["apt-get", "--version"], 0, "apt 3"),
            (&["dpkg-query"], 1, ""),
            (&["apt-get", "install", "-y", "nginx"], 0, ""),
        ]));
        let spec = PackageSpec { name: "nginx".into(), state: PackageState::Present };
        assert_eq!(spec.check(&ctx).unwrap(), Check::Drift(vec!["nginx not installed".into()]));
        spec.apply(&ctx).unwrap();
        assert!(r.calls().contains(&"apt-get install -y nginx".to_string()));
    }

    #[test]
    fn package_present_is_compliant_when_installed() {
        let (ctx, _) = ctx_with(FakeRunner::new(vec![
            (&["apt-get", "--version"], 0, ""),
            (&["dpkg-query"], 0, "install ok installed"),
        ]));
        let spec = PackageSpec { name: "nginx".into(), state: PackageState::Present };
        assert_eq!(spec.check(&ctx).unwrap(), Check::Compliant);
    }

    #[test]
    fn package_backend_fallback_to_dnf_and_remove() {
        let (ctx, r) = ctx_with(FakeRunner::new(vec![
            (&["dnf", "--version"], 0, ""),
            (&["rpm", "-q"], 0, ""),
            (&["dnf", "remove", "-y", "nginx"], 0, ""),
        ]));
        let spec = PackageSpec { name: "nginx".into(), state: PackageState::Absent };
        assert!(matches!(spec.check(&ctx).unwrap(), Check::Drift(_)));
        spec.apply(&ctx).unwrap();
        assert!(r.calls().contains(&"dnf remove -y nginx".to_string()));
    }

    #[test]
    fn package_install_refreshes_the_index_and_retries_once() {
        let (ctx, r) = ctx_with(FakeRunner::new(vec![
            (&["apt-get", "--version"], 0, ""),
            (&["apt-get", "install", "-y", "tree"], 100, ""),
            (&["apt-get", "update"], 0, ""),
            (&["apt-get", "install", "-y", "tree"], 0, ""),
        ]));
        PackageSpec { name: "tree".into(), state: PackageState::Present }.apply(&ctx).unwrap();
        let calls = r.calls();
        let pos = |s: &str| calls.iter().position(|c| c == s).unwrap();
        assert!(pos("apt-get update") > pos("apt-get install -y tree"));
        assert_eq!(calls.iter().filter(|c| *c == "apt-get install -y tree").count(), 2);
    }

    #[test]
    fn package_failure_reports_the_command() {
        let (ctx, _) = ctx_with(FakeRunner::new(vec![(&["apt-get", "--version"], 0, ""), (&["apt-get", "update"], 0, ""), (&["apt-get", "install"], 100, "")]));
        let err = PackageSpec { name: "x".into(), state: PackageState::Present }.apply(&ctx).unwrap_err();
        assert!(err.to_string().contains("apt-get install -y x"));
    }

    #[test]
    fn service_started_and_enabled() {
        let (ctx, r) = ctx_with(FakeRunner::new(vec![
            (&["systemctl", "is-active"], 3, ""),
            (&["systemctl", "is-enabled"], 1, ""),
            (&["systemctl", "start"], 0, ""),
            (&["systemctl", "enable"], 0, ""),
        ]));
        let spec = ServiceSpec { name: "nginx".into(), state: Some(ServiceState::Started), enabled: Some(true) };
        assert_eq!(systemd_check(&spec, &ctx).unwrap(), Check::Drift(vec!["not running".into(), "not enabled".into()]));
        systemd_apply(&spec, &ctx).unwrap();
        let calls = r.calls();
        assert!(calls.contains(&"systemctl start nginx".to_string()) && calls.contains(&"systemctl enable nginx".to_string()));
    }

    #[test]
    fn service_already_in_state_does_nothing() {
        let (ctx, r) = ctx_with(FakeRunner::new(vec![(&["systemctl", "is-active"], 0, ""), (&["systemctl", "is-enabled"], 0, "")]));
        let spec = ServiceSpec { name: "nginx".into(), state: Some(ServiceState::Started), enabled: Some(true) };
        assert_eq!(systemd_check(&spec, &ctx).unwrap(), Check::Compliant);
        systemd_apply(&spec, &ctx).unwrap();
        assert!(!r.calls().iter().any(|c| c.starts_with("systemctl start ") || c.starts_with("systemctl enable ")));
    }

    #[test]
    fn service_reload_is_an_action() {
        let (ctx, r) = ctx_with(FakeRunner::new(vec![(&["systemctl", "reload"], 0, "")]));
        let spec = ServiceSpec { name: "nginx".into(), state: Some(ServiceState::Reloaded), enabled: None };
        assert!(spec.is_action());
        assert!(matches!(systemd_check(&spec, &ctx).unwrap(), Check::Drift(_)));
        systemd_apply(&spec, &ctx).unwrap();
        assert_eq!(r.calls(), vec!["systemctl reload nginx"]);
    }
    #[cfg(unix)]
    #[test]
    fn sysctl_sets_the_value_now_and_at_boot() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("proc/sys/net/ipv4")).unwrap();
        std::fs::create_dir_all(tmp.path().join("etc/sysctl.d")).unwrap();
        std::fs::write(tmp.path().join("proc/sys/net/ipv4/ip_forward"), "0\n").unwrap();
        std::fs::write(tmp.path().join("proc/sys/net/ipv4/ip_local_port_range"), "32768\t60999\n").unwrap();
        let ctx = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());

        let spec = SysctlSpec { key: "net.ipv4.ip_forward".into(), value: "1".into(), persist: true };
        assert_eq!(spec.check(&ctx).unwrap(), Check::Drift(vec!["value differs".into(), "not set at boot".into()]));
        spec.apply(&ctx).unwrap();
        assert_eq!(spec.check(&ctx).unwrap(), Check::Compliant);
        assert_eq!(std::fs::read_to_string(tmp.path().join("proc/sys/net/ipv4/ip_forward")).unwrap(), "1\n");
        assert!(std::fs::read_to_string(tmp.path().join("etc/sysctl.d/90-delbert-net.ipv4.ip_forward.conf")).unwrap().ends_with("net.ipv4.ip_forward = 1\n"));

        // Blanks do not matter; without `persist` no file is written.
        let range = SysctlSpec { key: "net.ipv4.ip_local_port_range".into(), value: "32768 60999".into(), persist: false };
        assert_eq!(range.check(&ctx).unwrap(), Check::Compliant);
        assert!(!tmp.path().join("etc/sysctl.d/90-delbert-net.ipv4.ip_local_port_range.conf").exists());
        // An unknown parameter is an error, not something to create.
        let unknown = SysctlSpec { key: "net.nope".into(), value: "1".into(), persist: true };
        assert!(unknown.check(&ctx).unwrap_err().to_string().contains("unknown kernel parameter"));
        assert!(unknown.apply(&ctx).is_err() && !tmp.path().join("proc/sys/net/nope").exists());
    }
}
