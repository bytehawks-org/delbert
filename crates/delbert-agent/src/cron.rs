//! Scheduled jobs: the `cron` verb (docs/POLICY.md "Scheduled jobs").
//!
//! A job is one file in `/etc/cron.d`, written crash-safely; the agent itself runs nothing.
//! Because a cron job is a way to run a program, it follows the rules of the `command` resource:
//! - **off by default**: the executable must be on the agent's local allow-list
//!   (`--cron-allow` / `DELBERT_CRON_ALLOW`, exact absolute paths). No policy can change it;
//! - **no shell syntax**: the command is an argv, every argument is quoted for the cron line, so
//!   pipes, redirections, substitutions and `%` (cron's newline) are passed as plain text.
//!
//! Only files that carry the Delbert header are replaced or removed. Not available on Windows.

use std::fs;

use anyhow::{Context, Result, bail};
use delbert_policy::{CronSpec, Presence};

use crate::engine::Ctx;
use crate::fsutil::Attrs;
use crate::verbs::{Check, Verb, content_apply, content_check};

const DIR: &str = "/etc/cron.d";
const HEADER: &str = "# Managed by Delbert: do not edit, changes are overwritten.";
/// cron ignores files that are writable by group or others.
const ATTRS: Attrs = Attrs { owner: None, group: None, mode: Some("0644") };

/// One argument of the cron line: as it is when harmless, else in single quotes; `%` is escaped
/// for cron, which would otherwise turn it into a newline.
fn quote(arg: &str) -> String {
    let plain = !arg.is_empty() && arg.chars().all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
    let quoted = if plain { arg.to_owned() } else { format!("'{}'", arg.replace('\'', r"'\''")) };
    quoted.replace('%', r"\%")
}

/// The whole file of a job.
pub fn render(spec: &CronSpec) -> String {
    let mut out = format!("{HEADER}\n");
    for (key, value) in &spec.env {
        out.push_str(&format!("{key}={value}\n"));
    }
    let command: Vec<String> = spec.command.iter().map(|a| quote(a)).collect();
    out.push_str(&format!("{} {} {}\n", spec.schedule.as_deref().unwrap_or_default(), spec.user.as_deref().unwrap_or("root"), command.join(" ")));
    out
}

/// Refuse what the local configuration does not allow, and files that are not ours.
fn guard(spec: &CronSpec, ctx: &Ctx) -> Result<()> {
    if cfg!(windows) {
        bail!("cron is not supported on Windows");
    }
    if spec.state == Presence::Present {
        let exe = spec.command.first().context("cron requires 'command'")?;
        if !ctx.cron_allow.iter().any(|allowed| allowed == exe) {
            bail!("'{exe}' is not on this agent's cron allow-list (local setting DELBERT_CRON_ALLOW; scheduled jobs are off by default)");
        }
    }
    let path = ctx.path(&format!("{DIR}/{}", spec.name));
    match fs::read_to_string(&path) {
        Ok(current) if !current.starts_with(HEADER) => bail!("{DIR}/{} exists and is not managed by Delbert", spec.name),
        _ => Ok(()),
    }
}

impl Verb for CronSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        guard(self, ctx)?;
        let path = ctx.path(&format!("{DIR}/{}", self.name));
        match self.state {
            Presence::Present => content_check(ctx, &path, render(self).as_bytes(), ATTRS),
            Presence::Absent if path.exists() => Ok(Check::Drift(vec!["exists".into()])),
            Presence::Absent => Ok(Check::Compliant),
        }
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        guard(self, ctx)?;
        let path = ctx.path(&format!("{DIR}/{}", self.name));
        match self.state {
            Presence::Present => content_apply(ctx, &path, render(self).as_bytes(), ATTRS),
            Presence::Absent if path.exists() => fs::remove_file(&path).with_context(|| format!("removing {}", path.display())),
            Presence::Absent => Ok(()),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn job() -> CronSpec {
        CronSpec {
            name: "backup".into(),
            state: Presence::Present,
            schedule: Some("30 2 * * 1-5".into()),
            user: Some("backup".into()),
            command: vec!["/usr/local/bin/backup.sh".into(), "--to".into(), "/srv/backup dir".into(), "100%; rm -rf / | $(x) it's".into()],
            env: [("MAILTO".to_string(), "ops@example.com".to_string())].into(),
        }
    }

    fn ctx(allow: &[&str]) -> (tempfile::TempDir, Ctx) {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("etc/cron.d")).unwrap();
        let mut ctx = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());
        ctx.cron_allow = allow.iter().map(|s| s.to_string()).collect();
        (tmp, ctx)
    }

    #[test]
    fn the_line_is_quoted_so_nothing_is_shell_or_cron_syntax() {
        assert_eq!(
            render(&job()),
            "# Managed by Delbert: do not edit, changes are overwritten.\nMAILTO=ops@example.com\n30 2 * * 1-5 backup /usr/local/bin/backup.sh --to '/srv/backup dir' '100\\%; rm -rf / | $(x) it'\\''s'\n"
        );
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn off_by_default_and_only_listed_executables() {
        let (_tmp, closed) = ctx(&[]);
        assert!(job().check(&closed).unwrap_err().to_string().contains("allow-list"));
        assert!(job().apply(&closed).is_err());
        let (_tmp, other) = ctx(&["/usr/bin/other"]);
        assert!(job().check(&other).is_err());
    }

    #[test]
    fn job_is_written_converges_and_is_removed() {
        let (tmp, ctx) = ctx(&["/usr/local/bin/backup.sh"]);
        let file = tmp.path().join("etc/cron.d/backup");
        assert_eq!(job().check(&ctx).unwrap(), Check::Drift(vec!["missing".into()]));
        job().apply(&ctx).unwrap();
        assert_eq!(job().check(&ctx).unwrap(), Check::Compliant);
        assert_eq!(fs::read_to_string(&file).unwrap(), render(&job()));
        assert_eq!(std::os::unix::fs::MetadataExt::mode(&fs::metadata(&file).unwrap()) & 0o777, 0o644);
        // A changed schedule is drift; removal needs no allow-list.
        let later = CronSpec { schedule: Some("@daily".into()), ..job() };
        assert!(matches!(later.check(&ctx).unwrap(), Check::Drift(_)));
        let gone = CronSpec { state: Presence::Absent, schedule: None, command: vec![], ..job() };
        let mut closed = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());
        closed.cron_allow.clear();
        assert_eq!(gone.check(&closed).unwrap(), Check::Drift(vec!["exists".into()]));
        gone.apply(&closed).unwrap();
        assert!(!file.exists());
        assert_eq!(gone.check(&closed).unwrap(), Check::Compliant);
    }

    #[test]
    fn a_file_that_is_not_ours_is_never_touched() {
        let (tmp, ctx) = ctx(&["/usr/local/bin/backup.sh"]);
        let file = tmp.path().join("etc/cron.d/backup");
        fs::write(&file, "0 0 * * * root /bin/true\n").unwrap();
        assert!(job().check(&ctx).unwrap_err().to_string().contains("not managed by Delbert"));
        assert!(CronSpec { state: Presence::Absent, ..job() }.apply(&ctx).is_err());
        assert_eq!(fs::read_to_string(&file).unwrap(), "0 0 * * * root /bin/true\n");
    }
}
