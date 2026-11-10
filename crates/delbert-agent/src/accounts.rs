//! Local accounts: the `group` and `user` verbs (docs/POLICY.md "Users and groups").
//!
//! The state is read from the local `passwd` and `group` files (the same source the file verbs
//! use for owners; directory services such as LDAP are not consulted and never changed). Changes
//! go through the shadow tools (`groupadd`, `useradd`, `usermod`, ...) as argv vectors: they keep
//! `shadow`, `gshadow` and the lock files consistent, which editing the files would not.
//! No password is ever set. Not available on Windows.

use std::fs;

use anyhow::{Context, Result, bail};
use delbert_policy::{GroupSpec, Presence, UserSpec};

use crate::engine::Ctx;
use crate::verbs::{Check, Verb};

struct Passwd {
    uid: u32,
    gid: u32,
    comment: String,
    home: String,
    shell: String,
}

struct Group {
    gid: u32,
    members: Vec<String>,
}

fn refuse_on_windows() -> Result<()> {
    if cfg!(windows) {
        bail!("local users and groups are not supported on Windows");
    }
    Ok(())
}

/// The fields of the line of `name` in a colon-separated database; a missing file has no entries.
fn entry(ctx: &Ctx, db: &str, name: &str) -> Result<Option<Vec<String>>> {
    let text = match fs::read_to_string(ctx.path(db)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {db}")),
    };
    Ok(text.lines().map(|l| l.split(':').map(str::to_owned).collect::<Vec<_>>()).find(|f| f.first().is_some_and(|n| n == name)))
}

fn passwd(ctx: &Ctx, name: &str) -> Result<Option<Passwd>> {
    let Some(f) = entry(ctx, "/etc/passwd", name)? else { return Ok(None) };
    let field = |i: usize| f.get(i).cloned().unwrap_or_default();
    let id = |i: usize| field(i).parse::<u32>().with_context(|| format!("malformed passwd entry of '{name}'"));
    Ok(Some(Passwd { uid: id(2)?, gid: id(3)?, comment: field(4), home: field(5), shell: field(6) }))
}

fn group(ctx: &Ctx, name: &str) -> Result<Option<Group>> {
    let Some(f) = entry(ctx, "/etc/group", name)? else { return Ok(None) };
    let gid = f.get(2).and_then(|g| g.parse().ok()).with_context(|| format!("malformed group entry of '{name}'"))?;
    let members = f.get(3).map(|m| m.split(',').filter(|s| !s.is_empty()).map(str::to_owned).collect()).unwrap_or_default();
    Ok(Some(Group { gid, members }))
}

fn run(ctx: &Ctx, argv: &[&str]) -> Result<()> {
    ctx.runner.run(argv)?.check(argv).map(drop)
}

// --- group --------------------------------------------------------------------

impl Verb for GroupSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        refuse_on_windows()?;
        let drift = match (self.state, group(ctx, &self.name)?) {
            (Presence::Absent, None) => vec![],
            (Presence::Absent, Some(_)) => vec!["exists".to_string()],
            (Presence::Present, None) => vec!["missing".to_string()],
            (Presence::Present, Some(g)) => self.gid.filter(|want| *want != g.gid).map(|want| format!("gid {} -> {want}", g.gid)).into_iter().collect(),
        };
        Ok(if drift.is_empty() { Check::Compliant } else { Check::Drift(drift) })
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        refuse_on_windows()?;
        let gid = self.gid.map(|g| g.to_string());
        match (self.state, group(ctx, &self.name)?) {
            (Presence::Absent, Some(_)) => run(ctx, &["groupdel", &self.name]),
            (Presence::Present, None) => {
                let mut argv = vec!["groupadd"];
                if let Some(gid) = &gid {
                    argv.extend(["-g", gid]);
                }
                if self.system {
                    argv.push("-r");
                }
                argv.push(&self.name);
                run(ctx, &argv)
            }
            (Presence::Present, Some(g)) => match &gid {
                Some(want) if self.gid != Some(g.gid) => run(ctx, &["groupmod", "-g", want, &self.name]),
                _ => Ok(()),
            },
            (Presence::Absent, None) => Ok(()),
        }
    }
}

// --- user ---------------------------------------------------------------------

/// Supplementary groups of the policy the user is not yet a member of (a group that does not
/// exist counts as missing: `usermod` will say so).
fn missing_groups<'a>(spec: &'a UserSpec, ctx: &Ctx, current: &Passwd) -> Result<Vec<&'a str>> {
    let mut missing = Vec::new();
    for name in &spec.groups {
        let member = group(ctx, name)?.is_some_and(|g| g.gid == current.gid || g.members.contains(&spec.name));
        if !member {
            missing.push(name.as_str());
        }
    }
    Ok(missing)
}

/// The gid of the primary group named in the policy.
fn primary_gid(spec: &UserSpec, ctx: &Ctx) -> Result<Option<u32>> {
    spec.group.as_deref().map(|name| group(ctx, name)?.map(|g| g.gid).with_context(|| format!("primary group '{name}' does not exist"))).transpose()
}

impl Verb for UserSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        refuse_on_windows()?;
        let current = match (self.state, passwd(ctx, &self.name)?) {
            (Presence::Absent, None) => return Ok(Check::Compliant),
            (Presence::Absent, Some(_)) => return Ok(Check::Drift(vec!["exists".into()])),
            (Presence::Present, None) => return Ok(Check::Drift(vec!["missing".into()])),
            (Presence::Present, Some(current)) => current,
        };
        let mut drift = Vec::new();
        if let Some(want) = self.uid.filter(|u| *u != current.uid) {
            drift.push(format!("uid {} -> {want}", current.uid));
        }
        if primary_gid(self, ctx)?.is_some_and(|g| g != current.gid) {
            drift.push(format!("primary group -> {}", self.group.as_deref().unwrap_or_default()));
        }
        for (label, want, have) in [("shell", &self.shell, &current.shell), ("home", &self.home, &current.home), ("comment", &self.comment, &current.comment)] {
            if want.as_ref().is_some_and(|w| w != have) {
                drift.push(format!("{label} {have} -> {}", want.as_deref().unwrap_or_default()));
            }
        }
        for g in missing_groups(self, ctx, &current)? {
            drift.push(format!("not in group {g}"));
        }
        Ok(if drift.is_empty() { Check::Compliant } else { Check::Drift(drift) })
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        refuse_on_windows()?;
        let uid = self.uid.map(|u| u.to_string());
        let current = match (self.state, passwd(ctx, &self.name)?) {
            (Presence::Absent, None) => return Ok(()),
            // The home directory and the user's files are left in place: nothing is deleted by inference.
            (Presence::Absent, Some(_)) => return run(ctx, &["userdel", &self.name]),
            (Presence::Present, current) => current,
        };
        let Some(current) = current else {
            let groups = self.groups.join(",");
            let mut argv = vec!["useradd"];
            for (flag, value) in [("-u", uid.as_deref()), ("-g", self.group.as_deref()), ("-s", self.shell.as_deref()), ("-d", self.home.as_deref()), ("-c", self.comment.as_deref())] {
                if let Some(value) = value {
                    argv.extend([flag, value]);
                }
            }
            if !groups.is_empty() {
                argv.extend(["-G", &groups]);
            }
            if self.system {
                argv.push("-r");
            }
            // Explicit either way: the default differs between distributions.
            argv.extend([if self.create_home { "-m" } else { "-M" }, &self.name]);
            return run(ctx, &argv);
        };
        // Exists: change only what differs. The home directory is not moved.
        let missing = missing_groups(self, ctx, &current)?.join(",");
        let mut argv = vec!["usermod"];
        if let Some(uid) = uid.as_deref().filter(|_| self.uid != Some(current.uid)) {
            argv.extend(["-u", uid]);
        }
        if primary_gid(self, ctx)?.is_some_and(|g| g != current.gid) {
            argv.extend(["-g", self.group.as_deref().unwrap_or_default()]);
        }
        for (flag, want, have) in [("-s", &self.shell, &current.shell), ("-d", &self.home, &current.home), ("-c", &self.comment, &current.comment)] {
            if let Some(want) = want.as_deref().filter(|w| w != have) {
                argv.extend([flag, want]);
            }
        }
        if !missing.is_empty() {
            argv.extend(["-a", "-G", &missing]);
        }
        if argv.len() == 1 {
            return Ok(());
        }
        argv.push(&self.name);
        run(ctx, &argv)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::runner::FakeRunner;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\napp:x:1500:1500:App:/srv/app:/usr/sbin/nologin\n";
    const GROUP: &str = "root:x:0:\napp:x:1500:\nweb:x:1600:alice\nops:x:1700:\n";

    fn ctx(script: Vec<(&[&str], i32, &str)>) -> (tempfile::TempDir, Ctx, Arc<FakeRunner>) {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(tmp.path().join("etc/passwd"), PASSWD).unwrap();
        fs::write(tmp.path().join("etc/group"), GROUP).unwrap();
        let runner = Arc::new(FakeRunner::new(script));
        let mut ctx = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());
        ctx.runner = runner.clone();
        (tmp, ctx, runner)
    }

    fn user(name: &str) -> UserSpec {
        UserSpec { name: name.into(), state: Presence::Present, uid: None, group: None, groups: vec![], shell: None, home: None, comment: None, system: false, create_home: false }
    }

    #[test]
    fn group_is_created_changed_and_removed() {
        let (_tmp, ctx, runner) = ctx(vec![(&["groupadd"], 0, ""), (&["groupmod"], 0, ""), (&["groupdel"], 0, "")]);
        let new = GroupSpec { name: "deploy".into(), state: Presence::Present, gid: Some(1800), system: true };
        assert_eq!(new.check(&ctx).unwrap(), Check::Drift(vec!["missing".into()]));
        new.apply(&ctx).unwrap();
        let same = GroupSpec { name: "web".into(), state: Presence::Present, gid: Some(1600), system: false };
        assert_eq!(same.check(&ctx).unwrap(), Check::Compliant);
        same.apply(&ctx).unwrap();
        let moved = GroupSpec { gid: Some(1601), ..same.clone() };
        assert_eq!(moved.check(&ctx).unwrap(), Check::Drift(vec!["gid 1600 -> 1601".into()]));
        moved.apply(&ctx).unwrap();
        let gone = GroupSpec { name: "ops".into(), state: Presence::Absent, gid: None, system: false };
        assert_eq!(gone.check(&ctx).unwrap(), Check::Drift(vec!["exists".into()]));
        gone.apply(&ctx).unwrap();
        assert_eq!(GroupSpec { name: "nope".into(), ..gone.clone() }.check(&ctx).unwrap(), Check::Compliant);
        assert_eq!(runner.calls(), vec!["groupadd -g 1800 -r deploy", "groupmod -g 1601 web", "groupdel ops"]);
    }

    #[test]
    fn user_is_created_with_everything_declared() {
        let (_tmp, ctx, runner) = ctx(vec![(&["useradd"], 0, "")]);
        let spec = UserSpec {
            uid: Some(1501),
            group: Some("web".into()),
            groups: vec!["ops".into()],
            shell: Some("/bin/bash".into()),
            home: Some("/home/alice".into()),
            comment: Some("Alice".into()),
            create_home: true,
            ..user("alice")
        };
        assert_eq!(spec.check(&ctx).unwrap(), Check::Drift(vec!["missing".into()]));
        spec.apply(&ctx).unwrap();
        assert_eq!(runner.calls(), vec!["useradd -u 1501 -g web -s /bin/bash -d /home/alice -c Alice -G ops -m alice"]);
    }

    #[test]
    fn existing_user_changes_only_what_differs_and_memberships_are_additive() {
        let (_tmp, ctx, runner) = ctx(vec![(&["usermod"], 0, "")]);
        // Compliant: same uid, primary group app (1500), nothing else declared.
        let same = UserSpec { uid: Some(1500), group: Some("app".into()), groups: vec!["app".into()], ..user("app") };
        assert_eq!(same.check(&ctx).unwrap(), Check::Compliant);
        same.apply(&ctx).unwrap();
        assert!(runner.calls().is_empty());

        let spec = UserSpec { shell: Some("/bin/sh".into()), groups: vec!["web".into(), "app".into()], ..user("app") };
        assert_eq!(spec.check(&ctx).unwrap(), Check::Drift(vec!["shell /usr/sbin/nologin -> /bin/sh".into(), "not in group web".into()]));
        spec.apply(&ctx).unwrap();
        assert_eq!(runner.calls(), vec!["usermod -s /bin/sh -a -G web app"]);
    }

    #[test]
    fn user_absent_and_missing_primary_group() {
        let (_tmp, ctx, runner) = ctx(vec![(&["userdel"], 0, "")]);
        let gone = UserSpec { state: Presence::Absent, ..user("app") };
        assert_eq!(gone.check(&ctx).unwrap(), Check::Drift(vec!["exists".into()]));
        gone.apply(&ctx).unwrap();
        assert_eq!(runner.calls(), vec!["userdel app"]);
        assert_eq!(UserSpec { state: Presence::Absent, ..user("ghost") }.check(&ctx).unwrap(), Check::Compliant);
        let err = UserSpec { group: Some("nogroup".into()), ..user("app") }.check(&ctx).unwrap_err();
        assert!(err.to_string().contains("primary group 'nogroup' does not exist"), "{err}");
    }

    #[test]
    fn a_sandbox_root_refuses_to_change_accounts() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());
        assert_eq!(user("alice").check(&ctx).unwrap(), Check::Drift(vec!["missing".into()]));
        assert!(user("alice").apply(&ctx).unwrap_err().downcast_ref::<crate::runner::Refused>().is_some());
    }
}
