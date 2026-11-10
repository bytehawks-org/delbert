//! The `mount` verb: one line of `/etc/fstab` and whether the filesystem is mounted now
//! (docs/POLICY.md "Mounts").
//!
//! `/etc/fstab` is edited as text, one line, and replaced crash-safely; every other line stays
//! byte for byte. What is mounted is read from `/proc/mounts`; mounting and unmounting go through
//! `mount <path>` and `umount <path>` (argv, no shell), which read the line just written, so the
//! file and the running system cannot disagree. Not available on Windows.

use std::fs;

use anyhow::{Context, Result, bail};
use delbert_policy::{MountSpec, MountState};

use crate::engine::Ctx;
use crate::fsutil::{Attrs, write_atomic};
use crate::verbs::{Check, Verb};

const FSTAB: &str = "/etc/fstab";

/// The six fields of the policy's fstab line.
fn fields(spec: &MountSpec) -> [String; 6] {
    [
        spec.src.clone().unwrap_or_default(),
        spec.path.clone(),
        spec.fstype.clone().unwrap_or_default(),
        spec.opts.clone().unwrap_or_else(|| "defaults".into()),
        spec.dump.to_string(),
        spec.passno.to_string(),
    ]
}

/// Does this fstab line describe the mount point `path`? Comments and blank lines never do.
fn is_entry(line: &str, path: &str) -> bool {
    !line.trim_start().starts_with('#') && line.split_whitespace().nth(1) == Some(path)
}

/// Pure fstab editing: the line of the mount point is replaced where it is (appended when new) or
/// removed. Returns the content unchanged, byte for byte, when the line already says the same.
pub fn edit_fstab(content: &str, spec: &MountSpec) -> String {
    let wanted = fields(spec);
    let present = spec.state != MountState::Absent;
    let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
    let existing = lines.iter().position(|l| is_entry(l, &spec.path));
    match (existing, present) {
        (Some(i), true) => {
            // Missing fifth and sixth fields mean 0 0.
            let mut have: Vec<&str> = lines[i].split_whitespace().collect();
            have.resize(6, "0");
            if have == wanted {
                return content.to_owned();
            }
            lines[i] = wanted.join(" ");
        }
        (None, true) => lines.push(wanted.join(" ")),
        (Some(_), false) => lines.retain(|l| !is_entry(l, &spec.path)),
        (None, false) => return content.to_owned(),
    }
    let mut out = lines.join("\n");
    if !lines.is_empty() {
        out.push('\n');
    }
    out
}

/// A missing fstab is an empty one.
fn fstab(ctx: &Ctx) -> Result<String> {
    match fs::read_to_string(ctx.path(FSTAB)) {
        Ok(content) => Ok(content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).context("reading /etc/fstab"),
    }
}

fn is_mounted(ctx: &Ctx, path: &str) -> bool {
    fs::read_to_string(ctx.path("/proc/mounts")).is_ok_and(|mounts| mounts.lines().any(|l| l.split_whitespace().nth(1) == Some(path.trim_end_matches('/'))))
}

/// The mount state the policy asks for; `None` leaves it alone (`present`).
fn wants_mounted(state: MountState) -> Option<bool> {
    match state {
        MountState::Mounted => Some(true),
        MountState::Present => None,
        MountState::Unmounted | MountState::Absent => Some(false),
    }
}

fn run(ctx: &Ctx, argv: &[&str]) -> Result<()> {
    ctx.runner.run(argv)?.check(argv).map(drop)
}

impl Verb for MountSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        if cfg!(windows) {
            bail!("mount is not supported on Windows");
        }
        let current = fstab(ctx)?;
        let mut drift = Vec::new();
        if edit_fstab(&current, self) != current {
            drift.push(if self.state == MountState::Absent { "in fstab" } else { "fstab entry differs" }.to_string());
        }
        match (wants_mounted(self.state), is_mounted(ctx, &self.path)) {
            (Some(true), false) => drift.push("not mounted".into()),
            (Some(false), true) => drift.push("mounted".into()),
            _ => {}
        }
        Ok(if drift.is_empty() { Check::Compliant } else { Check::Drift(drift) })
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        if cfg!(windows) {
            bail!("mount is not supported on Windows");
        }
        let mounted = is_mounted(ctx, &self.path);
        // Unmount first, while fstab still has the line; a busy filesystem fails the resource
        // and leaves fstab as it was.
        if wants_mounted(self.state) == Some(false) && mounted {
            run(ctx, &["umount", &self.path])?;
        }
        let current = fstab(ctx)?;
        let desired = edit_fstab(&current, self);
        let changed = desired != current;
        if changed {
            write_atomic(ctx, &ctx.path(FSTAB), desired.as_bytes(), Attrs { owner: None, group: None, mode: None })?;
        }
        if wants_mounted(self.state) == Some(true) {
            if !mounted {
                run(ctx, &["mount", &self.path])?;
            } else if changed {
                // New options take effect now; a different source or type needs an unmount, which
                // is never done by inference (declare `unmounted` for a version).
                run(ctx, &["mount", "-o", "remount", &self.path])?;
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::runner::FakeRunner;

    const FSTAB_TEXT: &str = "# /etc/fstab\nUUID=aaaa / ext4 errors=remount-ro 0 1\n\nUUID=bbbb\t/srv/data\text4\tdefaults\n";

    fn spec(state: MountState) -> MountSpec {
        MountSpec { path: "/srv/share".into(), src: Some("nas.example.com:/export".into()), fstype: Some("nfs".into()), opts: Some("ro,noexec".into()), state, dump: 0, passno: 0 }
    }

    #[test]
    fn fstab_lines_are_added_replaced_in_place_and_removed() {
        let added = edit_fstab(FSTAB_TEXT, &spec(MountState::Mounted));
        assert_eq!(added, format!("{FSTAB_TEXT}nas.example.com:/export /srv/share nfs ro,noexec 0 0\n"));
        assert_eq!(edit_fstab(&added, &spec(MountState::Present)), added);
        // An entry that says the same in another layout (tabs, no dump/pass fields) is left alone.
        let data = MountSpec { path: "/srv/data".into(), src: Some("UUID=bbbb".into()), fstype: Some("ext4".into()), opts: None, state: MountState::Mounted, dump: 0, passno: 0 };
        assert_eq!(edit_fstab(FSTAB_TEXT, &data), FSTAB_TEXT);
        let changed = edit_fstab(FSTAB_TEXT, &MountSpec { opts: Some("noatime".into()), passno: 2, ..data.clone() });
        assert_eq!(changed, "# /etc/fstab\nUUID=aaaa / ext4 errors=remount-ro 0 1\n\nUUID=bbbb /srv/data ext4 noatime 0 2\n");
        let removed = edit_fstab(&added, &MountSpec { src: None, fstype: None, opts: None, ..spec(MountState::Absent) });
        assert_eq!(removed, FSTAB_TEXT);
        assert_eq!(edit_fstab(FSTAB_TEXT, &spec(MountState::Absent)), FSTAB_TEXT);
        // A commented line is not an entry.
        assert!(edit_fstab("#x /srv/share nfs ro 0 0\n", &spec(MountState::Present)).starts_with("#x /srv/share nfs ro 0 0\nnas"));
    }

    fn ctx(mounts: &str, script: Vec<(&[&str], i32, &str)>) -> (tempfile::TempDir, Ctx, Arc<FakeRunner>) {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::create_dir_all(tmp.path().join("proc")).unwrap();
        fs::write(tmp.path().join("etc/fstab"), FSTAB_TEXT).unwrap();
        fs::write(tmp.path().join("proc/mounts"), mounts).unwrap();
        let runner = Arc::new(FakeRunner::new(script));
        let mut ctx = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());
        ctx.runner = runner.clone();
        (tmp, ctx, runner)
    }

    #[test]
    fn mounted_writes_fstab_then_mounts_and_remounts_on_a_change() {
        let (tmp, ctx, runner) = ctx("/dev/sda1 / ext4 rw 0 0\n", vec![(&["mount"], 0, "")]);
        assert_eq!(spec(MountState::Mounted).check(&ctx).unwrap(), Check::Drift(vec!["fstab entry differs".into(), "not mounted".into()]));
        spec(MountState::Mounted).apply(&ctx).unwrap();
        assert!(fs::read_to_string(tmp.path().join("etc/fstab")).unwrap().ends_with("nas.example.com:/export /srv/share nfs ro,noexec 0 0\n"));
        assert_eq!(runner.calls(), vec!["mount /srv/share"]);

        // Now mounted, with other options in the policy: fstab changes and the mount is refreshed.
        fs::write(tmp.path().join("proc/mounts"), "nas.example.com:/export /srv/share nfs ro 0 0\n").unwrap();
        assert_eq!(spec(MountState::Mounted).check(&ctx).unwrap(), Check::Compliant);
        let other = MountSpec { opts: Some("ro".into()), ..spec(MountState::Mounted) };
        assert_eq!(other.check(&ctx).unwrap(), Check::Drift(vec!["fstab entry differs".into()]));
        other.apply(&ctx).unwrap();
        assert_eq!(runner.calls()[1], "mount -o remount /srv/share");
    }

    #[test]
    fn present_leaves_the_mount_alone_and_absent_unmounts_before_touching_fstab() {
        let mounted = "nas.example.com:/export /srv/share nfs ro 0 0\n";
        let (_tmp, c, runner) = ctx("", vec![]);
        spec(MountState::Present).apply(&c).unwrap();
        assert!(runner.calls().is_empty());
        assert_eq!(spec(MountState::Present).check(&c).unwrap(), Check::Compliant);

        // A busy filesystem: umount fails, fstab keeps its line.
        let (tmp, c, runner) = ctx(mounted, vec![(&["umount"], 32, "target is busy")]);
        spec(MountState::Mounted).apply(&c).unwrap_or(()); // puts the line in fstab (already mounted: remount is not scripted)
        let with_line = fs::read_to_string(tmp.path().join("etc/fstab")).unwrap();
        let gone = spec(MountState::Absent);
        assert_eq!(gone.check(&c).unwrap(), Check::Drift(vec!["in fstab".into(), "mounted".into()]));
        assert!(gone.apply(&c).unwrap_err().to_string().contains("umount /srv/share"));
        assert_eq!(fs::read_to_string(tmp.path().join("etc/fstab")).unwrap(), with_line);
        assert!(runner.calls().contains(&"umount /srv/share".to_string()));

        let (tmp, c, runner) = ctx(mounted, vec![(&["umount"], 0, "")]);
        spec(MountState::Unmounted).apply(&c).unwrap();
        assert_eq!(runner.calls(), vec!["umount /srv/share"]);
        assert!(fs::read_to_string(tmp.path().join("etc/fstab")).unwrap().contains("/srv/share nfs"));
    }
}
