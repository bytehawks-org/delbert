//! The three names of the agent executable (docs/POLICY.md "The command line"): `delbert-agent`
//! does everything, `delbert` and `dg` change, `overlook` only looks. Aliases are symlinks here.
#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const POLICY: &str = "apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: p, tenant: t1 }\nspec:\n  resources:\n    - id: motd\n      copy: { content: \"hello\\n\", dest: /etc/motd, mode: \"0644\" }\n";

struct Setup {
    dir: tempfile::TempDir,
}

impl Setup {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for name in ["delbert", "dg", "overlook"] {
            symlink(env!("CARGO_BIN_EXE_delbert-agent"), dir.path().join(name)).unwrap();
        }
        fs::create_dir_all(dir.path().join("root/etc")).unwrap();
        fs::write(dir.path().join("policy.yaml"), POLICY).unwrap();
        Setup { dir }
    }

    fn motd(&self) -> PathBuf {
        self.dir.path().join("root/etc/motd")
    }

    /// Run `tool` (an alias, or `delbert-agent`) with a command on the sandbox root.
    fn run(&self, tool: &str, command: &str) -> Output {
        let exe: PathBuf = if tool == "delbert-agent" { env!("CARGO_BIN_EXE_delbert-agent").into() } else { self.dir.path().join(tool) };
        let policy = self.dir.path().join("policy.yaml");
        let mut cmd = Command::new(exe);
        cmd.args([command, policy.to_str().unwrap()]);
        // `validate` only reads the file: it has no sandbox root.
        if command != "validate" {
            cmd.args(["--root", self.dir.path().join("root").to_str().unwrap()]);
        }
        cmd.output().unwrap()
    }

    fn help(&self, tool: &str) -> String {
        let out = Command::new(self.dir.path().join(tool)).arg("--help").output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn overlook_looks_and_never_touches_and_dg_changes() {
    let s = Setup::new();
    // Drift is exit 2, and looking leaves no trace.
    assert_eq!(s.run("overlook", "check").status.code(), Some(2));
    assert!(!s.motd().exists());
    assert_eq!(s.run("overlook", "validate").status.code(), Some(0));
    // Changing goes through delbert or dg.
    assert_eq!(s.run("dg", "apply").status.code(), Some(0));
    assert_eq!(fs::read_to_string(s.motd()).unwrap(), "hello\n");
    assert_eq!(s.run("overlook", "check").status.code(), Some(0));
    // Both names change; the full name does everything.
    fs::remove_file(s.motd()).unwrap();
    assert_eq!(s.run("delbert", "apply").status.code(), Some(0));
    fs::remove_file(s.motd()).unwrap();
    assert_eq!(s.run("delbert-agent", "check").status.code(), Some(2));
    assert_eq!(s.run("delbert-agent", "apply").status.code(), Some(0));
    assert!(s.motd().exists());
}

#[test]
fn a_command_of_the_other_family_is_refused_with_a_pointer_and_does_nothing() {
    let s = Setup::new();
    let out = s.run("overlook", "apply");
    assert_eq!(out.status.code(), Some(64));
    assert!(stderr(&out).contains("dg apply") && stderr(&out).contains("overlook only looks"), "{}", stderr(&out));
    assert!(!s.motd().exists());
    for tool in ["dg", "delbert"] {
        let out = s.run(tool, "check");
        assert_eq!(out.status.code(), Some(64), "{tool}");
        assert!(stderr(&out).contains("overlook check"), "{}", stderr(&out));
    }
}

#[test]
fn help_lists_only_the_commands_of_the_family() {
    let s = Setup::new();
    let (overlook, dg) = (s.help("overlook"), s.help("dg"));
    for want in ["validate", "schema", "check", "check-signed"] {
        assert!(overlook.contains(want), "overlook --help lacks {want}:\n{overlook}");
    }
    assert!(!overlook.contains("apply") && !overlook.contains("enroll"), "{overlook}");
    for want in ["apply", "apply-signed", "enroll", "run"] {
        assert!(dg.contains(want), "dg --help lacks {want}:\n{dg}");
    }
    assert!(!dg.contains("validate") && !dg.contains("schema"), "{dg}");
    assert!(Path::new(env!("CARGO_BIN_EXE_delbert-agent")).is_file());
}
