//! Command execution for verbs that must call system tools (package managers,
//! `systemctl`). Always an argv vector: there is no shell and no interpolation.

use std::{
    process::{Command, Stdio},
    sync::Mutex,
};

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Default)]
pub struct CmdOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    /// Fail with a short, readable message unless the command succeeded.
    pub fn check(self, argv: &[&str]) -> Result<Self> {
        if self.ok() {
            return Ok(self);
        }
        let detail: String = self.stderr.trim().chars().take(300).collect();
        bail!("`{}` failed (exit {:?}): {detail}", argv.join(" "), self.code)
    }
}

pub trait Runner: Send + Sync {
    fn run(&self, argv: &[&str]) -> Result<CmdOutput>;
}

/// Runs commands on the host.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, argv: &[&str]) -> Result<CmdOutput> {
        let (program, args) = argv.split_first().context("empty command")?;
        let out = Command::new(program)
            .args(args)
            .env("DEBIAN_FRONTEND", "noninteractive")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("cannot run '{program}'"))?;
        Ok(CmdOutput {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Used when the agent works on a sandbox `--root`: commands would act on the
/// real host, so they are refused.
pub struct SandboxRunner;

/// Error returned by [`SandboxRunner`]; callers must not mistake it for "tool not installed".
#[derive(Debug, thiserror::Error)]
#[error("command execution is disabled in a sandbox root (`{0}`)")]
pub struct Refused(pub String);

impl Runner for SandboxRunner {
    fn run(&self, argv: &[&str]) -> Result<CmdOutput> {
        Err(Refused(argv.join(" ")).into())
    }
}

/// Test double: records calls and answers from a script of `(argv prefix, output)`.
pub struct FakeRunner {
    script: Vec<(Vec<String>, CmdOutput)>,
    /// Entries already answered: the same command can be scripted several times
    /// and is answered in order (the last one repeats).
    used: Mutex<Vec<bool>>,
    pub calls: Mutex<Vec<String>>,
}

impl FakeRunner {
    pub fn new(script: Vec<(&[&str], i32, &str)>) -> Self {
        let script: Vec<(Vec<String>, CmdOutput)> = script
            .into_iter()
            .map(|(p, code, out)| {
                (
                    p.iter().map(|s| s.to_string()).collect(),
                    CmdOutput { code: Some(code), stdout: out.into(), stderr: String::new() },
                )
            })
            .collect();
        let used: Mutex<Vec<bool>> = Mutex::new(vec![false; script.len()]);
        FakeRunner { script, used, calls: Mutex::new(Vec::new()) }
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Runner for FakeRunner {
    fn run(&self, argv: &[&str]) -> Result<CmdOutput> {
        self.calls.lock().unwrap().push(argv.join(" "));
        let matching: Vec<usize> = (0..self.script.len())
            .filter(|&i| {
                let prefix = &self.script[i].0;
                argv.len() >= prefix.len() && prefix.iter().zip(argv).all(|(a, b)| a == b)
            })
            .collect();
        let mut used = self.used.lock().unwrap();
        let pick = matching.iter().copied().find(|&i| !used[i]).or(matching.last().copied());
        match pick {
            Some(i) => {
                used[i] = true;
                Ok(self.script[i].1.clone())
            }
            None => bail!("cannot run '{}': not found", argv[0]),
        }
    }
}
