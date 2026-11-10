//! Command execution for verbs that must call system tools (package managers,
//! `systemctl`). Always an argv vector: there is no shell and no interpolation.

use std::{
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
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

/// A program run for the `command` verb: as a given user, with a closed environment and a
/// deadline (see `command.rs`).
#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    /// uid and gid to switch to; `None` keeps the agent's own (root).
    pub user: Option<(u32, u32)>,
    /// The whole environment of the program: nothing is inherited from the agent.
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub timeout: Duration,
}

/// Most output kept from one stream of a program; the rest is read and dropped.
const MAX_OUTPUT: usize = 64 * 1024;

pub trait Runner: Send + Sync {
    fn run(&self, argv: &[&str]) -> Result<CmdOutput>;
    /// Run a program for the `command` verb. Killed, and an error, when it exceeds its timeout.
    fn exec(&self, request: &ExecRequest) -> Result<CmdOutput>;
}

/// Read a pipe to its end on a thread, keeping the first [`MAX_OUTPUT`] bytes.
fn drain(pipe: Option<impl Read + Send + 'static>) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buffer = [0u8; 8192];
        if let Some(mut pipe) = pipe {
            while let Ok(n) = pipe.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                let room = MAX_OUTPUT.saturating_sub(kept.len());
                kept.extend_from_slice(&buffer[..n.min(room)]);
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&kept).into_owned());
    });
    rx
}

/// Spawn the program of an [`ExecRequest`] and wait for it, at most until its deadline.
pub fn exec_on_host(request: &ExecRequest) -> Result<CmdOutput> {
    let (program, args) = request.argv.split_first().context("empty command")?;
    let mut command = Command::new(program);
    command.args(args).env_clear().envs(request.env.iter().cloned()).current_dir(&request.cwd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    if let Some((uid, gid)) = request.user {
        use std::os::unix::process::CommandExt;
        // With a uid set, the standard library also drops the supplementary groups of the agent.
        command.uid(uid).gid(gid);
    }
    #[cfg(not(unix))]
    if request.user.is_some() {
        bail!("running a command as another user is not supported on this platform");
    }
    let mut child = command.spawn().with_context(|| format!("cannot run '{program}'"))?;
    let (stdout, stderr) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let deadline = Instant::now() + request.timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            // Its output is not waited for: a grandchild may still hold the pipes open.
            bail!("`{program}` timed out after {}s and was killed", request.timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    // The program has exited; a grandchild that keeps a pipe open must not hang the agent.
    let read = |rx: std::sync::mpsc::Receiver<String>| rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    Ok(CmdOutput { code: status.code(), stdout: read(stdout), stderr: read(stderr) })
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

    fn exec(&self, request: &ExecRequest) -> Result<CmdOutput> {
        exec_on_host(request)
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

    fn exec(&self, request: &ExecRequest) -> Result<CmdOutput> {
        Err(Refused(request.argv.join(" ")).into())
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
                    CmdOutput { code: Some(code), stdout: out.into(), stderr: if code == 0 { String::new() } else { out.into() } },
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

    /// Answered from the same script as `run`; the call is recorded with the user it would run as.
    fn exec(&self, request: &ExecRequest) -> Result<CmdOutput> {
        let argv: Vec<&str> = request.argv.iter().map(String::as_str).collect();
        let out = self.run(&argv)?;
        if let (Some((uid, gid)), Some(last)) = (request.user, self.calls.lock().unwrap().last_mut()) {
            *last = format!("[{uid}:{gid}] {last}");
        }
        Ok(out)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn request(argv: &[&str], secs: u64) -> ExecRequest {
        ExecRequest { argv: argv.iter().map(|s| s.to_string()).collect(), user: None, env: vec![("GREETING".into(), "hello".into())], cwd: "/".into(), timeout: Duration::from_secs(secs) }
    }

    #[test]
    fn a_program_gets_only_the_given_environment_and_its_result_is_captured() {
        // No shell is involved in `exec`; `sh -c` is used here only as a program to observe.
        let out = exec_on_host(&request(&["/bin/sh", "-c", "echo \"$GREETING ${HOME:-nohome} $PWD\"; echo oops >&2; exit 3"], 10)).unwrap();
        assert_eq!((out.code, out.stdout.as_str(), out.stderr.as_str()), (Some(3), "hello nohome /\n", "oops\n"));
        assert!(exec_on_host(&request(&["/nonexistent/program"], 10)).unwrap_err().to_string().contains("cannot run"));
    }

    #[test]
    fn a_program_that_exceeds_its_timeout_is_killed() {
        let started = Instant::now();
        let err = exec_on_host(&request(&["/bin/sleep", "30"], 1)).unwrap_err();
        assert!(err.to_string().contains("timed out after 1s"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn long_output_is_cut_and_never_blocks_the_program() {
        let out = exec_on_host(&request(&["/bin/sh", "-c", "head -c 300000 /dev/zero | tr '\\0' x"], 20)).unwrap();
        assert_eq!((out.code, out.stdout.len()), (Some(0), MAX_OUTPUT));
    }
}
