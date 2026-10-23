//! Verb implementations: `file`, `copy`, `line_in_file`.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, bail};
use delbert_policy::{CopySpec, FileSpec, FileState, LineInFileSpec, Presence, TemplateSpec};
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::engine::Ctx;
use crate::fsutil::{Attrs, apply_attrs, attrs_drift, write_atomic};

/// Result of a side-effect-free check.
#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    Compliant,
    Drift(Vec<String>),
}

impl Check {
    fn from_drift(drift: Vec<String>) -> Self {
        if drift.is_empty() { Check::Compliant } else { Check::Drift(drift) }
    }
}

pub trait Verb {
    /// Compare the host with the desired state. Must not change anything.
    fn check(&self, ctx: &Ctx) -> Result<Check>;
    /// Converge the host to the desired state.
    fn apply(&self, ctx: &Ctx) -> Result<()>;
    /// One-shot actions (e.g. reload) are always "drifted" and cannot be
    /// verified afterwards; the engine skips the post-apply check for them.
    fn is_action(&self) -> bool {
        false
    }
}

// --- file -------------------------------------------------------------------

fn file_attrs(spec: &FileSpec) -> Attrs<'_> {
    Attrs { owner: spec.owner.as_deref(), group: spec.group.as_deref(), mode: spec.mode.as_deref() }
}

impl Verb for FileSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        let path = ctx.path(&self.path);
        let meta = fs::symlink_metadata(&path).ok();
        let drift = match (self.state, meta) {
            (FileState::Absent, None) => vec![],
            (FileState::Absent, Some(_)) => vec!["exists".into()],
            (_, None) => vec!["missing".into()],
            (FileState::File, Some(m)) if !m.is_file() => vec!["not a regular file".into()],
            (FileState::Directory, Some(m)) if !m.is_dir() => vec!["not a directory".into()],
            (FileState::Link, Some(m)) => {
                let want = self.target.as_deref().unwrap_or_default();
                if m.file_type().is_symlink() && fs::read_link(&path).is_ok_and(|t| t.to_str() == Some(want)) {
                    vec![]
                } else {
                    vec![format!("link target != {want}")]
                }
            }
            (_, Some(m)) => attrs_drift(ctx, &m, file_attrs(self))?,
        };
        Ok(Check::from_drift(drift))
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        let path = ctx.path(&self.path);
        let meta = fs::symlink_metadata(&path).ok();
        match self.state {
            FileState::Absent => match meta {
                None => {}
                // Never delete recursively: a non-empty directory is an error.
                Some(m) if m.is_dir() => fs::remove_dir(&path).context("refusing to remove a non-empty directory")?,
                Some(_) => fs::remove_file(&path)?,
            },
            FileState::File => {
                match meta {
                    None => drop(fs::OpenOptions::new().write(true).create_new(true).open(&path)?),
                    Some(m) if !m.is_file() => bail!("{} exists and is not a regular file", self.path),
                    Some(_) => {}
                }
                apply_attrs(ctx, &path, file_attrs(self))?;
            }
            FileState::Directory => {
                match meta {
                    None => fs::create_dir_all(&path)?,
                    Some(m) if !m.is_dir() => bail!("{} exists and is not a directory", self.path),
                    Some(_) => {}
                }
                apply_attrs(ctx, &path, file_attrs(self))?;
            }
            FileState::Link => {
                let target = self.target.as_deref().context("state 'link' requires 'target'")?;
                match meta {
                    Some(m) if m.file_type().is_symlink() => fs::remove_file(&path)?,
                    Some(_) => bail!("{} exists and is not a symlink", self.path),
                    None => {}
                }
                std::os::unix::fs::symlink(target, &path)?;
            }
        }
        Ok(())
    }
}

// --- copy -------------------------------------------------------------------

fn artifact_bytes(ctx: &Ctx, src: &str) -> Result<Vec<u8>> {
    let name = src.strip_prefix("artifact://").context("src must be an artifact:// reference")?;
    if name.is_empty() || name.contains('/') || name.contains("..") {
        bail!("invalid artifact name '{name}'");
    }
    let bytes = fs::read(ctx.artifacts.join(name)).with_context(|| format!("reading artifact '{name}'"))?;
    // When the signed policy pins the artifact, never use anything else.
    if let Some(expected) = ctx.artifact_hashes.get(name) {
        let actual: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        if actual != *expected {
            bail!("artifact '{name}' does not match the pinned SHA-256");
        }
    }
    Ok(bytes)
}

/// Check a whole-file target against the bytes it must contain.
fn content_check(ctx: &Ctx, path: &Path, desired: &[u8], attrs: Attrs) -> Result<Check> {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return Ok(Check::Drift(vec!["missing".into()]));
    };
    if !meta.is_file() {
        return Ok(Check::Drift(vec!["not a regular file".into()]));
    }
    let mut drift = Vec::new();
    if fs::read(path)? != desired {
        drift.push("content differs".to_string());
    }
    drift.extend(attrs_drift(ctx, &meta, attrs)?);
    Ok(Check::from_drift(drift))
}

fn content_apply(ctx: &Ctx, path: &Path, desired: &[u8], attrs: Attrs) -> Result<()> {
    if fs::read(path).is_ok_and(|current| current == desired) {
        apply_attrs(ctx, path, attrs)
    } else {
        write_atomic(ctx, path, desired, attrs)
    }
}

fn copy_attrs(spec: &CopySpec) -> Attrs<'_> {
    Attrs { owner: spec.owner.as_deref(), group: spec.group.as_deref(), mode: spec.mode.as_deref() }
}

/// Bytes the destination must contain: inline content or a named artifact.
fn copy_desired(spec: &CopySpec, ctx: &Ctx) -> Result<Vec<u8>> {
    match (&spec.content, &spec.src) {
        (Some(content), _) => Ok(content.clone().into_bytes()),
        (None, Some(src)) => artifact_bytes(ctx, src),
        (None, None) => bail!("copy requires 'src' or 'content'"),
    }
}

impl Verb for CopySpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        content_check(ctx, &ctx.path(&self.dest), &copy_desired(self, ctx)?, copy_attrs(self))
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        content_apply(ctx, &ctx.path(&self.dest), &copy_desired(self, ctx)?, copy_attrs(self))
    }
}

// --- template -----------------------------------------------------------------

fn template_attrs(spec: &TemplateSpec) -> Attrs<'_> {
    Attrs { owner: spec.owner.as_deref(), group: spec.group.as_deref(), mode: spec.mode.as_deref() }
}

/// Render the template on the agent. Undefined variables are errors, and the
/// engine has no loader or functions that could read files or run commands.
fn render(spec: &TemplateSpec, ctx: &Ctx) -> Result<Vec<u8>> {
    let source = String::from_utf8(artifact_bytes(ctx, &spec.src)?).context("template is not valid UTF-8")?;
    let mut vars: BTreeMap<&String, &serde_json::Value> = ctx.vars.iter().collect();
    vars.extend(spec.vars.iter());
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    env.set_keep_trailing_newline(true);
    let out = env
        .render_str(&source, minijinja::context! { vars => vars, secrets => &ctx.secrets, facts => ctx.facts() })
        .with_context(|| format!("rendering {}", spec.src))?;
    Ok(out.into_bytes())
}

impl Verb for TemplateSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        content_check(ctx, &ctx.path(&self.dest), &render(self, ctx)?, template_attrs(self))
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        content_apply(ctx, &ctx.path(&self.dest), &render(self, ctx)?, template_attrs(self))
    }
}

// --- line_in_file -------------------------------------------------------------

fn compile(pattern: Option<&str>) -> Result<Option<Regex>> {
    pattern.map(|p| Regex::new(p).with_context(|| format!("invalid regexp '{p}'"))).transpose()
}

/// Pure line editing, so it can be tested without a filesystem. Returns the
/// content unchanged (byte for byte) when nothing needs to change.
pub fn edit_lines(content: &str, spec: &LineInFileSpec) -> Result<String> {
    let mut lines: Vec<String> = content.split('\n').map(str::to_owned).collect();
    if content.ends_with('\n') || content.is_empty() {
        lines.pop(); // empty element after the final newline
    }
    let matches = |re: &Regex, l: &str| re.is_match(l.trim_end_matches('\r'));
    let last_match = |lines: &[String], re: &Regex| lines.iter().rposition(|l| matches(re, l));

    let regexp = compile(spec.regexp.as_deref())?;
    let mut changed = false;

    match spec.state {
        Presence::Present => {
            let existing = match &regexp {
                Some(re) => last_match(&lines, re),
                None => lines.iter().position(|l| *l == spec.line),
            };
            match existing {
                Some(i) => {
                    if lines[i] != spec.line {
                        lines[i] = spec.line.clone();
                        changed = true;
                    }
                }
                None => {
                    let after = compile(spec.insert_after.as_deref())?;
                    let before = compile(spec.insert_before.as_deref())?;
                    let at = match (&after, &before) {
                        (Some(re), _) => last_match(&lines, re).map(|i| i + 1),
                        (_, Some(re)) => last_match(&lines, re),
                        _ => None,
                    };
                    lines.insert(at.unwrap_or(lines.len()), spec.line.clone());
                    changed = true;
                }
            }
        }
        Presence::Absent => {
            let before = lines.len();
            lines.retain(|l| match &regexp {
                Some(re) => !matches(re, l),
                None => *l != spec.line,
            });
            changed = lines.len() != before;
        }
    }

    if !changed {
        return Ok(content.to_owned());
    }
    let mut out = lines.join("\n");
    if !lines.is_empty() {
        out.push('\n');
    }
    Ok(out)
}

/// Current and desired content; `None` when there is nothing to do because
/// the file is absent and the line must be absent too.
fn line_contents(spec: &LineInFileSpec, ctx: &Ctx) -> Result<Option<(String, String)>> {
    let current = match fs::read_to_string(ctx.path(&spec.path)) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && spec.state == Presence::Absent => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", spec.path)),
    };
    let desired = edit_lines(&current, spec)?;
    Ok(Some((current, desired)))
}

impl Verb for LineInFileSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        Ok(match line_contents(self, ctx)? {
            Some((current, desired)) if current != desired => Check::Drift(vec!["line(s) differ".into()]),
            _ => Check::Compliant,
        })
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        if let Some((current, desired)) = line_contents(self, ctx)? {
            if current != desired {
                write_atomic(ctx, &ctx.path(&self.path), desired.as_bytes(), Attrs::default())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template(src: &str, dest: &str) -> TemplateSpec {
        TemplateSpec { src: src.into(), dest: dest.into(), vars: BTreeMap::new(), owner: None, group: None, mode: None }
    }

    #[test]
    fn template_renders_vars_facts_and_converges() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::create_dir_all(tmp.path().join("artifacts")).unwrap();
        fs::write(tmp.path().join("etc/hostname"), "web1\n").unwrap();
        fs::write(tmp.path().join("artifacts/app.j2"), "host={{ facts.hostname }} port={{ vars.port }} env={{ vars.env }}\n").unwrap();
        let mut ctx = Ctx::new(tmp.path().to_path_buf(), tmp.path().join("artifacts"));
        ctx.vars.insert("port".into(), serde_json::json!(8080));
        ctx.vars.insert("env".into(), serde_json::json!("prod"));
        let mut spec = template("artifact://app.j2", "/etc/app.conf");
        spec.vars.insert("env".into(), serde_json::json!("staging")); // per-resource override

        assert!(matches!(spec.check(&ctx).unwrap(), Check::Drift(_)));
        spec.apply(&ctx).unwrap();
        assert_eq!(fs::read_to_string(tmp.path().join("etc/app.conf")).unwrap(), "host=web1 port=8080 env=staging\n");
        assert_eq!(spec.check(&ctx).unwrap(), Check::Compliant);
    }

    #[test]
    fn template_secrets_and_pinned_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::create_dir_all(tmp.path().join("artifacts")).unwrap();
        fs::write(tmp.path().join("artifacts/db.j2"), "password={{ secrets.db }}\n").unwrap();
        let mut ctx = Ctx::new(tmp.path().to_path_buf(), tmp.path().join("artifacts"));
        ctx.secrets.insert("db".into(), "s3cr3t".into());
        let spec = template("artifact://db.j2", "/etc/db.conf");
        spec.apply(&ctx).unwrap();
        assert_eq!(fs::read_to_string(tmp.path().join("etc/db.conf")).unwrap(), "password=s3cr3t\n");

        // A pinned hash that does not match refuses the artifact.
        ctx.artifact_hashes.insert("db.j2".into(), "00".repeat(32));
        assert!(spec.check(&ctx).unwrap_err().to_string().contains("pinned SHA-256"));
        let real: String = Sha256::digest(b"password={{ secrets.db }}\n").iter().map(|b| format!("{b:02x}")).collect();
        ctx.artifact_hashes.insert("db.j2".into(), real);
        assert_eq!(spec.check(&ctx).unwrap(), Check::Compliant);
    }

    #[test]
    fn template_undefined_variable_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("artifacts")).unwrap();
        fs::write(tmp.path().join("artifacts/a.j2"), "{{ vars.nope }}").unwrap();
        let ctx = Ctx::new(tmp.path().to_path_buf(), tmp.path().join("artifacts"));
        assert!(template("artifact://a.j2", "/x").check(&ctx).is_err());
    }

    fn spec(line: &str) -> LineInFileSpec {
        LineInFileSpec {
            path: "/x".into(),
            line: line.into(),
            regexp: None,
            state: Presence::Present,
            insert_after: None,
            insert_before: None,
        }
    }

    #[test]
    fn appends_missing_line_and_is_idempotent() {
        let s = spec("b");
        let once = edit_lines("a\n", &s).unwrap();
        assert_eq!(once, "a\nb\n");
        assert_eq!(edit_lines(&once, &s).unwrap(), once);
    }

    #[test]
    fn unchanged_content_is_returned_byte_for_byte() {
        assert_eq!(edit_lines("a\nb", &spec("b")).unwrap(), "a\nb");
    }

    #[test]
    fn regexp_replaces_last_match() {
        let mut s = spec("PermitRootLogin no");
        s.regexp = Some("^#?PermitRootLogin".into());
        assert_eq!(
            edit_lines("x\n#PermitRootLogin yes\ny\n", &s).unwrap(),
            "x\nPermitRootLogin no\ny\n"
        );
    }

    #[test]
    fn insert_after_and_before() {
        let mut s = spec("new");
        s.insert_after = Some("^a$".into());
        assert_eq!(edit_lines("a\nb\n", &s).unwrap(), "a\nnew\nb\n");
        let mut s = spec("new");
        s.insert_before = Some("^b$".into());
        assert_eq!(edit_lines("a\nb\n", &s).unwrap(), "a\nnew\nb\n");
    }

    #[test]
    fn absent_removes_matching_lines() {
        let mut s = spec("b");
        s.state = Presence::Absent;
        assert_eq!(edit_lines("a\nb\nb\nc\n", &s).unwrap(), "a\nc\n");
        assert_eq!(edit_lines("a\nc\n", &s).unwrap(), "a\nc\n");
    }

    #[test]
    fn empty_file_gets_the_line() {
        assert_eq!(edit_lines("", &spec("a")).unwrap(), "a\n");
    }
}
