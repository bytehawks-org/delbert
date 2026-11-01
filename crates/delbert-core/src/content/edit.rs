//! Editing a repository from the console (docs/REPOSITORY.md "Editing").
//!
//! The editor never touches the tracked branch of a git remote. A commit goes to a **new branch**
//! (`delbert/<user>-<time>`) that the forge turns into a merge request: review and branch
//! protection stay where they belong, and the four-eyes rule is the forge's. A directory source is
//! the exception, because there is nothing to review in a folder: the files are written in place and
//! picked up by the next sync.
//!
//! Before anything is written the resulting tree is validated as a whole with the same parser the
//! sync uses. A change is refused if it introduces a problem that was not there before, so a
//! repository that is already broken can still be repaired one file at a time.

use std::{collections::BTreeSet, path::Path as FsPath};

use axum::{
    Json,
    extract::{Path, Query, State},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use super::{Snapshot, Source, authorize, check_rel, err, load, parse_layout, read_snapshot};
use crate::{
    api::{ApiResult, AppState},
    audit::{self, NewEvent},
    auth::Authn,
};
use axum::http::StatusCode;

const MAX_CHANGES: usize = 200;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_MESSAGE: usize = 500;

#[derive(Serialize, ToSchema)]
pub struct FileEntry {
    pub path: String,
    pub size: usize,
}

#[derive(Serialize, ToSchema)]
pub struct TreeOut {
    /// Commit id (git) or tree hash (directory) the list was read from.
    pub revision: String,
    pub writable: bool,
    /// Owning tenant of the source; absent for a platform source.
    pub tenant: Option<String>,
    pub files: Vec<FileEntry>,
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TreeQuery {
    /// Ask the remote first (default: what the last sync left in the mirror).
    #[serde(default)]
    pub refresh: bool,
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FileQuery {
    pub path: String,
}

#[derive(Serialize, ToSchema)]
pub struct FileOut {
    pub path: String,
    pub revision: String,
    /// `utf8`, or `base64` for content that is not text.
    pub encoding: String,
    pub content: String,
}

/// One file of a change set: new content (text, or base64 for binary) or a deletion.
#[derive(Deserialize, ToSchema, Clone)]
pub struct FileChange {
    pub path: String,
    pub content: Option<String>,
    pub content_b64: Option<String>,
    #[serde(default)]
    pub delete: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct ChangeSet {
    pub changes: Vec<FileChange>,
}

#[derive(Serialize, ToSchema)]
pub struct ValidateOut {
    pub ok: bool,
    /// Problems the change would introduce, naming the files.
    pub errors: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct CommitBody {
    pub message: String,
    pub changes: Vec<FileChange>,
}

#[derive(Serialize, ToSchema)]
pub struct CommitOut {
    /// The branch that was pushed (git sources); absent for a directory.
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub files: usize,
    /// Revision the change was made on.
    pub base_revision: String,
}

fn mirror_dir_name(path: &str) -> bool {
    path.split('/').any(|c| c == ".git" || c.is_empty() || c == "." || c == "..")
}

async fn tenant_name(st: &AppState, s: &Source) -> ApiResult<Option<String>> {
    Ok(match s.tenant_id {
        Some(t) => sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1").bind(t).fetch_optional(&st.pool).await?,
        None => None,
    })
}

/// The files after the change, or the first reason it cannot be applied.
fn apply(base: &Snapshot, changes: &[FileChange]) -> Result<std::collections::BTreeMap<String, Vec<u8>>, String> {
    if changes.is_empty() || changes.len() > MAX_CHANGES {
        return Err(format!("a change set has 1 to {MAX_CHANGES} files"));
    }
    let mut files = base.files.clone();
    let mut seen = BTreeSet::new();
    let mut total = 0usize;
    for c in changes {
        if mirror_dir_name(&c.path) {
            return Err(format!("invalid path '{}'", c.path));
        }
        check_rel(&c.path)?;
        if !seen.insert(c.path.as_str()) {
            return Err(format!("'{}' appears twice", c.path));
        }
        if c.delete {
            if files.remove(&c.path).is_none() {
                return Err(format!("'{}' does not exist", c.path));
            }
            continue;
        }
        let bytes = match (&c.content, &c.content_b64) {
            (Some(text), None) => text.clone().into_bytes(),
            (None, Some(b)) => B64.decode(b).map_err(|_| format!("'{}': content_b64 is not base64", c.path))?,
            _ => return Err(format!("'{}': give exactly one of content, content_b64 or delete", c.path)),
        };
        total += bytes.len();
        if bytes.len() > MAX_FILE_BYTES || total > 4 * MAX_FILE_BYTES {
            return Err(format!("'{}' is too large for the editor (1 MiB a file, 4 MiB a change)", c.path));
        }
        files.insert(c.path.clone(), bytes);
    }
    Ok(files)
}

/// Problems the change adds to the tree.
fn new_problems(base: &Snapshot, after: &std::collections::BTreeMap<String, Vec<u8>>, owner: Option<&str>) -> Vec<String> {
    let before: BTreeSet<String> = parse_layout(&base.files, owner).1.into_iter().collect();
    parse_layout(after, owner).1.into_iter().filter(|e| !before.contains(e)).collect()
}

fn reachable(s: &Source) -> bool {
    s.enabled
}

#[utoipa::path(get, path = "/v1/content/sources/{name}/files", tag = "content", security(("bearer" = [])), params(("name" = String, Path), TreeQuery),
    responses((status = 200, body = TreeOut), (status = 404), (status = 502)))]
pub async fn tree(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>, Query(q): Query<TreeQuery>) -> ApiResult<Json<TreeOut>> {
    let s = load(&st, &name).await?;
    authorize(&user, "content:read", s.tenant_id)?;
    let snap = read_snapshot(&st, &s, q.refresh).await.map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
    Ok(Json(TreeOut {
        revision: snap.revision,
        writable: s.writable,
        tenant: tenant_name(&st, &s).await?,
        files: snap.files.iter().map(|(path, c)| FileEntry { path: path.clone(), size: c.len() }).collect(),
    }))
}

#[utoipa::path(get, path = "/v1/content/sources/{name}/file", tag = "content", security(("bearer" = [])), params(("name" = String, Path), FileQuery),
    responses((status = 200, body = FileOut), (status = 404)))]
pub async fn file(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>, Query(q): Query<FileQuery>) -> ApiResult<Json<FileOut>> {
    let s = load(&st, &name).await?;
    authorize(&user, "content:read", s.tenant_id)?;
    let snap = read_snapshot(&st, &s, false).await.map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
    let bytes = snap.files.get(&q.path).ok_or_else(|| err(StatusCode::NOT_FOUND, "file not found"))?;
    let (encoding, content) = match std::str::from_utf8(bytes) {
        Ok(text) => ("utf8", text.to_owned()),
        Err(_) => ("base64", B64.encode(bytes)),
    };
    Ok(Json(FileOut { path: q.path, revision: snap.revision, encoding: encoding.into(), content }))
}

#[utoipa::path(post, path = "/v1/content/sources/{name}/validate", tag = "content", security(("bearer" = [])), request_body = ChangeSet, params(("name" = String, Path)),
    description = "Checks what the repository would look like after the change, with the parser the sync uses. Writes nothing.",
    responses((status = 200, body = ValidateOut), (status = 404), (status = 422)))]
pub async fn validate(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>, Json(body): Json<ChangeSet>) -> ApiResult<Json<ValidateOut>> {
    let s = load(&st, &name).await?;
    authorize(&user, "content:edit", s.tenant_id)?;
    let base = read_snapshot(&st, &s, false).await.map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
    let after = apply(&base, &body.changes).map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let owner = tenant_name(&st, &s).await?;
    let errors = new_problems(&base, &after, owner.as_deref());
    Ok(Json(ValidateOut { ok: errors.is_empty(), errors }))
}

fn write_files(root: &FsPath, base: &std::collections::BTreeMap<String, Vec<u8>>, after: &std::collections::BTreeMap<String, Vec<u8>>, prefix: &str) -> Result<usize, String> {
    let mut n = 0;
    for (path, bytes) in after {
        if base.get(path) == Some(bytes) {
            continue;
        }
        let target = root.join(prefix).join(path);
        std::fs::create_dir_all(target.parent().ok_or("bad path")?).map_err(|e| e.to_string())?;
        std::fs::write(&target, bytes).map_err(|e| format!("writing {path}: {e}"))?;
        n += 1;
    }
    for path in base.keys().filter(|p| !after.contains_key(*p)) {
        let target = root.join(prefix).join(path);
        std::fs::remove_file(&target).map_err(|e| format!("removing {path}: {e}"))?;
        n += 1;
    }
    Ok(n)
}

/// `delbert/<user>-<yyyymmddThhmmss>`: unique enough, safe as a ref.
fn branch_name(user: &str) -> String {
    let who: String = user.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    format!("delbert/{who}-{now}")
}

#[utoipa::path(post, path = "/v1/content/sources/{name}/commits", tag = "content", security(("bearer" = [])), request_body = CommitBody, params(("name" = String, Path)),
    description = "Git: pushes the change as a new branch for review; the tracked branch is never written. Directory: writes the files in place. The source must be `writable`. The result is validated first.",
    responses((status = 201, body = CommitOut), (status = 404), (status = 409, description = "Read-only source, or nothing changed"), (status = 422), (status = 502)))]
pub async fn commit(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>, Json(body): Json<CommitBody>) -> ApiResult<(StatusCode, Json<CommitOut>)> {
    let s = load(&st, &name).await?;
    authorize(&user, "content:edit", s.tenant_id)?;
    if !s.writable || !reachable(&s) {
        return Err(err(StatusCode::CONFLICT, "this source is read-only (or disabled): an administrator has to make it writable"));
    }
    let message = body.message.trim();
    if message.is_empty() || message.chars().count() > MAX_MESSAGE {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, format!("the commit message is 1 to {MAX_MESSAGE} characters")));
    }
    // The base is the remote as it is now, not as it was at the last sync.
    let base = read_snapshot(&st, &s, true).await.map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
    let after = apply(&base, &body.changes).map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let owner = tenant_name(&st, &s).await?;
    let problems = new_problems(&base, &after, owner.as_deref());
    if !problems.is_empty() {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, format!("the change would break the repository:\n{}", problems.join("\n"))));
    }

    let (branch, commit_id, files) = if s.kind == "directory" {
        let root = st.content.dir.join(&s.location);
        let (base_files, after_files) = (base.files.clone(), after);
        let n = tokio::task::spawn_blocking(move || write_files(&root, &base_files, &after_files, "")).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?.map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
        (None, None, n)
    } else {
        let (b, c, n) = push_branch(&st, &s, &user.username, message, &base, &after).await.map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
        (Some(b), Some(c), n)
    };
    if files == 0 {
        return Err(err(StatusCode::CONFLICT, "nothing changed"));
    }
    let mut tx = st.pool.begin().await?;
    audit::append(&mut tx, &NewEvent { tenant_id: s.tenant_id, actor: &user.username, action: "content.commit", target: Some(&s.name), outcome: "ok", details: json!({ "branch": branch, "commit": commit_id, "files": files, "message": message, "base": base.revision }) }).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(CommitOut { branch, commit: commit_id, files, base_revision: base.revision })))
}

/// Clone the tracked branch, apply the change, commit as the user and push a new branch.
async fn push_branch(st: &AppState, s: &Source, username: &str, message: &str, base: &Snapshot, after: &std::collections::BTreeMap<String, Vec<u8>>) -> Result<(String, String, usize), String> {
    let work_root = st.content.dir.join(".git-work");
    std::fs::create_dir_all(&work_root).map_err(|e| e.to_string())?;
    let work = tempfile_dir(&work_root)?;
    let result = push_in(st, s, username, message, base, after, &work).await;
    let _ = std::fs::remove_dir_all(&work);
    result
}

fn tempfile_dir(parent: &FsPath) -> Result<std::path::PathBuf, String> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let dir = parent.join(format!("w{nanos}-{}", std::process::id()));
    std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

async fn push_in(st: &AppState, s: &Source, username: &str, message: &str, base: &Snapshot, after: &std::collections::BTreeMap<String, Vec<u8>>, work: &FsPath) -> Result<(String, String, usize), String> {
    let token = match (&s.auth_user, &s.auth_token, &st.secrets_key) {
        (user, Some(sealed), Some(key)) => Some((user.clone().unwrap_or_else(|| "x-access-token".into()), String::from_utf8_lossy(&crate::secrets::open(key, sealed).map_err(|e| e.1)?).into_owned())),
        _ => None,
    };
    let auth = token.as_ref().map(|(u, t)| (u.as_str(), t.as_str()));
    let checkout = work.join("repo");
    let parent = work.to_path_buf();
    let target = checkout.to_str().ok_or("bad path")?.to_owned();
    super::git(st, &["clone", "--quiet", "--no-tags", "--depth=1", "--branch", &s.branch, "--", &s.location, &target], &parent, auth).await?;
    let n = write_files(&checkout, &base.files, after, &s.subdir)?;
    if n == 0 {
        return Ok((String::new(), String::new(), 0));
    }
    let who = format!("user.name={username}");
    let mail = format!("user.email={}@delbert.invalid", username.replace(|c: char| !c.is_ascii_alphanumeric(), "-"));
    super::git(st, &["add", "-A"], &checkout, None).await?;
    super::git(st, &["-c", &who, "-c", &mail, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", message], &checkout, None).await?;
    let commit = String::from_utf8_lossy(&super::git(st, &["rev-parse", "HEAD"], &checkout, None).await?).trim().to_owned();
    let branch = branch_name(username);
    let refspec = format!("HEAD:refs/heads/{branch}");
    super::git(st, &["push", "--quiet", "--", "origin", &refspec], &checkout, auth).await?;
    Ok((branch, commit, n))
}
