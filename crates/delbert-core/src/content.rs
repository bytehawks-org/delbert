//! Content sources (docs/CONTENT.md): policies, artifacts and tenant settings read from a local
//! directory or a git remote, validated as a whole, diffed against what was applied last, and
//! applied through the same code paths as the API (so approval, signing and audit all apply).
//!
//! * Layout: `tenants/<tenant>/{tenant.yaml, policies/<name>.yaml, artifacts/<name>}`.
//! * One invalid item rejects the whole snapshot: nothing is applied.
//! * Items a source applied are owned by it: the API refuses to edit them (409).
//! * Git is the `git` program, run on the Core's host only: fixed arguments, no shell, hooks off,
//!   https/file protocols only, a private HOME, no prompts, a timeout, tokens through the
//!   environment (never the command line). The repository content is untrusted input.

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path as FsPath, PathBuf},
    time::Duration,
};

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use similar::TextDiff;
use sqlx::{PgPool, types::Uuid};
use utoipa::ToSchema;

use crate::{
    api::{ApiError, ApiResult, AppState, check_name},
    audit::{self, NewEvent},
    auth::{Authn, CurrentUser},
};

const MAX_FILES: usize = 10_000;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DIFF_BYTES: usize = 256 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(120);

fn err(status: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(status, msg.into())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The API must not edit what a source owns.
pub(crate) async fn ensure_unowned(pool: &PgPool, tenant: Uuid, kind: &str, name: &str) -> ApiResult<()> {
    let owner: Option<String> = sqlx::query_scalar("SELECT s.name FROM content_items i JOIN content_sources s ON s.id = i.source_id WHERE i.tenant_id = $1 AND i.kind = $2 AND i.name = $3")
        .bind(tenant)
        .bind(kind)
        .bind(name)
        .fetch_optional(pool)
        .await?;
    match owner {
        Some(s) => Err(err(StatusCode::CONFLICT, format!("this {kind} is managed by content source '{s}': change it in the repository"))),
        None => Ok(()),
    }
}

// --- sources -------------------------------------------------------------------------------

#[derive(sqlx::FromRow, Clone)]
pub(crate) struct Source {
    id: Uuid,
    name: String,
    kind: String,
    tenant_id: Option<Uuid>,
    location: String,
    branch: String,
    subdir: String,
    auth_user: Option<String>,
    auth_token: Option<Vec<u8>>,
    prune: bool,
    enabled: bool,
    poll_secs: Option<i32>,
    last_sync_at: Option<i64>,
    last_revision: Option<String>,
    last_error: Option<String>,
}

const COLUMNS: &str = "id, name, kind, tenant_id, location, branch, subdir, auth_user, auth_token, prune, enabled, poll_secs, (EXTRACT(EPOCH FROM last_sync_at))::bigint AS last_sync_at, last_revision, last_error";

#[derive(Serialize, ToSchema)]
pub struct SourceOut {
    pub name: String,
    pub kind: String,
    /// Owning tenant; absent for a platform source.
    pub tenant: Option<String>,
    pub location: String,
    pub branch: String,
    pub subdir: String,
    pub auth_user: Option<String>,
    pub has_token: bool,
    pub prune: bool,
    pub enabled: bool,
    pub poll_secs: Option<i32>,
    pub last_sync_at: Option<i64>,
    pub last_revision: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct SourceBody {
    /// Ignored on update.
    #[serde(default)]
    pub name: String,
    /// `directory` (a name under the Core's content directory) or `git`. Ignored on update.
    #[serde(default)]
    pub kind: String,
    /// Make the source tenant-owned (it can only touch that tenant). Ignored on update.
    pub tenant: Option<String>,
    /// directory: folder name; git: `https://` (or `file://` when allowed) URL.
    pub location: String,
    pub branch: Option<String>,
    pub subdir: Option<String>,
    pub auth_user: Option<String>,
    /// Access token for https remotes; absent on update keeps the stored one, empty removes it.
    pub auth_token: Option<String>,
    pub prune: Option<bool>,
    pub enabled: Option<bool>,
    /// Sync every N seconds (at least 30); absent = only on demand.
    pub poll_secs: Option<i32>,
}

async fn source_out(pool: &PgPool, s: Source) -> ApiResult<SourceOut> {
    let tenant: Option<String> = match s.tenant_id {
        Some(t) => sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1").bind(t).fetch_optional(pool).await?,
        None => None,
    };
    Ok(SourceOut {
        name: s.name, kind: s.kind, tenant, location: s.location, branch: s.branch, subdir: s.subdir, auth_user: s.auth_user, has_token: s.auth_token.is_some(),
        prune: s.prune, enabled: s.enabled, poll_secs: s.poll_secs, last_sync_at: s.last_sync_at, last_revision: s.last_revision, last_error: s.last_error,
    })
}

/// Permission on a source: its tenant for a tenant-owned one, a global grant for a platform one.
/// A source the caller cannot reach at all looks missing.
fn authorize(user: &CurrentUser, permission: &str, tenant: Option<Uuid>) -> ApiResult<()> {
    if user.can(permission, tenant) {
        return Ok(());
    }
    let any = !user.global.is_empty() || tenant.is_some_and(|t| user.scoped.contains_key(&t));
    Err(if any { err(StatusCode::FORBIDDEN, format!("missing permission '{permission}'")) } else { err(StatusCode::NOT_FOUND, "source not found") })
}

async fn load(st: &AppState, name: &str) -> ApiResult<Source> {
    let s: Option<Source> = sqlx::query_as(&format!("SELECT {COLUMNS} FROM content_sources WHERE name = $1")).bind(name).fetch_optional(&st.pool).await?;
    s.ok_or_else(|| err(StatusCode::NOT_FOUND, "source not found"))
}

fn check_ref(branch: &str) -> ApiResult<()> {
    let ok = !branch.is_empty() && !branch.starts_with('-') && !branch.contains("..") && branch.chars().all(|c| c.is_ascii_alphanumeric() || "._/-".contains(c));
    if ok { Ok(()) } else { Err(err(StatusCode::UNPROCESSABLE_ENTITY, "invalid branch name")) }
}

fn check_subdir(sub: &str) -> ApiResult<()> {
    let ok = sub.is_empty() || (!sub.starts_with('/') && !sub.starts_with('-') && sub.split('/').all(|c| !c.is_empty() && c != ".." && c != ".") && sub.chars().all(|c| c.is_ascii_alphanumeric() || "._/-".contains(c)));
    if ok { Ok(()) } else { Err(err(StatusCode::UNPROCESSABLE_ENTITY, "subdir must be a relative path without '..'")) }
}

fn check_location(st: &AppState, kind: &str, tenant_owned: bool, location: &str) -> ApiResult<()> {
    match kind {
        "directory" => {
            if tenant_owned {
                return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "directory sources belong to the platform: a tenant cannot read the Core's disk"));
            }
            check_name(location, "directory")
        }
        "git" => {
            if tenant_owned && !st.content.allow_tenant_git {
                return Err(err(StatusCode::FORBIDDEN, "tenant-owned git sources are not enabled (DELBERT_CONTENT_ALLOW_TENANT_GIT)"));
            }
            let scheme_ok = location.starts_with("https://") || (!st.auth.cookie_secure && location.starts_with("http://")) || (st.content.allow_file && location.starts_with("file://"));
            let clean = !location.chars().any(|c| c.is_whitespace() || c.is_control()) && !location.starts_with('-');
            if scheme_ok && clean { Ok(()) } else { Err(err(StatusCode::UNPROCESSABLE_ENTITY, "git location must be an https:// URL (http:// only in development)")) }
        }
        _ => Err(err(StatusCode::UNPROCESSABLE_ENTITY, "kind must be 'directory' or 'git'")),
    }
}

#[utoipa::path(get, path = "/v1/content/sources", tag = "content", security(("bearer" = [])), responses((status = 200, body = Vec<SourceOut>)))]
pub async fn list_sources(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<Vec<SourceOut>>> {
    let rows: Vec<Source> = match user.tenants_with("content:read") {
        None => sqlx::query_as(&format!("SELECT {COLUMNS} FROM content_sources ORDER BY name")).fetch_all(&st.pool).await?,
        Some(ids) => sqlx::query_as(&format!("SELECT {COLUMNS} FROM content_sources WHERE tenant_id = ANY($1) ORDER BY name")).bind(ids).fetch_all(&st.pool).await?,
    };
    let mut out = Vec::new();
    for r in rows {
        out.push(source_out(&st.pool, r).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(get, path = "/v1/content/sources/{name}", tag = "content", security(("bearer" = [])), params(("name" = String, Path)), responses((status = 200, body = SourceOut), (status = 404)))]
pub async fn get_source(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>) -> ApiResult<Json<SourceOut>> {
    let s = load(&st, &name).await?;
    authorize(&user, "content:read", s.tenant_id)?;
    Ok(Json(source_out(&st.pool, s).await?))
}

fn check_poll(p: Option<i32>) -> ApiResult<()> {
    match p {
        Some(v) if v < 30 => Err(err(StatusCode::UNPROCESSABLE_ENTITY, "poll_secs must be at least 30")),
        _ => Ok(()),
    }
}

#[utoipa::path(post, path = "/v1/content/sources", tag = "content", security(("bearer" = [])), request_body = SourceBody,
    responses((status = 201, body = SourceOut), (status = 403), (status = 409), (status = 422)))]
pub async fn create_source(State(st): State<AppState>, Authn(user): Authn, Json(body): Json<SourceBody>) -> ApiResult<(StatusCode, Json<SourceOut>)> {
    crate::api::check_token(&body.name, "source")?;
    let tenant_id = match &body.tenant {
        Some(t) => Some(user.tenant(&st.pool, t, "content:write").await?),
        None => {
            user.require_global("content:write")?;
            None
        }
    };
    check_location(&st, &body.kind, tenant_id.is_some(), &body.location)?;
    let (branch, subdir) = (body.branch.clone().unwrap_or_else(|| "main".into()), body.subdir.clone().unwrap_or_default());
    check_ref(&branch)?;
    check_subdir(&subdir)?;
    check_poll(body.poll_secs)?;
    let token = match body.auth_token.as_deref().filter(|t| !t.is_empty()) {
        Some(t) => Some(crate::secrets::seal(st.secrets_key.as_ref().ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "tokens need DELBERT_SECRETS_KEY_FILE"))?, t.as_bytes())?),
        None => None,
    };
    let mut tx = st.pool.begin().await?;
    sqlx::query("INSERT INTO content_sources (name, kind, tenant_id, location, branch, subdir, auth_user, auth_token, prune, enabled, poll_secs) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)")
        .bind(&body.name).bind(&body.kind).bind(tenant_id).bind(&body.location).bind(&branch).bind(&subdir).bind(&body.auth_user).bind(token)
        .bind(body.prune.unwrap_or(false)).bind(body.enabled.unwrap_or(true)).bind(body.poll_secs)
        .execute(&mut *tx)
        .await?;
    audit::append(&mut tx, &NewEvent { tenant_id, actor: &user.username, action: "content.create", target: Some(&body.name), outcome: "ok", details: json!({ "kind": body.kind, "location": body.location, "prune": body.prune.unwrap_or(false) }) }).await?;
    tx.commit().await?;
    let s = load(&st, &body.name).await?;
    Ok((StatusCode::CREATED, Json(source_out(&st.pool, s).await?)))
}

#[utoipa::path(put, path = "/v1/content/sources/{name}", tag = "content", security(("bearer" = [])), request_body = SourceBody, params(("name" = String, Path)),
    responses((status = 204), (status = 403), (status = 404), (status = 422)))]
pub async fn update_source(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>, Json(body): Json<SourceBody>) -> ApiResult<StatusCode> {
    let s = load(&st, &name).await?;
    authorize(&user, "content:write", s.tenant_id)?;
    check_location(&st, &s.kind, s.tenant_id.is_some(), &body.location)?;
    let branch = body.branch.clone().unwrap_or_else(|| s.branch.clone());
    let subdir = body.subdir.clone().unwrap_or_else(|| s.subdir.clone());
    check_ref(&branch)?;
    check_subdir(&subdir)?;
    check_poll(body.poll_secs)?;
    let mut tx = st.pool.begin().await?;
    sqlx::query("UPDATE content_sources SET location = $2, branch = $3, subdir = $4, prune = $5, enabled = $6, poll_secs = $7, auth_user = COALESCE($8, auth_user), last_revision = NULL WHERE id = $1")
        .bind(s.id).bind(&body.location).bind(&branch).bind(&subdir).bind(body.prune.unwrap_or(s.prune)).bind(body.enabled.unwrap_or(s.enabled)).bind(body.poll_secs.or(s.poll_secs)).bind(&body.auth_user)
        .execute(&mut *tx)
        .await?;
    if let Some(t) = body.auth_token.as_deref() {
        let sealed = if t.is_empty() { None } else { Some(crate::secrets::seal(st.secrets_key.as_ref().ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "tokens need DELBERT_SECRETS_KEY_FILE"))?, t.as_bytes())?) };
        sqlx::query("UPDATE content_sources SET auth_token = $2 WHERE id = $1").bind(s.id).bind(sealed).execute(&mut *tx).await?;
    }
    audit::append(&mut tx, &NewEvent { tenant_id: s.tenant_id, actor: &user.username, action: "content.update", target: Some(&name), outcome: "ok", details: json!({ "location": body.location, "prune": body.prune, "enabled": body.enabled }) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/v1/content/sources/{name}", tag = "content", security(("bearer" = [])), params(("name" = String, Path)),
    description = "Deleting a source releases what it owned (the items stay, editable again).", responses((status = 204), (status = 404)))]
pub async fn delete_source(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>) -> ApiResult<StatusCode> {
    let s = load(&st, &name).await?;
    authorize(&user, "content:write", s.tenant_id)?;
    let mut tx = st.pool.begin().await?;
    sqlx::query("DELETE FROM content_sources WHERE id = $1").bind(s.id).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: s.tenant_id, actor: &user.username, action: "content.delete", target: Some(&name), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- reading a snapshot --------------------------------------------------------------------

/// Files of a snapshot by path relative to the layout root.
struct Snapshot {
    revision: String,
    files: BTreeMap<String, Vec<u8>>,
}

fn check_rel(path: &str) -> Result<(), String> {
    if path.is_empty() || path.starts_with('/') || path.split('/').any(|c| c.is_empty() || c == ".." || c == ".") {
        return Err(format!("unsafe path '{path}'"));
    }
    Ok(())
}

fn read_directory(root: &FsPath) -> Result<Snapshot, String> {
    let mut files = BTreeMap::new();
    let (mut total, mut count) = (0u64, 0usize);
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|e| format!("reading {}: {e}", dir.display()))? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == ".git" {
                continue;
            }
            let rel = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() {
                return Err(format!("'{rel}' is a symbolic link"));
            }
            if meta.is_dir() {
                stack.push((entry.path(), rel));
            } else if meta.is_file() {
                count += 1;
                total += meta.len();
                if count > MAX_FILES || total > MAX_TOTAL_BYTES {
                    return Err("the source is too large".into());
                }
                files.insert(rel, std::fs::read(entry.path()).map_err(|e| e.to_string())?);
            }
        }
    }
    let mut h = Sha256::new();
    for (p, c) in &files {
        h.update(p.as_bytes());
        h.update([0]);
        h.update(Sha256::digest(c));
    }
    Ok(Snapshot { revision: format!("tree:{}", &hex(&h.finalize())[..16]), files })
}

async fn git(st: &AppState, args: &[&str], cwd: &FsPath, token: Option<(&str, &str)>) -> Result<Vec<u8>, String> {
    let home = st.content.dir.join(".git-home");
    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    let protocols = match (st.content.allow_file, st.auth.cookie_secure) {
        (true, _) => "https:http:file",
        (false, false) => "https:http",
        (false, true) => "https",
    };
    let mut cmd = tokio::process::Command::new("git");
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into()))
        .env("HOME", &home)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ALLOW_PROTOCOL", protocols)
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "/dev/null")
        .kill_on_drop(true);
    match token {
        Some((user, tok)) => {
            // Through the environment, so the token never appears in a process listing.
            cmd.env("GIT_CONFIG_COUNT", "2").env("GIT_CONFIG_KEY_1", "http.extraHeader").env("GIT_CONFIG_VALUE_1", format!("Authorization: Basic {}", B64.encode(format!("{user}:{tok}"))));
        }
        None => {
            cmd.env("GIT_CONFIG_COUNT", "1");
        }
    }
    let out = tokio::time::timeout(GIT_TIMEOUT, cmd.output()).await.map_err(|_| "git timed out".to_string())?.map_err(|e| format!("cannot run git: {e}"))?;
    if !out.status.success() {
        // The URL may carry a user name; the token never does. Keep the message short.
        let msg: String = String::from_utf8_lossy(&out.stderr).lines().take(3).collect::<Vec<_>>().join(" | ");
        return Err(format!("git {} failed: {msg}", args.first().unwrap_or(&"")));
    }
    Ok(out.stdout)
}

async fn read_git(st: &AppState, s: &Source) -> Result<Snapshot, String> {
    let mirrors = st.content.dir.join(".git-mirrors");
    std::fs::create_dir_all(&mirrors).map_err(|e| e.to_string())?;
    let mirror = mirrors.join(format!("{}.git", s.id));
    if !mirror.exists() {
        git(st, &["init", "--bare", "--quiet", mirror.to_str().ok_or("bad path")?], &mirrors, None).await?;
    }
    let token = match (&s.auth_user, &s.auth_token, &st.secrets_key) {
        (user, Some(sealed), Some(key)) => Some((user.clone().unwrap_or_else(|| "x-access-token".into()), String::from_utf8_lossy(&crate::secrets::open(key, sealed).map_err(|e| e.1)?).into_owned())),
        _ => None,
    };
    let refspec = format!("+refs/heads/{}:refs/delbert/tracked", s.branch);
    git(st, &["fetch", "--quiet", "--no-tags", "--prune", "--depth=1", "--", &s.location, &refspec], &mirror, token.as_ref().map(|(u, t)| (u.as_str(), t.as_str()))).await?;
    let rev = String::from_utf8_lossy(&git(st, &["rev-parse", "--verify", "refs/delbert/tracked^{commit}"], &mirror, None).await?).trim().to_owned();
    let tree = if s.subdir.is_empty() { rev.clone() } else { format!("{rev}:{}", s.subdir) };
    let tar_bytes = git(st, &["archive", "--format=tar", &tree], &mirror, None).await?;

    let mut files = BTreeMap::new();
    let (mut total, mut count) = (0u64, 0usize);
    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.header().entry_type();
        let path = entry.path().map_err(|e| e.to_string())?.to_string_lossy().trim_end_matches('/').to_owned();
        if kind.is_dir() || kind.is_pax_global_extensions() || kind.is_pax_local_extensions() || path.is_empty() {
            continue;
        }
        if !kind.is_file() {
            return Err(format!("'{path}' is a link or special file"));
        }
        check_rel(&path)?;
        count += 1;
        total += entry.size();
        if count > MAX_FILES || total > MAX_TOTAL_BYTES {
            return Err("the source is too large".into());
        }
        let mut content = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut content).map_err(|e| e.to_string())?;
        files.insert(path, content);
    }
    Ok(Snapshot { revision: rev, files })
}

async fn read_snapshot(st: &AppState, s: &Source) -> Result<Snapshot, String> {
    match s.kind.as_str() {
        "git" => read_git(st, s).await,
        _ => {
            let root: PathBuf = st.content.dir.join(&s.location);
            tokio::task::spawn_blocking(move || read_directory(&root)).await.map_err(|e| e.to_string())?
        }
    }
}

// --- parsing the layout --------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantFile {
    approval_required: Option<bool>,
}

#[derive(Default)]
struct TenantContent {
    approval_required: Option<bool>,
    policies: BTreeMap<String, String>,
    artifacts: BTreeMap<String, Vec<u8>>,
}

/// Interpret the files; every problem is collected so the operator sees them all at once.
fn parse_layout(files: &BTreeMap<String, Vec<u8>>, only_tenant: Option<&str>) -> (BTreeMap<String, TenantContent>, Vec<String>) {
    let mut tenants: BTreeMap<String, TenantContent> = BTreeMap::new();
    let mut errors = Vec::new();
    for (path, content) in files {
        let parts: Vec<&str> = path.split('/').collect();
        if parts[0] != "tenants" {
            continue; // README, LICENSE, CI files... only what is under tenants/ is interpreted
        }
        let (Some(tenant), Some(rest)) = (parts.get(1), parts.get(2..)) else {
            errors.push(format!("{path}: expected tenants/<tenant>/..."));
            continue;
        };
        if let Err(e) = crate::api::check_token(tenant, "tenant") {
            errors.push(format!("{path}: {}", e.1));
            continue;
        }
        if only_tenant.is_some_and(|t| t != *tenant) {
            errors.push(format!("{path}: this source may only contain tenant '{}'", only_tenant.unwrap_or_default()));
            continue;
        }
        let t = tenants.entry((*tenant).to_owned()).or_default();
        match rest {
            ["tenant.yaml"] => match std::str::from_utf8(content).ok().and_then(|s| serde_yaml_ng::from_str::<TenantFile>(s).ok()) {
                Some(f) => t.approval_required = f.approval_required,
                None => errors.push(format!("{path}: invalid tenant settings (known: approval_required)")),
            },
            ["policies", file] => {
                let Some(stem) = file.strip_suffix(".yaml").or_else(|| file.strip_suffix(".yml")) else {
                    errors.push(format!("{path}: policies must be .yaml files"));
                    continue;
                };
                match std::str::from_utf8(content) {
                    Ok(yaml) => match crate::api::validate_policy(yaml, tenant) {
                        Ok(name) if name == stem => {
                            t.policies.insert(name, yaml.to_owned());
                        }
                        Ok(name) => errors.push(format!("{path}: metadata.name is '{name}', the file must be called {name}.yaml")),
                        Err(e) => errors.push(format!("{path}: {}", e.1)),
                    },
                    Err(_) => errors.push(format!("{path}: not UTF-8")),
                }
            }
            ["artifacts", name] => match check_name(name, "artifact") {
                Ok(()) if content.len() <= crate::artifacts::MAX_ARTIFACT_BYTES => {
                    t.artifacts.insert((*name).to_owned(), content.clone());
                }
                Ok(()) => errors.push(format!("{path}: artifact too large")),
                Err(e) => errors.push(format!("{path}: {}", e.1)),
            },
            _ => errors.push(format!("{path}: not part of the layout (tenant.yaml, policies/<name>.yaml, artifacts/<name>)")),
        }
    }
    (tenants, errors)
}

// --- sync ----------------------------------------------------------------------------------

#[derive(Serialize, ToSchema, Clone)]
pub struct ChangeOut {
    pub tenant: String,
    pub kind: String,
    pub name: String,
    /// `added`, `changed` or `removed`.
    pub change: String,
    /// Resulting version (policies and artifacts).
    pub version: Option<i64>,
    /// False for a removal that was reported but not applied (`prune` is off).
    pub applied: bool,
    /// Unified diff of text content.
    pub diff: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SyncOut {
    pub revision: String,
    /// `unchanged`, `applied`, `rejected` or `failed`.
    pub status: String,
    pub snapshot: Option<i64>,
    pub errors: Vec<String>,
    pub changes: Vec<ChangeOut>,
}

fn unified(old: &str, new: &str, name: &str) -> Option<String> {
    if old.len() > MAX_DIFF_BYTES || new.len() > MAX_DIFF_BYTES {
        return None;
    }
    Some(TextDiff::from_lines(old, new).unified_diff().context_radius(3).header(&format!("a/{name}"), &format!("b/{name}")).to_string())
}

fn text_diff(old: Option<&[u8]>, new: Option<&[u8]>, name: &str) -> Option<String> {
    let (o, n) = (old.map(std::str::from_utf8).transpose().ok()?, new.map(std::str::from_utf8).transpose().ok()?);
    unified(o.unwrap_or(""), n.unwrap_or(""), name)
}

async fn latest_artifact_bytes(st: &AppState, tid: Uuid, name: &str) -> Option<Vec<u8>> {
    let sha: Vec<u8> = sqlx::query_scalar("SELECT sha256 FROM artifacts WHERE tenant_id = $1 AND name = $2 ORDER BY version DESC LIMIT 1").bind(tid).bind(name).fetch_optional(&st.pool).await.ok()??;
    let stream = st.blobs.get(tid, &hex(&sha)).await.ok()??;
    let chunks: Vec<Bytes> = futures::TryStreamExt::try_collect(stream).await.ok()?;
    Some(chunks.concat())
}

/// Read, validate, diff and apply one source. `actor` goes to the audit trail.
pub(crate) async fn sync_source(st: &AppState, s: &Source, actor: &str) -> ApiResult<SyncOut> {
    // One sync per source at a time, across Core replicas.
    let mut lock = st.pool.acquire().await?;
    let key = i64::from_le_bytes(s.id.as_bytes()[..8].try_into().expect("8 bytes"));
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)").bind(key).fetch_one(&mut *lock).await?;
    if !got {
        return Err(err(StatusCode::CONFLICT, "a sync of this source is already running"));
    }
    let result = sync_locked(st, s, actor).await;
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)").bind(key).execute(&mut *lock).await;
    result
}

async fn finish(st: &AppState, s: &Source, revision: Option<&str>, error: Option<&str>) -> ApiResult<()> {
    sqlx::query("UPDATE content_sources SET last_sync_at = now(), last_revision = COALESCE($2, last_revision), last_error = $3 WHERE id = $1").bind(s.id).bind(revision).bind(error).execute(&st.pool).await?;
    Ok(())
}

async fn sync_locked(st: &AppState, s: &Source, actor: &str) -> ApiResult<SyncOut> {
    let snap = match read_snapshot(st, s).await {
        Ok(snap) => snap,
        Err(e) => {
            tracing::warn!("content source '{}': {e}", s.name);
            finish(st, s, None, Some(&e)).await?;
            return Err(err(StatusCode::BAD_GATEWAY, e));
        }
    };
    let short = &snap.revision[..snap.revision.len().min(12)];
    let actor_name = format!("source:{}@{short}", s.name);
    let _ = actor;
    let unchanged = SyncOut { revision: snap.revision.clone(), status: "unchanged".into(), snapshot: None, errors: vec![], changes: vec![] };
    if s.last_revision.as_deref() == Some(snap.revision.as_str()) {
        finish(st, s, Some(&snap.revision), None).await?;
        return Ok(unchanged);
    }
    let owner_tenant: Option<String> = match s.tenant_id {
        Some(t) => sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1").bind(t).fetch_optional(&st.pool).await?,
        None => None,
    };

    // Validate everything first; apply nothing if anything is wrong.
    let (parsed, mut problems) = parse_layout(&snap.files, owner_tenant.as_deref());
    let mut tenant_ids: HashMap<String, Uuid> = HashMap::new();
    for t in parsed.keys() {
        match sqlx::query_scalar::<_, Uuid>("SELECT id FROM tenants WHERE name = $1 AND archived_at IS NULL").bind(t).fetch_optional(&st.pool).await? {
            Some(id) => {
                tenant_ids.insert(t.clone(), id);
            }
            None => problems.push(format!("tenants/{t}: the tenant does not exist")),
        }
    }
    // Items owned by another source cannot be taken over silently.
    let others: Vec<(Uuid, String, String, String)> = sqlx::query_as("SELECT i.tenant_id, i.kind, i.name, c.name FROM content_items i JOIN content_sources c ON c.id = i.source_id WHERE i.source_id <> $1").bind(s.id).fetch_all(&st.pool).await?;
    for (tid, kind, name, owner) in &others {
        if let Some((t, c)) = tenant_ids.iter().find(|(_, id)| *id == tid).and_then(|(t, _)| parsed.get(t).map(|c| (t, c))) {
            let present = match kind.as_str() {
                "policy" => c.policies.contains_key(name),
                "artifact" => c.artifacts.contains_key(name),
                _ => false,
            };
            if present {
                problems.push(format!("tenants/{t}: {kind} '{name}' is already managed by source '{owner}'"));
            }
        }
    }
    if !problems.is_empty() {
        let msg = problems.join("\n");
        // Not marked as done, so a cause outside the repository (a missing tenant) is retried; the
        // same rejection is recorded once, not at every poll.
        let repeated: bool = sqlx::query_scalar("SELECT COALESCE((SELECT revision = $2 AND status = 'rejected' AND error = $3 FROM content_snapshots WHERE source_id = $1 ORDER BY id DESC LIMIT 1), false)")
            .bind(s.id).bind(&snap.revision).bind(&msg).fetch_one(&st.pool).await?;
        let id = if repeated {
            None
        } else {
            let id = record_snapshot(st, s, &snap.revision, "rejected", Some(&msg), &actor_name, &[]).await?;
            let mut tx = st.pool.begin().await?;
            audit::append(&mut tx, &NewEvent { tenant_id: s.tenant_id, actor: &actor_name, action: "content.sync", target: Some(&s.name), outcome: "rejected", details: json!({ "revision": snap.revision, "problems": problems.len() }) }).await?;
            tx.commit().await?;
            Some(id)
        };
        finish(st, s, None, Some(&format!("snapshot rejected: {}", problems.first().map(String::as_str).unwrap_or("")))).await?;
        return Ok(SyncOut { revision: snap.revision, status: "rejected".into(), snapshot: id, errors: problems, changes: vec![] });
    }

    // Diff against what this source applied last.
    let owned: Vec<(Uuid, String, String, Vec<u8>)> = sqlx::query_as("SELECT tenant_id, kind, name, last_hash FROM content_items WHERE source_id = $1").bind(s.id).fetch_all(&st.pool).await?;
    let previous: HashMap<(Uuid, String, String), Vec<u8>> = owned.into_iter().map(|(t, k, n, h)| ((t, k, n), h)).collect();
    let tenant_name: HashMap<Uuid, String> = tenant_ids.iter().map(|(n, i)| (*i, n.clone())).collect();
    let mut changes: Vec<ChangeOut> = Vec::new();
    let mut hashes: Vec<(Uuid, &str, String, Vec<u8>)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for (tenant, c) in &parsed {
        let tid = tenant_ids[tenant];
        if let Some(want) = c.approval_required {
            let current: bool = sqlx::query_scalar("SELECT approval_required FROM tenants WHERE id = $1").bind(tid).fetch_one(&st.pool).await?;
            let h = Sha256::digest([want as u8]).to_vec();
            if current != want {
                let mut tx = st.pool.begin().await?;
                let weakening = current && !want;
                if weakening && (s.tenant_id.is_some() || crate::approval::count_submitted(&mut tx, tid).await? > 0) {
                    errors.push(format!("tenants/{tenant}/tenant.yaml: approval_required cannot be switched off from here (tenant-owned source or versions waiting for approval)"));
                } else {
                    sqlx::query("UPDATE tenants SET approval_required = $2 WHERE id = $1").bind(tid).bind(want).execute(&mut *tx).await?;
                    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &actor_name, action: "tenant.settings", target: Some(tenant), outcome: "ok", details: json!({ "approval_required": want }) }).await?;
                    changes.push(ChangeOut { tenant: tenant.clone(), kind: "tenant".into(), name: "tenant.yaml".into(), change: "changed".into(), version: None, applied: true, diff: Some(format!("-approval_required: {current}\n+approval_required: {want}\n")) });
                    hashes.push((tid, "tenant", "tenant.yaml".into(), h));
                }
                tx.commit().await?;
            } else {
                hashes.push((tid, "tenant", "tenant.yaml".into(), h));
            }
        }
        // Artifacts first: policies may refer to them.
        for (name, bytes) in &c.artifacts {
            let h = Sha256::digest(bytes).to_vec();
            let before = previous.get(&(tid, "artifact".into(), name.clone()));
            if before == Some(&h) {
                hashes.push((tid, "artifact", name.clone(), h));
                continue;
            }
            let old = latest_artifact_bytes(st, tid, name).await;
            let diff = match (std::str::from_utf8(bytes).is_ok(), old.as_deref().map(std::str::from_utf8)) {
                (true, None | Some(Ok(_))) => text_diff(old.as_deref(), Some(bytes), name),
                _ => Some(format!("binary content: {} -> sha256:{}\n", old.as_deref().map_or("none".into(), |o| format!("sha256:{}", hex(&Sha256::digest(o)))), hex(&h))),
            };
            match crate::artifacts::store_artifact(st, tid, tenant, name, Bytes::from(bytes.clone()), &actor_name).await {
                Ok((_, out)) => {
                    changes.push(ChangeOut { tenant: tenant.clone(), kind: "artifact".into(), name: name.clone(), change: if before.is_some() || old.is_some() { "changed" } else { "added" }.into(), version: Some(out.version), applied: true, diff });
                    hashes.push((tid, "artifact", name.clone(), h));
                }
                Err(e) => errors.push(format!("artifact {tenant}/{name}: {}", e.1)),
            }
        }
        for (name, yaml) in &c.policies {
            let h = Sha256::digest(yaml.as_bytes()).to_vec();
            let before = previous.get(&(tid, "policy".into(), name.clone()));
            if before == Some(&h) {
                hashes.push((tid, "policy", name.clone(), h));
                continue;
            }
            let old: Option<String> = sqlx::query_scalar("SELECT v.yaml FROM policies p JOIN policy_versions v ON v.policy_id = p.id WHERE p.tenant_id = $1 AND p.name = $2 ORDER BY v.version DESC LIMIT 1").bind(tid).bind(name).fetch_optional(&st.pool).await?;
            match crate::api::store_policy_version(st, tid, tenant, yaml, &actor_name).await {
                Ok(out) => {
                    changes.push(ChangeOut { tenant: tenant.clone(), kind: "policy".into(), name: name.clone(), change: if old.is_some() { "changed" } else { "added" }.into(), version: Some(out.version), applied: true, diff: unified(old.as_deref().unwrap_or(""), yaml, &format!("{name}.yaml")) });
                    hashes.push((tid, "policy", name.clone(), h));
                }
                Err(e) => errors.push(format!("policy {tenant}/{name}: {}", e.1)),
            }
        }
    }

    // Removals: reported always, applied only with `prune`.
    let present: std::collections::HashSet<(Uuid, String, String)> = hashes.iter().map(|(t, k, n, _)| (*t, (*k).to_owned(), n.clone())).collect();
    for ((tid, kind, name), _) in previous.iter().filter(|(k, _)| !present.contains(*k)) {
        let tenant = tenant_name.get(tid).cloned().unwrap_or_else(|| tid.to_string());
        let mut applied = false;
        if s.prune && kind == "policy" {
            let n = sqlx::query("UPDATE policies SET active = false WHERE tenant_id = $1 AND name = $2 AND active").bind(tid).bind(name).execute(&st.pool).await?.rows_affected();
            applied = n > 0;
            if applied {
                crate::api::notify_tenant(st, &tenant, *tid).await;
            }
        }
        // Artifact versions are immutable: pruning releases ownership, nothing is deleted.
        if s.prune {
            sqlx::query("DELETE FROM content_items WHERE source_id = $1 AND tenant_id = $2 AND kind = $3 AND name = $4").bind(s.id).bind(tid).bind(kind).bind(name).execute(&st.pool).await?;
            applied = true;
        }
        let old: Option<String> = if kind == "policy" { sqlx::query_scalar("SELECT v.yaml FROM policies p JOIN policy_versions v ON v.policy_id = p.id WHERE p.tenant_id = $1 AND p.name = $2 ORDER BY v.version DESC LIMIT 1").bind(tid).bind(name).fetch_optional(&st.pool).await? } else { None };
        changes.push(ChangeOut { tenant, kind: kind.clone(), name: name.clone(), change: "removed".into(), version: None, applied, diff: old.map(|o| unified(&o, "", &format!("{name}.yaml")).unwrap_or_default()) });
        if !s.prune {
            // Still owned until the operator allows pruning or deletes the source.
            continue;
        }
    }

    for (tid, kind, name, h) in &hashes {
        sqlx::query("INSERT INTO content_items (source_id, tenant_id, kind, name, last_hash) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, kind, name) DO UPDATE SET source_id = $1, last_hash = $5").bind(s.id).bind(tid).bind(kind).bind(name).bind(h).execute(&st.pool).await?;
    }

    let status = if errors.is_empty() { "applied" } else { "failed" };
    let snapshot = if changes.is_empty() && errors.is_empty() {
        None
    } else {
        Some(record_snapshot(st, s, &snap.revision, status, (!errors.is_empty()).then(|| errors.join("\n")).as_deref(), &actor_name, &changes).await?)
    };
    // A failed apply is retried at the next sync: the revision is not marked as done.
    finish(st, s, errors.is_empty().then_some(snap.revision.as_str()), (!errors.is_empty()).then(|| errors.join("; ")).as_deref()).await?;
    let mut tx = st.pool.begin().await?;
    audit::append(&mut tx, &NewEvent { tenant_id: s.tenant_id, actor: &actor_name, action: "content.sync", target: Some(&s.name), outcome: if errors.is_empty() { "ok" } else { "failed" }, details: json!({ "revision": snap.revision, "changes": changes.len(), "errors": errors.len() }) }).await?;
    tx.commit().await?;
    Ok(SyncOut { revision: snap.revision, status: if changes.is_empty() && errors.is_empty() { "unchanged" } else { status }.into(), snapshot, errors, changes })
}

async fn record_snapshot(st: &AppState, s: &Source, revision: &str, status: &str, error: Option<&str>, actor: &str, changes: &[ChangeOut]) -> ApiResult<i64> {
    let mut tx = st.pool.begin().await?;
    let id: i64 = sqlx::query_scalar("INSERT INTO content_snapshots (source_id, revision, status, error, actor) VALUES ($1, $2, $3, $4, $5) RETURNING id").bind(s.id).bind(revision).bind(status).bind(error).bind(actor).fetch_one(&mut *tx).await?;
    for c in changes {
        sqlx::query("INSERT INTO content_changes (snapshot_id, tenant, kind, name, change, version, applied, diff) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
            .bind(id).bind(&c.tenant).bind(&c.kind).bind(&c.name).bind(&c.change).bind(c.version).bind(c.applied).bind(&c.diff)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(id)
}

#[utoipa::path(post, path = "/v1/content/sources/{name}/sync", tag = "content", security(("bearer" = [])), params(("name" = String, Path)),
    responses((status = 200, body = SyncOut), (status = 404), (status = 409, description = "A sync is already running"), (status = 502, description = "Cannot read the source")))]
pub async fn sync_now(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>) -> ApiResult<Json<SyncOut>> {
    let s = load(&st, &name).await?;
    authorize(&user, "content:sync", s.tenant_id)?;
    if !s.enabled {
        return Err(err(StatusCode::CONFLICT, "the source is disabled"));
    }
    Ok(Json(sync_source(&st, &s, &user.username).await?))
}

/// Background loop: sync the sources whose interval elapsed.
pub async fn poller(st: AppState) {
    loop {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let due: Result<Vec<Source>, _> = sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM content_sources WHERE enabled AND poll_secs IS NOT NULL AND (last_sync_at IS NULL OR last_sync_at + make_interval(secs => poll_secs) < now())"
        ))
        .fetch_all(&st.pool)
        .await;
        for s in due.unwrap_or_default() {
            if let Err(e) = sync_source(&st, &s, "poller").await {
                tracing::warn!("content source '{}': {}", s.name, e.1);
            }
        }
    }
}

// --- history -------------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct SnapshotOut {
    pub id: i64,
    pub revision: String,
    pub status: String,
    pub error: Option<String>,
    pub actor: String,
    pub created_at: i64,
}

#[derive(Serialize, ToSchema)]
pub struct SnapshotDetail {
    #[serde(flatten)]
    pub snapshot: SnapshotOut,
    pub changes: Vec<ChangeOut>,
}

#[utoipa::path(get, path = "/v1/content/sources/{name}/snapshots", tag = "content", security(("bearer" = [])), params(("name" = String, Path)),
    responses((status = 200, body = Vec<SnapshotOut>), (status = 404)))]
pub async fn list_snapshots(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>) -> ApiResult<Json<Vec<SnapshotOut>>> {
    let s = load(&st, &name).await?;
    authorize(&user, "content:read", s.tenant_id)?;
    let rows: Vec<(i64, String, String, Option<String>, String, i64)> = sqlx::query_as("SELECT id, revision, status, error, actor, (EXTRACT(EPOCH FROM created_at))::bigint FROM content_snapshots WHERE source_id = $1 ORDER BY id DESC LIMIT 200").bind(s.id).fetch_all(&st.pool).await?;
    Ok(Json(rows.into_iter().map(|(id, revision, status, error, actor, created_at)| SnapshotOut { id, revision, status, error, actor, created_at }).collect()))
}

#[utoipa::path(get, path = "/v1/content/sources/{name}/snapshots/{id}", tag = "content", security(("bearer" = [])), params(("name" = String, Path), ("id" = i64, Path)),
    responses((status = 200, body = SnapshotDetail), (status = 404)))]
pub async fn get_snapshot(State(st): State<AppState>, Authn(user): Authn, Path((name, id)): Path<(String, i64)>) -> ApiResult<Json<SnapshotDetail>> {
    let s = load(&st, &name).await?;
    authorize(&user, "content:read", s.tenant_id)?;
    let row: Option<(i64, String, String, Option<String>, String, i64)> = sqlx::query_as("SELECT id, revision, status, error, actor, (EXTRACT(EPOCH FROM created_at))::bigint FROM content_snapshots WHERE source_id = $1 AND id = $2").bind(s.id).bind(id).fetch_optional(&st.pool).await?;
    let (id, revision, status, error, actor, created_at) = row.ok_or_else(|| err(StatusCode::NOT_FOUND, "snapshot not found"))?;
    let rows: Vec<(String, String, String, String, Option<i64>, bool, Option<String>)> = sqlx::query_as("SELECT tenant, kind, name, change, version, applied, diff FROM content_changes WHERE snapshot_id = $1 ORDER BY id").bind(id).fetch_all(&st.pool).await?;
    Ok(Json(SnapshotDetail {
        snapshot: SnapshotOut { id, revision, status, error, actor, created_at },
        changes: rows.into_iter().map(|(tenant, kind, name, change, version, applied, diff)| ChangeOut { tenant, kind, name, change, version, applied, diff }).collect(),
    }))
}
