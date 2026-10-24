//! Template variables in layers (migration `0020`, docs/POLICY.md "Variables").
//!
//! Four layers, from the most general to the most specific: **global**, **tenant**, **group**,
//! **agent** (host). A more specific layer overrides a more general one, unless the general one is
//! a **constant** (`locked`): then nothing below it can change the value. Policy `spec.vars` are
//! the defaults of the policy author and sit under all of these; a template resource's own `vars`
//! override everything except constants.
//!
//! The Core resolves the layers for each agent and puts the result in the signed effective policy
//! (`vars`), so what an agent renders depends only on verified data. Nothing here is a secret
//! store: secrets stay in `/secrets`, which is sealed per agent. Values are shown in clear and the
//! audit trail records only their hash.
//!
//! Resolution is deterministic: groups apply in alphabetical order (the last one wins and the
//! disagreement is reported as a conflict). [`resolved`] shows, per variable, where its value
//! comes from and what it hides; [`render`] renders the agent's templates with masked secrets.

use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::{
    api::{ApiError, ApiResult, AppState, check_name},
    audit::{self, NewEvent},
    auth::Authn,
    compile::{Compiled, Conflict},
};

const MAX_VALUE_BYTES: usize = 16 * 1024;
const MAX_TEMPLATE_BYTES: usize = 1024 * 1024;

#[derive(Serialize, ToSchema)]
pub struct VariableOut {
    /// `global`, `tenant`, `group` or `agent`.
    pub scope: String,
    /// The group or agent name; empty for `global` and `tenant`.
    pub target: String,
    pub name: String,
    pub value: Value,
    /// A constant: lower layers cannot override it.
    pub locked: bool,
    pub updated_by: String,
    /// Unix seconds.
    pub updated_at: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct NewVariable {
    pub value: Value,
    #[serde(default)]
    pub locked: bool,
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct Where {
    /// `tenant` (default), `group` or `agent`.
    scope: Option<String>,
    /// The group or agent name; required for those scopes.
    target: Option<String>,
}

/// A variable name is usable as `vars.<name>` in a template.
fn check_var_name(name: &str) -> ApiResult<()> {
    let ok = !name.is_empty() && name.len() <= 64 && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok { Ok(()) } else { Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "invalid variable name (letters, digits and _, starting with a letter or _, at most 64)".into())) }
}

fn check_value(value: &Value) -> ApiResult<()> {
    if value.is_null() {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "a variable needs a value (null is not allowed)".into()));
    }
    if value.to_string().len() > MAX_VALUE_BYTES {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "value too large (16 KiB at most)".into()));
    }
    Ok(())
}

fn digest(value: &Value) -> String {
    Sha256::digest(value.to_string().as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

type Row = (String, String, String, Value, bool, String, i64);

fn out(r: Row) -> VariableOut {
    VariableOut { scope: r.0, target: r.1, name: r.2, value: r.3, locked: r.4, updated_by: r.5, updated_at: r.6 }
}

const COLUMNS: &str = "scope, target, name, value, locked, updated_by, (EXTRACT(EPOCH FROM updated_at))::bigint";

// --- resolution ----------------------------------------------------------------------------

/// One variable as an agent sees it, and where it comes from.
#[derive(Serialize, ToSchema, Clone, Debug, PartialEq)]
pub struct Resolution {
    pub name: String,
    pub value: Value,
    pub locked: bool,
    /// `global`, `tenant`, `group:<name>` or `agent:<name>`.
    pub source: String,
    /// Lower layers that define the same name and lose to `source`.
    pub overrides: Vec<String>,
    /// Higher layers that tried to override a constant and were ignored.
    pub ignored: Vec<String>,
}

fn source_of(scope: &str, target: &str) -> String {
    if target.is_empty() { scope.to_owned() } else { format!("{scope}:{target}") }
}

/// Fold layered rows (already ordered global, tenant, group by name, agent) into the values an
/// agent receives, with the conflicts worth reporting.
pub fn fold(rows: &[(String, String, String, Value, bool)]) -> (Vec<Resolution>, Vec<Conflict>) {
    let mut by_name: BTreeMap<&str, Resolution> = BTreeMap::new();
    let mut conflicts = Vec::new();
    for (scope, target, name, value, locked) in rows {
        let source = source_of(scope, target);
        match by_name.get_mut(name.as_str()) {
            None => {
                by_name.insert(name, Resolution { name: name.clone(), value: value.clone(), locked: *locked, source, overrides: vec![], ignored: vec![] });
            }
            Some(cur) if cur.locked => {
                if cur.value != *value {
                    conflicts.push(Conflict { what: format!("variable '{name}'"), resources: vec![cur.source.clone(), source.clone()], resolution: format!("constant from {}: value from {source} ignored", cur.source) });
                }
                cur.ignored.push(source);
            }
            Some(cur) => {
                if scope == "group" && cur.source.starts_with("group:") && cur.value != *value {
                    conflicts.push(Conflict { what: format!("variable '{name}'"), resources: vec![cur.source.clone(), source.clone()], resolution: format!("groups disagree: kept {source} (alphabetical order)") });
                }
                cur.overrides.push(std::mem::replace(&mut cur.source, source));
                cur.value = value.clone();
                cur.locked = *locked;
            }
        }
    }
    (by_name.into_values().collect(), conflicts)
}

/// The layers that apply to one agent, resolved.
pub async fn resolve(st: &AppState, tid: sqlx::types::Uuid, groups: &[String], agent: &str) -> Result<(Vec<Resolution>, Vec<Conflict>), sqlx::Error> {
    let rows: Vec<(String, String, String, Value, bool)> = sqlx::query_as(
        "SELECT scope, target, name, value, locked FROM variables \
         WHERE scope = 'global' OR (tenant_id = $1 AND (scope = 'tenant' OR (scope = 'group' AND target = ANY($2)) OR (scope = 'agent' AND target = $3))) \
         ORDER BY CASE scope WHEN 'global' THEN 0 WHEN 'tenant' THEN 1 WHEN 'group' THEN 2 ELSE 3 END, target, name",
    )
    .bind(tid)
    .bind(groups)
    .bind(agent)
    .fetch_all(&st.pool)
    .await?;
    Ok(fold(&rows))
}

/// Put the resolved variables into a compiled policy: they override the policy defaults, and the
/// constants also override whatever a template resource sets for itself.
pub fn overlay(compiled: &mut Compiled, resolved: &[Resolution]) {
    for r in resolved {
        if r.locked && compiled.vars.get(&r.name).is_some_and(|v| *v != r.value) {
            compiled.conflicts.push(Conflict { what: format!("variable '{}'", r.name), resources: vec![r.source.clone()], resolution: "constant overrides the policy's value".into() });
        }
        compiled.vars.insert(r.name.clone(), r.value.clone());
    }
    let locked: Vec<&str> = resolved.iter().filter(|r| r.locked).map(|r| r.name.as_str()).collect();
    let mut notes = Vec::new();
    for res in &mut compiled.resources {
        let Some(t) = res.template.as_mut() else { continue };
        for name in &locked {
            if t.vars.remove(*name).is_some() {
                notes.push(Conflict { what: format!("variable '{name}'"), resources: vec![res.id.clone()], resolution: "constant: the resource's own value is ignored".into() });
            }
        }
    }
    compiled.conflicts.extend(notes);
}

// --- API: write ----------------------------------------------------------------------------

async fn store(st: &AppState, user: &crate::auth::CurrentUser, tid: Option<sqlx::types::Uuid>, scope: &str, target: &str, name: &str, body: &NewVariable) -> ApiResult<StatusCode> {
    check_var_name(name)?;
    check_value(&body.value)?;
    let mut tx = st.pool.begin().await?;
    // A constant set above cannot be changed from below (resolution would ignore it anyway: refuse early).
    if scope != "global" {
        let above: Option<String> = sqlx::query_scalar("SELECT scope FROM variables WHERE name = $1 AND locked AND (scope = 'global' OR (tenant_id = $2 AND scope = 'tenant' AND $3 <> 'tenant')) ORDER BY scope LIMIT 1").bind(name).bind(tid).bind(scope).fetch_optional(&mut *tx).await?;
        if let Some(by) = above {
            return Err(ApiError(StatusCode::CONFLICT, format!("'{name}' is a constant set at the {by} level and cannot be overridden")));
        }
    }
    let created: bool = sqlx::query_scalar(
        "INSERT INTO variables (scope, tenant_id, target, name, value, locked, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (scope, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'), target, name) \
         DO UPDATE SET value = EXCLUDED.value, locked = EXCLUDED.locked, updated_by = EXCLUDED.updated_by, updated_at = now() RETURNING (xmax = 0)",
    )
    .bind(scope)
    .bind(tid)
    .bind(target)
    .bind(name)
    .bind(&body.value)
    .bind(body.locked)
    .bind(&user.username)
    .fetch_one(&mut *tx)
    .await?;
    audit::append(&mut tx, &NewEvent { tenant_id: tid, actor: &user.username, action: "variable.set", target: Some(name), outcome: "ok", details: json!({ "scope": scope, "target": target, "locked": body.locked, "value_sha256": digest(&body.value) }) }).await?;
    tx.commit().await?;
    Ok(if created { StatusCode::CREATED } else { StatusCode::OK })
}

async fn remove(st: &AppState, user: &crate::auth::CurrentUser, tid: Option<sqlx::types::Uuid>, scope: &str, target: &str, name: &str) -> ApiResult<StatusCode> {
    let mut tx = st.pool.begin().await?;
    let n = sqlx::query("DELETE FROM variables WHERE scope = $1 AND COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000') = COALESCE($2, '00000000-0000-0000-0000-000000000000') AND target = $3 AND name = $4")
        .bind(scope)
        .bind(tid)
        .bind(target)
        .bind(name)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, "variable not found".into()));
    }
    audit::append(&mut tx, &NewEvent { tenant_id: tid, actor: &user.username, action: "variable.delete", target: Some(name), outcome: "ok", details: json!({ "scope": scope, "target": target }) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Scope and target of a tenant-level write: `tenant`, `group:<name>` or `agent:<name>`.
async fn level(st: &AppState, tid: sqlx::types::Uuid, q: &Where) -> ApiResult<(&'static str, String)> {
    let target = q.target.clone().unwrap_or_default();
    match q.scope.as_deref().unwrap_or("tenant") {
        "tenant" if target.is_empty() => Ok(("tenant", String::new())),
        "group" if !target.is_empty() => {
            check_name(&target, "group")?;
            Ok(("group", target))
        }
        "agent" if !target.is_empty() => {
            let known: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM agents WHERE tenant_id = $1 AND name = $2)").bind(tid).bind(&target).fetch_one(&st.pool).await?;
            if known { Ok(("agent", target)) } else { Err(ApiError(StatusCode::NOT_FOUND, "agent not found".into())) }
        }
        _ => Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "scope is tenant (no target), group or agent (with target=<name>)".into())),
    }
}

#[utoipa::path(put, path = "/v1/globals/variables/{name}", tag = "variables", security(("bearer" = [])),
    params(("name" = String, Path)), request_body = NewVariable,
    responses((status = 201, description = "Created"), (status = 200, description = "Updated"), (status = 422)))]
pub async fn put_global(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>, Json(body): Json<NewVariable>) -> ApiResult<StatusCode> {
    user.require_global("globals:write")?;
    let status = store(&st, &user, None, "global", "", &name, &body).await?;
    crate::api::notify_all(&st).await;
    Ok(status)
}

#[utoipa::path(delete, path = "/v1/globals/variables/{name}", tag = "variables", security(("bearer" = [])),
    params(("name" = String, Path)), responses((status = 204), (status = 404)))]
pub async fn delete_global(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>) -> ApiResult<StatusCode> {
    user.require_global("globals:write")?;
    let status = remove(&st, &user, None, "global", "", &name).await?;
    crate::api::notify_all(&st).await;
    Ok(status)
}

#[utoipa::path(put, path = "/v1/tenants/{tenant}/variables/{name}", tag = "variables", security(("bearer" = [])),
    params(("tenant" = String, Path), ("name" = String, Path), Where), request_body = NewVariable,
    responses((status = 201, description = "Created"), (status = 200, description = "Updated"), (status = 409, description = "A constant above cannot be overridden"), (status = 422)))]
pub async fn put_variable(State(st): State<AppState>, Authn(user): Authn, Path((tenant, name)): Path<(String, String)>, Query(q): Query<Where>, Json(body): Json<NewVariable>) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, &tenant, "policies:write").await?;
    let (scope, target) = level(&st, tid, &q).await?;
    let status = store(&st, &user, Some(tid), scope, &target, &name, &body).await?;
    crate::api::notify_tenant(&st, &tenant, tid).await;
    Ok(status)
}

#[utoipa::path(delete, path = "/v1/tenants/{tenant}/variables/{name}", tag = "variables", security(("bearer" = [])),
    params(("tenant" = String, Path), ("name" = String, Path), Where), responses((status = 204), (status = 404)))]
pub async fn delete_variable(State(st): State<AppState>, Authn(user): Authn, Path((tenant, name)): Path<(String, String)>, Query(q): Query<Where>) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, &tenant, "policies:write").await?;
    let (scope, target) = level(&st, tid, &q).await?;
    let status = remove(&st, &user, Some(tid), scope, &target, &name).await?;
    crate::api::notify_tenant(&st, &tenant, tid).await;
    Ok(status)
}

// --- API: read -----------------------------------------------------------------------------

#[utoipa::path(get, path = "/v1/globals/variables", tag = "variables", security(("bearer" = [])),
    responses((status = 200, body = Vec<VariableOut>)))]
pub async fn list_global(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<Vec<VariableOut>>> {
    user.require_global("globals:read")?;
    let rows: Vec<Row> = sqlx::query_as(&format!("SELECT {COLUMNS} FROM variables WHERE scope = 'global' ORDER BY name")).fetch_all(&st.pool).await?;
    Ok(Json(rows.into_iter().map(out).collect()))
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/variables", tag = "variables", security(("bearer" = [])),
    params(("tenant" = String, Path)),
    responses((status = 200, description = "The tenant's own variables (tenant, group and agent level) and the inherited global ones", body = Vec<VariableOut>), (status = 404)))]
pub async fn list_variables(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>) -> ApiResult<Json<Vec<VariableOut>>> {
    let tid = user.tenant(&st.pool, &tenant, "policies:read").await?;
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM variables WHERE scope = 'global' OR tenant_id = $1 \
         ORDER BY CASE scope WHEN 'global' THEN 0 WHEN 'tenant' THEN 1 WHEN 'group' THEN 2 ELSE 3 END, target, name"
    ))
    .bind(tid)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows.into_iter().map(out).collect()))
}

#[derive(Serialize, ToSchema)]
pub struct Resolved {
    pub variables: Vec<Resolution>,
    pub conflicts: Vec<Conflict>,
}

async fn agent_groups(st: &AppState, tid: sqlx::types::Uuid, agent: &str) -> ApiResult<Vec<String>> {
    sqlx::query_scalar("SELECT groups FROM agents WHERE tenant_id = $1 AND name = $2")
        .bind(tid)
        .bind(agent)
        .fetch_optional(&st.pool)
        .await?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "agent not found".into()))
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/agents/{agent}/variables", tag = "variables", security(("bearer" = [])),
    params(("tenant" = String, Path), ("agent" = String, Path)),
    responses((status = 200, description = "Variables as this agent receives them, with their origin", body = Resolved), (status = 404)))]
pub async fn resolved(State(st): State<AppState>, Authn(user): Authn, Path((tenant, agent)): Path<(String, String)>) -> ApiResult<Json<Resolved>> {
    let tid = user.tenant(&st.pool, &tenant, "agents:preview").await?;
    let groups = agent_groups(&st, tid, &agent).await?;
    let (variables, conflicts) = resolve(&st, tid, &groups, &agent).await?;
    Ok(Json(Resolved { variables, conflicts }))
}

// --- API: render preview ---------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct Rendered {
    /// The template resource (`<policy>/<id>`).
    pub resource: String,
    pub dest: String,
    /// The rendering, with secrets masked; absent when rendering failed.
    pub output: Option<String>,
    /// Why rendering failed (for example an undefined variable).
    pub error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Preview {
    pub templates: Vec<Rendered>,
    pub notes: Vec<String>,
}

/// Render every template resource of the agent's effective policy the way the agent will, except
/// that secrets are masked and the host facts are placeholders (the Core does not know them). The
/// Core only renders text here; it never applies anything.
#[utoipa::path(get, path = "/v1/tenants/{tenant}/agents/{agent}/render", tag = "variables", security(("bearer" = [])),
    params(("tenant" = String, Path), ("agent" = String, Path)),
    responses((status = 200, body = Preview), (status = 404)))]
pub async fn render(State(st): State<AppState>, Authn(user): Authn, Path((tenant, agent)): Path<(String, String)>) -> ApiResult<Json<Preview>> {
    let tid = user.tenant(&st.pool, &tenant, "agents:preview").await?;
    let groups = agent_groups(&st, tid, &agent).await?;
    let compiled = crate::api::compile_for(&st, tid, &agent, &groups).await?;

    let masked: BTreeMap<&String, &str> = compiled.secrets.iter().map(|n| (n, "********")).collect();
    let facts = json!({ "hostname": "<hostname>", "os_id": "<os_id>", "os_version_id": "<os_version_id>" });
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    env.set_keep_trailing_newline(true);

    let mut templates = Vec::new();
    for r in &compiled.resources {
        let Some(t) = &r.template else { continue };
        let mut item = Rendered { resource: r.id.clone(), dest: t.dest.clone(), output: None, error: None };
        let rendered: Result<String, String> = async {
            let name = t.src.strip_prefix("artifact://").ok_or("src must be an artifact:// reference")?;
            let pinned = compiled.artifacts.get(name).ok_or("artifact not available")?;
            let bytes = crate::artifacts::read_small(&st, tid, name, &pinned.sha256, MAX_TEMPLATE_BYTES).await.map_err(|e| e.1)?;
            let source = String::from_utf8(bytes).map_err(|_| "template is not valid UTF-8".to_string())?;
            let mut vars: BTreeMap<&String, &Value> = compiled.vars.iter().collect();
            vars.extend(t.vars.iter());
            env.render_str(&source, minijinja::context! { vars => vars, secrets => &masked, facts => &facts }).map_err(|e| format!("{e:#}"))
        }
        .await;
        match rendered {
            Ok(text) => item.output = Some(text),
            Err(e) => item.error = Some(e),
        }
        templates.push(item);
    }
    Ok(Json(Preview { templates, notes: vec!["secrets are shown as ********".into(), "host facts (hostname, os_id, os_version_id) are placeholders: the agent fills them in".into()] }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(scope: &str, target: &str, name: &str, value: Value, locked: bool) -> (String, String, String, Value, bool) {
        (scope.into(), target.into(), name.into(), value, locked)
    }

    #[test]
    fn the_most_specific_layer_wins_and_says_what_it_hides() {
        let (r, conflicts) = fold(&[
            row("global", "", "env", json!("prod"), false),
            row("tenant", "", "env", json!("staging"), false),
            row("agent", "web-1", "env", json!("canary"), false),
            row("tenant", "", "port", json!(80), false),
        ]);
        let env = r.iter().find(|x| x.name == "env").unwrap();
        assert_eq!((env.value.clone(), env.source.as_str(), env.overrides.clone()), (json!("canary"), "agent:web-1", vec!["global".to_string(), "tenant".to_string()]));
        assert_eq!(r.iter().find(|x| x.name == "port").unwrap().source, "tenant");
        assert!(conflicts.is_empty());
    }

    #[test]
    fn a_constant_cannot_be_overridden_and_the_attempt_is_reported() {
        let (r, conflicts) = fold(&[row("global", "", "region", json!("eu"), true), row("tenant", "", "region", json!("us"), false), row("agent", "a", "region", json!("eu"), false)]);
        assert_eq!((r[0].value.clone(), r[0].source.as_str(), r[0].ignored.len()), (json!("eu"), "global", 2));
        // Only the attempt that would have changed the value is a conflict.
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].resolution.contains("tenant"));
    }

    #[test]
    fn groups_apply_alphabetically_and_disagreement_is_reported() {
        let (r, conflicts) = fold(&[row("group", "a", "tier", json!("gold"), false), row("group", "b", "tier", json!("silver"), false)]);
        assert_eq!((r[0].value.clone(), r[0].source.as_str()), (json!("silver"), "group:b"));
        assert_eq!(conflicts.len(), 1);
        let (_, same) = fold(&[row("group", "a", "tier", json!("x"), false), row("group", "b", "tier", json!("x"), false)]);
        assert!(same.is_empty());
    }

    #[test]
    fn overlay_beats_policy_defaults_and_constants_beat_the_resource() {
        let policy = delbert_policy::from_yaml(
            "apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: p, tenant: t }\nspec:\n  vars: { port: 80, region: us }\n  resources:\n    - id: conf\n      template: { src: \"artifact://a.j2\", dest: /etc/a, vars: { region: ap, extra: 1 } }\n",
        )
        .unwrap();
        let mut compiled = crate::compile::compile(
            &[crate::compile::PolicyInput { name: "p".into(), priority: 0, secrets: vec![], vars: policy.spec.vars, resources: policy.spec.resources }],
            &[crate::compile::Strategy::Error],
            &BTreeMap::from([("a.j2".to_string(), delbert_wire::ArtifactRef { sha256: "ab".repeat(32), size: 1 })]),
        );
        let (resolved, _) = fold(&[row("global", "", "region", json!("eu"), true), row("tenant", "", "port", json!(8080), false)]);
        overlay(&mut compiled, &resolved);
        assert_eq!(compiled.vars["port"], 8080);
        assert_eq!(compiled.vars["region"], "eu");
        let vars = &compiled.resources[0].template.as_ref().unwrap().vars;
        assert!(!vars.contains_key("region") && vars.contains_key("extra"));
        assert_eq!(compiled.conflicts.len(), 2, "{:?}", compiled.conflicts);
    }

    #[test]
    fn names_and_values_are_checked() {
        assert!(check_var_name("app_port").is_ok() && check_var_name("_x1").is_ok());
        for bad in ["", "1a", "a-b", "a.b", &"a".repeat(65)] {
            assert!(check_var_name(bad).is_err(), "{bad}");
        }
        assert!(check_value(&json!(null)).is_err());
        assert!(check_value(&json!("x".repeat(MAX_VALUE_BYTES))).is_err());
        assert!(check_value(&json!({ "a": [1, 2] })).is_ok());
    }
}
