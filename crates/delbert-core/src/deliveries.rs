//! Configuration delivery to workloads (migration `0021`, docs/ABSTRACT.md §5).
//!
//! Containers are ephemeral, so they get no agent and no identity: configuration is delivered
//! per environment. A *delivery* names a tenant environment and the identity (the Kubernetes
//! Operator, enrolled as an agent) that may fetch it. The bundle has:
//!
//! * **variables**: the layered variables resolved for the group named like the delivery
//!   (global, tenant, group). Strings are delivered as they are, any other JSON value as compact
//!   JSON;
//! * **files**: the latest version of the listed artifacts, as UTF-8 text (tenant artifact first,
//!   then the global one);
//! * **sensitive**: the listed tenant secrets, decrypted by the Core and re-encrypted to the
//!   fetching identity only (age, base64), exactly like secrets in an effective policy.
//!
//! The Core only builds the bundle; the Operator applies it in its own cluster. A bundle that
//! cannot be complete (missing secret or file, bad content) is refused as a whole: a workload is
//! never handed a half configuration.

use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use delbert_pki::authn::Proof;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::{
    api::{ApiError, ApiResult, AppState, check_name, tenant_id},
    audit::{self, NewEvent},
    auth::Authn,
};

/// One file in the bundle; the whole bundle must fit a Kubernetes ConfigMap (1 MiB).
const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_FILES_BYTES: usize = 768 * 1024;
const MAX_ITEMS: usize = 64;

#[derive(Serialize, ToSchema)]
pub struct DeliveryOut {
    pub name: String,
    /// Identity allowed to fetch the bundle.
    pub agent: String,
    pub secrets: Vec<String>,
    pub files: Vec<String>,
    pub updated_by: String,
    /// Unix seconds.
    pub updated_at: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct NewDelivery {
    /// The enrolled agent (the Operator) that fetches this delivery.
    pub agent: String,
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Artifact names delivered as files.
    #[serde(default)]
    pub files: Vec<String>,
}

/// What the Operator receives.
#[derive(Serialize, Deserialize, ToSchema, Debug, PartialEq)]
pub struct DeliveryBundle {
    /// Unix seconds of the latest change among the inputs. Informational: a removal is not
    /// reflected, so decide on changes by comparing content, not versions.
    pub version: i64,
    pub variables: BTreeMap<String, String>,
    pub files: BTreeMap<String, String>,
    /// Secret name → base64 of the age ciphertext for the fetching identity.
    pub sensitive: BTreeMap<String, String>,
}

type Row = (String, String, Vec<String>, Vec<String>, String, i64);

const COLUMNS: &str =
    "name, agent, secrets, files, updated_by, (EXTRACT(EPOCH FROM updated_at))::bigint";

fn out(r: Row) -> DeliveryOut {
    DeliveryOut {
        name: r.0,
        agent: r.1,
        secrets: r.2,
        files: r.3,
        updated_by: r.4,
        updated_at: r.5,
    }
}

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

fn check_list(names: &[String], what: &str) -> ApiResult<()> {
    if names.len() > MAX_ITEMS {
        return Err(unprocessable(format!("at most {MAX_ITEMS} {what}")));
    }
    names.iter().try_for_each(|n| check_name(n, what))
}

/// A variable as an environment value: strings as they are, everything else as compact JSON.
fn as_text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

// --- API: administration -------------------------------------------------------------------

#[utoipa::path(get, path = "/v1/tenants/{tenant}/deliveries", tag = "deliveries", security(("bearer" = [])),
    params(("tenant" = String, Path)), responses((status = 200, body = Vec<DeliveryOut>), (status = 404)))]
pub async fn list(
    State(st): State<AppState>,
    Authn(user): Authn,
    Path(tenant): Path<String>,
) -> ApiResult<Json<Vec<DeliveryOut>>> {
    let tid = user.tenant(&st.pool, &tenant, "policies:read").await?;
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM deliveries WHERE tenant_id = $1 ORDER BY name"
    ))
    .bind(tid)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows.into_iter().map(out).collect()))
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/deliveries/{name}", tag = "deliveries", security(("bearer" = [])),
    params(("tenant" = String, Path), ("name" = String, Path)), responses((status = 200, body = DeliveryOut), (status = 404)))]
pub async fn get(
    State(st): State<AppState>,
    Authn(user): Authn,
    Path((tenant, name)): Path<(String, String)>,
) -> ApiResult<Json<DeliveryOut>> {
    let tid = user.tenant(&st.pool, &tenant, "policies:read").await?;
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM deliveries WHERE tenant_id = $1 AND name = $2"
    ))
    .bind(tid)
    .bind(&name)
    .fetch_optional(&st.pool)
    .await?;
    row.map(|r| Json(out(r)))
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "delivery not found".into()))
}

#[utoipa::path(put, path = "/v1/tenants/{tenant}/deliveries/{name}", tag = "deliveries", security(("bearer" = [])),
    params(("tenant" = String, Path), ("name" = String, Path)), request_body = NewDelivery,
    responses((status = 201, description = "Created"), (status = 200, description = "Updated"), (status = 404, description = "Unknown tenant or agent"), (status = 422)))]
pub async fn put(
    State(st): State<AppState>,
    Authn(user): Authn,
    Path((tenant, name)): Path<(String, String)>,
    Json(body): Json<NewDelivery>,
) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, &tenant, "policies:write").await?;
    check_name(&name, "delivery")?;
    check_name(&body.agent, "agent")?;
    check_list(&body.secrets, "secret")?;
    check_list(&body.files, "file")?;
    let known: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM agents WHERE tenant_id = $1 AND name = $2)",
    )
    .bind(tid)
    .bind(&body.agent)
    .fetch_one(&st.pool)
    .await?;
    if !known {
        return Err(ApiError(StatusCode::NOT_FOUND, "agent not found".into()));
    }
    let mut tx = st.pool.begin().await?;
    let created: bool = sqlx::query_scalar(
        "INSERT INTO deliveries (tenant_id, name, agent, secrets, files, updated_by) VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (tenant_id, name) DO UPDATE SET agent = EXCLUDED.agent, secrets = EXCLUDED.secrets, files = EXCLUDED.files, updated_by = EXCLUDED.updated_by, updated_at = now() \
         RETURNING (xmax = 0)",
    )
    .bind(tid)
    .bind(&name)
    .bind(&body.agent)
    .bind(&body.secrets)
    .bind(&body.files)
    .bind(&user.username)
    .fetch_one(&mut *tx)
    .await?;
    audit::append(
        &mut tx,
        &NewEvent {
            tenant_id: Some(tid),
            actor: &user.username,
            action: "delivery.set",
            target: Some(&name),
            outcome: "ok",
            details: json!({ "agent": body.agent, "secrets": body.secrets, "files": body.files }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    })
}

#[utoipa::path(delete, path = "/v1/tenants/{tenant}/deliveries/{name}", tag = "deliveries", security(("bearer" = [])),
    params(("tenant" = String, Path), ("name" = String, Path)), responses((status = 204), (status = 404)))]
pub async fn delete(
    State(st): State<AppState>,
    Authn(user): Authn,
    Path((tenant, name)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, &tenant, "policies:write").await?;
    let mut tx = st.pool.begin().await?;
    let n = sqlx::query("DELETE FROM deliveries WHERE tenant_id = $1 AND name = $2")
        .bind(tid)
        .bind(&name)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, "delivery not found".into()));
    }
    audit::append(
        &mut tx,
        &NewEvent {
            tenant_id: Some(tid),
            actor: &user.username,
            action: "delivery.delete",
            target: Some(&name),
            outcome: "ok",
            details: json!({}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- API: bundle for the Operator ----------------------------------------------------------

/// Build the bundle of delivery `name` for `agent`.
async fn build(
    st: &AppState,
    tid: sqlx::types::Uuid,
    name: &str,
    agent: &str,
) -> ApiResult<DeliveryBundle> {
    let row: Option<(Vec<String>, Vec<String>, i64)> = sqlx::query_as(
        "SELECT d.secrets, d.files, (EXTRACT(EPOCH FROM d.updated_at))::bigint FROM deliveries d WHERE d.tenant_id = $1 AND d.name = $2 AND d.agent = $3",
    )
    .bind(tid)
    .bind(name)
    .bind(agent)
    .fetch_optional(&st.pool)
    .await?;
    // Same answer for "no such delivery" and "not yours": no enumeration.
    let (secret_names, file_names, mut version) =
        row.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "delivery not found".into()))?;

    // Variables: global, tenant and the group named like the delivery. No agent layer.
    let (resolved, _) = crate::variables::resolve(st, tid, &[name.to_owned()], "").await?;
    let variables: BTreeMap<String, String> = resolved
        .iter()
        .map(|r| (r.name.clone(), as_text(&r.value)))
        .collect();
    let changed: Option<i64> = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM max(updated_at)))::bigint FROM variables WHERE scope = 'global' OR (tenant_id = $1 AND (scope = 'tenant' OR (scope = 'group' AND target = $2)))",
    )
    .bind(tid)
    .bind(name)
    .fetch_one(&st.pool)
    .await?;
    version = version.max(changed.unwrap_or(0));

    // Files: the latest version of each artifact, the tenant's own over the global one.
    let catalog = crate::artifacts::catalog(st, tid).await?;
    let (mut files, mut total) = (BTreeMap::new(), 0usize);
    for file in &file_names {
        let pinned = catalog.get(file).ok_or_else(|| {
            ApiError(
                StatusCode::CONFLICT,
                format!("file '{file}' is not an available artifact"),
            )
        })?;
        if pinned.size as usize > MAX_FILE_BYTES {
            return Err(unprocessable(format!(
                "file '{file}' is larger than {} KiB",
                MAX_FILE_BYTES / 1024
            )));
        }
        let bytes =
            crate::artifacts::read_small(st, tid, file, &pinned.sha256, MAX_FILE_BYTES).await?;
        total += bytes.len();
        if total > MAX_FILES_BYTES {
            return Err(unprocessable(format!(
                "files are larger than {} KiB in total",
                MAX_FILES_BYTES / 1024
            )));
        }
        files.insert(
            file.clone(),
            String::from_utf8(bytes)
                .map_err(|_| unprocessable(format!("file '{file}' is not valid UTF-8")))?,
        );
    }
    let newest_artifact: Option<i64> = sqlx::query_scalar(
        "SELECT max(t) FROM (SELECT (EXTRACT(EPOCH FROM max(created_at)))::bigint AS t FROM artifacts WHERE tenant_id = $1 AND name = ANY($2) \
         UNION ALL SELECT (EXTRACT(EPOCH FROM max(created_at)))::bigint FROM global_artifacts WHERE name = ANY($2)) x",
    )
    .bind(tid)
    .bind(&file_names)
    .fetch_one(&st.pool)
    .await?;
    version = version.max(newest_artifact.unwrap_or(0));

    // Sensitive: re-encrypted to the fetching identity only.
    let plain = crate::secrets::load(st, tid, &secret_names).await?;
    if let Some(missing) = secret_names.iter().find(|n| !plain.contains_key(*n)) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!("secret '{missing}' does not exist"),
        ));
    }
    let mut sensitive = BTreeMap::new();
    if !plain.is_empty() {
        let recipient: Option<String> = sqlx::query_scalar(
            "SELECT enc_public_key FROM agents WHERE tenant_id = $1 AND name = $2",
        )
        .bind(tid)
        .bind(agent)
        .fetch_one(&st.pool)
        .await?;
        let recipient = recipient.ok_or_else(|| {
            ApiError(
                StatusCode::CONFLICT,
                "agent has no encryption key (not enrolled)".into(),
            )
        })?;
        for (secret, value) in &plain {
            sensitive.insert(
                secret.clone(),
                B64.encode(crate::secrets::seal_for_agent(&recipient, value)?),
            );
        }
        let newest_secret: Option<i64> = sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM max(updated_at)))::bigint FROM secrets WHERE tenant_id = $1 AND name = ANY($2)").bind(tid).bind(&secret_names).fetch_one(&st.pool).await?;
        version = version.max(newest_secret.unwrap_or(0));
    }
    Ok(DeliveryBundle {
        version,
        variables,
        files,
        sensitive,
    })
}

/// Bundle fetch: `Authorization: Delbert-Agent <base64 of the proof JSON>`, proof kind
/// `delivery` over the delivery name.
#[utoipa::path(get, path = "/v1/agent/{tenant}/{agent}/deliveries/{name}", tag = "deliveries",
    params(("tenant" = String, Path), ("agent" = String, Path), ("name" = String, Path)),
    responses((status = 200, body = DeliveryBundle), (status = 401), (status = 404), (status = 409, description = "A secret or file of the delivery is missing"), (status = 422)))]
pub async fn fetch(
    State(st): State<AppState>,
    Path((tenant, agent, name)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<DeliveryBundle>> {
    let unauthorized = || ApiError(StatusCode::UNAUTHORIZED, "invalid agent proof".into());
    let proof: Proof = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Delbert-Agent "))
        .and_then(|v| B64.decode(v).ok())
        .and_then(|v| serde_json::from_slice(&v).ok())
        .ok_or_else(unauthorized)?;
    if !crate::bus::proven(
        &st,
        "delivery",
        &tenant,
        &agent,
        &Value::String(name.clone()),
        Some(&proof),
    )
    .await
    {
        return Err(unauthorized());
    }
    let tid = tenant_id(&st.pool, &tenant).await?;
    Ok(Json(build(&st, tid, &name, &agent).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variables_become_text() {
        assert_eq!(as_text(&json!("info")), "info");
        assert_eq!(as_text(&json!(8080)), "8080");
        assert_eq!(as_text(&json!(true)), "true");
        assert_eq!(as_text(&json!({ "a": [1, 2] })), r#"{"a":[1,2]}"#);
    }
}
