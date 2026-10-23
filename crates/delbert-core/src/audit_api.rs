//! Browsing and exporting the audit trail (docs/RBAC.md). Reads are scoped like everything
//! else: a global `audit:read` sees every event, a tenant-scoped one only its tenants' events.
//! Exports carry the hashes and raw fields needed to recompute the chain offline, and are
//! themselves audited.

use axum::{
    Json,
    body::Body,
    extract::{Query, State},
    http::{StatusCode, header},
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, QueryBuilder, types::Uuid};
use utoipa::{IntoParams, ToSchema};

use crate::{
    api::{ApiError, ApiResult, AppState},
    audit::{self, NewEvent},
    auth::{Authn, CurrentUser},
};

const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 1000;
const EXPORT_CHUNK: i64 = 1000;

#[derive(Deserialize, IntoParams, Clone, Default)]
#[into_params(parameter_in = Query)]
pub struct AuditQuery {
    /// Only events of this tenant (by name).
    pub tenant: Option<String>,
    pub actor: Option<String>,
    /// Exact action, or a prefix when it ends with `*` (`policy.*`).
    pub action: Option<String>,
    pub target: Option<String>,
    /// `ok`, `denied`, ...
    pub outcome: Option<String>,
    /// Unix seconds, inclusive.
    pub from: Option<i64>,
    /// Unix seconds, exclusive.
    pub to: Option<i64>,
    /// Keyset cursor: only events with a lower sequence number (the `next` of the previous page).
    pub before: Option<i64>,
    /// Page size (default 100, at most 1000).
    pub limit: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct AuditEvent {
    pub seq: i64,
    /// Microseconds since the Unix epoch, as hashed.
    pub occurred_at_micros: i64,
    pub tenant_id: Option<String>,
    pub tenant: Option<String>,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub outcome: String,
    pub details: Value,
    /// Hex SHA-256 of the previous event (absent for the first).
    pub prev_hash: Option<String>,
    pub hash: String,
}

#[derive(Serialize, ToSchema)]
pub struct AuditPage {
    /// Newest first.
    pub events: Vec<AuditEvent>,
    /// Pass as `before` to get the next (older) page; absent on the last page.
    pub next: Option<i64>,
}

type Row = (i64, i64, Option<Uuid>, Option<String>, String, String, Option<String>, String, Value, Option<Vec<u8>>, Vec<u8>);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn event(r: Row) -> AuditEvent {
    AuditEvent {
        seq: r.0,
        occurred_at_micros: r.1,
        tenant_id: r.2.map(|t| t.to_string()),
        tenant: r.3,
        actor: r.4,
        action: r.5,
        target: r.6,
        outcome: r.7,
        details: r.8,
        prev_hash: r.9.as_deref().map(hex),
        hash: hex(&r.10),
    }
}

/// What the caller may see, resolved once per request.
#[derive(Clone)]
struct Scope {
    /// `None` = every tenant and the platform-level events.
    tenants: Option<Vec<Uuid>>,
}

fn scope(user: &CurrentUser, permission: &str) -> ApiResult<Scope> {
    let tenants = user.tenants_with(permission);
    if tenants.as_ref().is_some_and(Vec::is_empty) {
        return Err(ApiError(StatusCode::FORBIDDEN, format!("missing permission '{permission}'")));
    }
    Ok(Scope { tenants })
}

/// Filters resolved to ids, ready for SQL.
#[derive(Clone)]
struct Filter {
    scope: Scope,
    tenant: Option<Uuid>,
    q: AuditQuery,
}

async fn resolve(st: &AppState, user: &CurrentUser, permission: &str, q: AuditQuery) -> ApiResult<Filter> {
    let scope = scope(user, permission)?;
    let tenant = match &q.tenant {
        Some(name) => Some(user.tenant(&st.pool, name, permission).await?),
        None => None,
    };
    Ok(Filter { scope, tenant, q })
}

fn select<'a>(f: &'a Filter) -> QueryBuilder<'a, Postgres> {
    let mut qb = QueryBuilder::new(
        "SELECT e.seq, (EXTRACT(EPOCH FROM e.occurred_at) * 1000000)::bigint, e.tenant_id, t.name, e.actor, e.action, e.target, e.outcome, e.details, e.prev_hash, e.hash \
         FROM audit_events e LEFT JOIN tenants t ON t.id = e.tenant_id WHERE true",
    );
    if let Some(ids) = &f.scope.tenants {
        qb.push(" AND e.tenant_id = ANY(").push_bind(ids.clone()).push(")");
    }
    if let Some(t) = f.tenant {
        qb.push(" AND e.tenant_id = ").push_bind(t);
    }
    if let Some(v) = &f.q.actor {
        qb.push(" AND e.actor = ").push_bind(v);
    }
    if let Some(v) = &f.q.action {
        match v.strip_suffix('*') {
            Some(prefix) => qb.push(" AND starts_with(e.action, ").push_bind(prefix.to_owned()).push(")"),
            None => qb.push(" AND e.action = ").push_bind(v),
        };
    }
    if let Some(v) = &f.q.target {
        qb.push(" AND e.target = ").push_bind(v);
    }
    if let Some(v) = &f.q.outcome {
        qb.push(" AND e.outcome = ").push_bind(v);
    }
    if let Some(v) = f.q.from {
        qb.push(" AND e.occurred_at >= to_timestamp(").push_bind(v).push(")");
    }
    if let Some(v) = f.q.to {
        qb.push(" AND e.occurred_at < to_timestamp(").push_bind(v).push(")");
    }
    qb
}

#[utoipa::path(get, path = "/v1/audit", tag = "audit", security(("bearer" = [])), params(AuditQuery),
    responses((status = 200, body = AuditPage), (status = 403), (status = 404, description = "Unknown or unreachable tenant")))]
pub async fn list(State(st): State<AppState>, Authn(user): Authn, Query(q): Query<AuditQuery>) -> ApiResult<Json<AuditPage>> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let before = q.before;
    let f = resolve(&st, &user, "audit:read", q).await?;
    let mut qb = select(&f);
    if let Some(b) = before {
        qb.push(" AND e.seq < ").push_bind(b);
    }
    qb.push(" ORDER BY e.seq DESC LIMIT ").push_bind(limit + 1);
    let mut rows: Vec<Row> = qb.build_query_as().fetch_all(&st.pool).await?;
    let next = (rows.len() as i64 > limit).then(|| {
        rows.truncate(limit as usize);
        rows.last().map(|r| r.0)
    });
    Ok(Json(AuditPage { events: rows.into_iter().map(event).collect(), next: next.flatten() }))
}

async fn chunk(pool: &PgPool, f: &Filter, after: i64) -> Result<Vec<Row>, sqlx::Error> {
    let mut qb = select(f);
    qb.push(" AND e.seq > ").push_bind(after).push(" ORDER BY e.seq ASC LIMIT ").push_bind(EXPORT_CHUNK);
    qb.build_query_as().fetch_all(pool).await
}

#[utoipa::path(get, path = "/v1/audit/export", tag = "audit", security(("bearer" = [])), params(AuditQuery),
    description = "Newline-delimited JSON, oldest first, one event per line with the fields and hashes needed to recompute the chain. `before` and `limit` are ignored. The export is itself audited.",
    responses((status = 200, content_type = "application/x-ndjson"), (status = 403), (status = 404)))]
pub async fn export(State(st): State<AppState>, Authn(user): Authn, Query(q): Query<AuditQuery>) -> ApiResult<Response> {
    let f = resolve(&st, &user, "audit:export", q).await?;
    let mut tx = st.pool.begin().await?;
    let details = json!({ "tenant": f.q.tenant, "actor": f.q.actor, "action": f.q.action, "target": f.q.target, "outcome": f.q.outcome, "from": f.q.from, "to": f.q.to, "all_tenants": f.scope.tenants.is_none() });
    audit::append(&mut tx, &NewEvent { tenant_id: f.tenant, actor: &user.username, action: "audit.export", target: None, outcome: "ok", details }).await?;
    tx.commit().await?;

    let pool = st.pool.clone();
    let stream = futures::stream::unfold((Some(0i64), pool, f), |(after, pool, f)| async move {
        let after = after?;
        match chunk(&pool, &f, after).await {
            Ok(rows) if rows.is_empty() => None,
            Ok(rows) => {
                let last = rows.last().map(|r| r.0);
                let mut out = String::new();
                for r in rows {
                    out.push_str(&serde_json::to_string(&event(r)).unwrap_or_default());
                    out.push('\n');
                }
                let next = if last.is_some_and(|_| out.lines().count() as i64 == EXPORT_CHUNK) { last } else { None };
                Some((Ok::<_, std::io::Error>(out), (next, pool, f)))
            }
            Err(e) => {
                tracing::error!("audit export failed: {e}");
                Some((Err(std::io::Error::other("export interrupted")), (None, pool, f)))
            }
        }
    });
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::CONTENT_DISPOSITION, "attachment; filename=\"delbert-audit.ndjson\"")
        .body(Body::from_stream(stream))
        .expect("valid response"))
}
