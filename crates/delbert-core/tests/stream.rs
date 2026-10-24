//! Live status stream: hints arrive after commit, only for tenants the caller can reach.

mod common;

use std::time::Duration;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{Client, admin_client, state};
use delbert_core::{compile::Strategy, stream};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

/// Opens the stream as `client` and returns the response (the body is read frame by frame).
async fn open(client: &Client) -> axum::response::Response {
    let mut req = Request::builder().method("GET").uri("/v1/stream");
    if let Some(t) = &client.token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    client.app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
}

/// The `data:` payloads that arrive within `wait`.
async fn hints(resp: axum::response::Response, wait: Duration) -> Vec<Value> {
    let mut body = resp.into_body();
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Some(Ok(frame))) = tokio::time::timeout_at(deadline, body.frame()).await {
        if let Some(data) = frame.data_ref() {
            text.push_str(&String::from_utf8_lossy(data));
        }
    }
    text.lines().filter_map(|l| l.strip_prefix("data:")).filter_map(|d| serde_json::from_str(d.trim()).ok()).collect()
}

#[sqlx::test]
async fn changes_are_streamed_after_commit_and_only_to_those_who_may_see_them(pool: PgPool) {
    let mut s = state(pool.clone(), vec![Strategy::Error], None);
    let tx = stream::channel();
    s.changes = tx.clone();
    stream::spawn_listener(pool, tx);
    tokio::time::sleep(Duration::from_millis(400)).await; // let LISTEN register
    let admin = admin_client(s).await;
    assert_eq!(admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await.0, StatusCode::CREATED);
    assert_eq!(admin.call("POST", "/v1/tenants", Some(json!({ "name": "beta" }))).await.0, StatusCode::CREATED);
    let mk = |name: &'static str, role: &'static str, tenant: Value| {
        let admin = admin.clone();
        async move {
            let r = admin.call("POST", "/v1/users", Some(json!({ "username": name, "password": "a-long-enough-password", "assignments": [{ "role": role, "tenant": tenant }] }))).await;
            assert_eq!(r.0, StatusCode::CREATED, "{}", r.1);
            admin.as_user(name, "a-long-enough-password").await
        }
    };
    let olivia = mk("olivia", "operator", json!("acme")).await; // reaches acme only
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Not signed in: refused.
    let anon = Client { token: None, ..admin.clone() };
    assert_eq!(open(&anon).await.status(), StatusCode::UNAUTHORIZED);

    let (admin_stream, olivia_stream) = (open(&admin).await, open(&olivia).await);
    assert_eq!(admin_stream.status(), StatusCode::OK);
    assert!(admin_stream.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/event-stream"));

    // One change in each tenant, after both streams are open.
    let (a, b) = tokio::join!(
        admin.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "a1" }))),
        admin.call("POST", "/v1/tenants/beta/agents", Some(json!({ "name": "b1" }))),
    );
    assert_eq!((a.0, b.0), (StatusCode::CREATED, StatusCode::CREATED));

    let (all, mine) = tokio::join!(hints(admin_stream, Duration::from_millis(1500)), hints(olivia_stream, Duration::from_millis(1500)));
    // The hint carries its kind and nothing else.
    assert!(all.iter().all(|h| h == &json!({ "kind": "audit" })), "{all:?}");
    assert_eq!(all.len(), 2, "the administrator hears both changes: {all:?}");
    assert_eq!(mine.len(), 1, "the tenant operator hears only acme: {mine:?}");
}
