//! Shared helpers for the API integration tests.
#![allow(dead_code)]

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use delbert_core::{
    api::{AppState, router},
    auth,
    bus::Bus,
    compile::Strategy,
};
use delbert_wire::Signer;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

pub const ADMIN_PASSWORD: &str = "correct-horse-battery";

pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

pub fn state(pool: PgPool, strategies: Vec<Strategy>, bus: Option<Bus>) -> AppState {
    AppState { pool, signer: Some(Arc::new(Signer::new(signing_key(), "k1"))), ttl_secs: 3600, strategies: Arc::new(strategies), bus, docs: true, secrets_key: Some(Arc::new(delbert_core::secrets::SecretsKeys::new(age::x25519::Identity::generate(), vec![]))), pki: Some(Arc::new(delbert_pki::Ca::create("Test CA", 30).unwrap())), agent_cert_days: 30, public_nats_url: None, approval_default: false, auth: Default::default(), trust: None, published_keys: vec![], content: Default::default(), blobs: delbert_core::blobs::Blobs::memory() }
}

/// An HTTP client against the router, authenticated as `token` (if any).
#[derive(Clone)]
pub struct Client {
    pub app: Router,
    pub token: Option<String>,
}

impl Client {
    pub async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(t) = &self.token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let body = match body {
            Some(b) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let resp = self.app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    /// Raw response body as text (for non-JSON endpoints).
    pub async fn text(&self, method: &str, uri: &str) -> (StatusCode, String) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(t) = &self.token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let resp = self.app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    pub async fn login(&self, username: &str, password: &str) -> (StatusCode, Value) {
        Client { token: None, ..self.clone() }.call("POST", "/v1/auth/login", Some(json!({ "username": username, "password": password }))).await
    }

    /// A client logged in as `username`.
    pub async fn as_user(&self, username: &str, password: &str) -> Client {
        let (status, body) = self.login(username, password).await;
        assert_eq!(status, StatusCode::OK, "login failed: {body}");
        Client { token: Some(body["token"].as_str().unwrap().to_owned()), ..self.clone() }
    }
}

/// Bootstraps the admin user and returns a client logged in as it.
pub async fn admin_client(app_state: AppState) -> Client {
    auth::bootstrap_admin(&app_state.pool, Some(ADMIN_PASSWORD)).await.unwrap();
    let anon = Client { app: router(app_state), token: None };
    anon.as_user("admin", ADMIN_PASSWORD).await
}

/// What an agent keeps after enrollment.
pub struct Enrolled {
    pub cert_pem: String,
    pub key_pem: String,
    pub age: age::x25519::Identity,
}

/// Enrolls `agent` through the API (as `admin`; also creates it, in group `web`).
pub async fn enroll_agent(admin: &Client, tenant: &str, agent: &str) -> Enrolled {
    let (status, key) = admin.call("POST", &format!("/v1/tenants/{tenant}/enrollment-keys"), Some(json!({ "groups": ["web"] }))).await;
    assert_eq!(status, StatusCode::CREATED, "{key}");
    let (key_pem, csr_pem) = delbert_pki::new_identity(agent).unwrap();
    let age = age::x25519::Identity::generate();
    let anon = Client { token: None, ..admin.clone() };
    let (status, body) = anon
        .call("POST", "/v1/enroll", Some(json!({ "psk": key["key"], "agent_name": agent, "csr_pem": csr_pem, "enc_public_key": age.to_public().to_string() })))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    Enrolled { cert_pem: body["cert_pem"].as_str().unwrap().to_owned(), key_pem, age }
}

impl Client {
    /// Raw request with custom headers and body; returns the status and the body bytes.
    pub async fn raw(&self, method: &'static str, uri: impl Into<String>, headers: Vec<(&'static str, String)>, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let mut req = Request::builder().method(method).uri(uri.into());
        if let Some(t) = &self.token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let resp = self.app.clone().oneshot(req.body(Body::from(body)).unwrap()).await.unwrap();
        let status = resp.status();
        (status, resp.into_body().collect().await.unwrap().to_bytes().to_vec())
    }
}

/// What a proxy keeps after enrollment.
pub struct EnrolledProxy {
    pub site: String,
    pub key_pem: String,
    pub cert_pem: String,
}

/// Creates and enrolls a proxy through the API (as `admin`).
pub async fn enroll_proxy(admin: &Client, site: &str) -> EnrolledProxy {
    let (status, created) = admin.call("POST", "/v1/proxies", Some(json!({ "name": site, "dns_names": [format!("{site}.example.com")] }))).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let (key_pem, csr_pem) = delbert_pki::new_identity(site).unwrap();
    let anon = Client { token: None, ..admin.clone() };
    let (status, body) = anon.call("POST", "/v1/proxies/enroll", Some(json!({ "name": site, "psk": created["key"], "csr_pem": csr_pem }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    EnrolledProxy { site: site.into(), key_pem, cert_pem: body["cert_pem"].as_str().unwrap().to_owned() }
}

impl EnrolledProxy {
    pub fn proof(&self, kind: &str, body: &Value) -> delbert_pki::authn::Proof {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        delbert_pki::authn::prove(&self.key_pem, kind, "proxy", &self.site, body, now).unwrap()
    }

    /// `Authorization: Delbert-Proxy ...` header value for `kind` and `body`.
    pub fn header(&self, kind: &str, body: &Value) -> String {
        use base64::Engine as _;
        let v = json!({ "site": self.site, "proof": self.proof(kind, body) });
        format!("Delbert-Proxy {}", base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&v).unwrap()))
    }
}

/// Enrolls an agent through the proxy's HTTPS relay endpoint of the Core; returns the agent's key.
pub async fn enroll_agent_via(admin: &Client, proxy: &EnrolledProxy, tenant: &str, agent: &str) -> Enrolled {
    let (status, key) = admin.call("POST", &format!("/v1/tenants/{tenant}/enrollment-keys"), Some(json!({ "groups": ["web"] }))).await;
    assert_eq!(status, StatusCode::CREATED, "{key}");
    let (key_pem, csr_pem) = delbert_pki::new_identity(agent).unwrap();
    let age = age::x25519::Identity::generate();
    let body = json!({ "psk": key["key"], "agent_name": agent, "csr_pem": csr_pem, "enc_public_key": age.to_public().to_string() });
    let (status, resp) = admin_raw_json(admin, "POST", "/v1/proxy/enroll-agent", vec![("authorization", proxy.header("enroll-agent", &body))], &body).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    Enrolled { cert_pem: resp["cert_pem"].as_str().unwrap().to_owned(), key_pem, age }
}

/// JSON request with custom headers and no session token.
pub async fn admin_raw_json(c: &Client, method: &'static str, uri: &str, headers: Vec<(&'static str, String)>, body: &Value) -> (StatusCode, Value) {
    let anon = Client { token: None, ..c.clone() };
    let mut headers = headers;
    headers.push(("content-type", "application/json".into()));
    let (status, bytes) = anon.raw(method, uri.to_string(), headers, serde_json::to_vec(body).unwrap()).await;
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}
