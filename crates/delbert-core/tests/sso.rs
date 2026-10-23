//! Single sign-on against a mock OpenID Connect provider (ES256 ID tokens).

mod common;

use std::{collections::HashMap, sync::{Arc, Mutex}};

use axum::{
    Form, Json, Router,
    extract::State,
    http::{Request, StatusCode as S, header},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use common::{Client, admin_client, state};
use delbert_core::compile::Strategy;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

struct Idp {
    key: SigningKey,
    issuer: String,
    /// code -> (challenge, claims to put in the ID token)
    codes: Mutex<HashMap<String, (String, Value)>>,
}

impl Idp {
    /// Pretend the user logged in at the IdP: returns the authorization code for a request the Core redirected to.
    fn authorize(&self, location: &str, claims: Value) -> String {
        let q: HashMap<String, String> = url_query(location);
        let code = format!("code-{}", self.codes.lock().unwrap().len());
        let mut claims = claims;
        claims["nonce"] = json!(q["nonce"]);
        self.codes.lock().unwrap().insert(code.clone(), (q["code_challenge"].clone(), claims));
        code
    }
}

fn url_query(location: &str) -> HashMap<String, String> {
    location.split_once('?').map(|(_, q)| q).unwrap_or("").split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_owned(), percent(v))).collect()
}

fn percent(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() + 0 && i + 2 <= b.len() - 1 => {
                out.push(u8::from_str_radix(&v[i + 1..i + 3], 16).unwrap_or(b'?'));
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn discovery(State(idp): State<Arc<Idp>>) -> Json<Value> {
    let i = &idp.issuer;
    Json(json!({
        "issuer": i, "authorization_endpoint": format!("{i}/authorize"), "token_endpoint": format!("{i}/token"), "jwks_uri": format!("{i}/jwks"),
        "response_types_supported": ["code"], "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["openid", "profile", "email"], "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
    }))
}

async fn jwks(State(idp): State<Arc<Idp>>) -> Json<Value> {
    let point = idp.key.verifying_key().to_encoded_point(false);
    Json(json!({ "keys": [{ "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1", "x": B64.encode(point.x().unwrap()), "y": B64.encode(point.y().unwrap()) }] }))
}

async fn token(State(idp): State<Arc<Idp>>, Form(f): Form<HashMap<String, String>>) -> Result<Json<Value>, (S, Json<Value>)> {
    let bad = |m: &str| (S::BAD_REQUEST, Json(json!({ "error": "invalid_grant", "error_description": m })));
    let (challenge, claims) = idp.codes.lock().unwrap().remove(f.get("code").map(String::as_str).unwrap_or("")).ok_or_else(|| bad("unknown code"))?;
    // PKCE: the verifier must hash to the challenge sent in the authorization request.
    let verifier = f.get("code_verifier").ok_or_else(|| bad("no verifier"))?;
    if B64.encode(Sha256::digest(verifier.as_bytes())) != challenge {
        return Err(bad("pkce mismatch"));
    }
    let header = B64.encode(json!({ "alg": "ES256", "typ": "JWT", "kid": "k1" }).to_string());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut c = json!({ "iss": idp.issuer, "aud": "delbert", "iat": now, "exp": now + 300 });
    for (k, v) in claims.as_object().unwrap() {
        c[k] = v.clone();
    }
    let payload = B64.encode(c.to_string());
    let sig: Signature = idp.key.sign(format!("{header}.{payload}").as_bytes());
    Ok(Json(json!({ "access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": format!("{header}.{payload}.{}", B64.encode(sig.to_bytes())) })))
}

async fn start_idp() -> Arc<Idp> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp = Arc::new(Idp { key: SigningKey::random(&mut rand_core::OsRng), issuer: format!("http://{}", listener.local_addr().unwrap()), codes: Mutex::new(HashMap::new()) });
    let app = Router::new().route("/.well-known/openid-configuration", get(discovery)).route("/jwks", get(jwks)).route("/token", post(token)).with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

async fn location(c: &Client, uri: &str) -> (S, String) {
    let resp = c.app.clone().oneshot(Request::builder().uri(uri).body(axum::body::Body::empty()).unwrap()).await.unwrap();
    (resp.status(), resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned())
}

/// A full browser login: returns where the Core finally redirects.
async fn browser_login(c: &Client, idp: &Idp, claims: Value) -> String {
    let (s, to_idp) = location(c, "/v1/auth/sso/mock/login").await;
    assert_eq!(s, S::SEE_OTHER, "{to_idp}");
    assert!(to_idp.starts_with(&idp.issuer) && to_idp.contains("code_challenge_method=S256"));
    let code = idp.authorize(&to_idp, claims);
    let state = url_query(&to_idp)["state"].clone();
    let (s, back) = location(c, &format!("/v1/auth/sso/mock/callback?code={code}&state={state}")).await;
    assert_eq!(s, S::SEE_OTHER);
    back
}

#[sqlx::test]
async fn oidc_login_maps_groups_and_resists_abuse(pool: PgPool) {
    let idp = start_idp().await;
    let mut st = state(pool.clone(), vec![Strategy::Error], None);
    st.auth.cookie_secure = false; // the mock IdP speaks plain HTTP
    st.auth.public_url = Some("http://core.test".into());
    st.auth.ui_url = Some("http://ui.test/".into());
    let admin = admin_client(st).await;
    let anon = Client { token: None, ..admin.clone() };
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    admin.call("POST", "/v1/users", Some(json!({ "username": "bob", "password": "a-long-enough-password", "assignments": [] }))).await;

    // Administration: bad mappings are refused; a good provider shows its redirect URI and no secret.
    let body = |mappings: Value| json!({ "name": "mock", "display_name": "Mock IdP", "issuer": idp.issuer, "client_id": "delbert", "client_secret": "s3cret", "mappings": mappings });
    assert_eq!(admin.call("POST", "/v1/sso/providers", Some(body(json!([{ "group": "ops", "role": "operator" }])))).await.0, S::UNPROCESSABLE_ENTITY); // tenant role, no tenant
    assert_eq!(admin.call("POST", "/v1/sso/providers", Some(body(json!([{ "group": "ops", "role": "nope" }])))).await.0, S::UNPROCESSABLE_ENTITY);
    assert_eq!(admin.call("POST", "/v1/sso/providers", Some(json!({ "name": "x", "display_name": "x", "issuer": "ftp://idp.example.com", "client_id": "c" }))).await.0, S::UNPROCESSABLE_ENTITY);
    let mappings = json!([{ "group": "ops", "role": "operator", "tenant": "acme" }, { "group": "audit", "role": "auditor" }]);
    let (s, p) = admin.call("POST", "/v1/sso/providers", Some(body(mappings.clone()))).await;
    assert_eq!(s, S::CREATED, "{p}");
    assert_eq!((p["has_client_secret"].clone(), p["redirect_uri"].clone()), (json!(true), json!("http://core.test/v1/auth/sso/mock/callback")));
    assert!(p.get("client_secret").is_none());
    let (_, t) = admin.call("POST", "/v1/sso/providers/mock/test", None).await;
    assert_eq!(t["ok"], true, "{t}");
    let (_, public) = anon.call("GET", "/v1/auth/sso/providers", None).await;
    assert_eq!(public, json!([{ "name": "mock", "display_name": "Mock IdP" }]));

    // A login: PKCE, nonce and signature are checked by the Core; the browser gets a one-time code.
    let alice = json!({ "sub": "u-1", "preferred_username": "alice", "email": "alice@example.com", "groups": ["ops", "other"] });
    let back = browser_login(&anon, &idp, alice.clone()).await;
    assert!(back.starts_with("http://ui.test/?code="), "{back}");
    let code = back.split("code=").nth(1).unwrap().to_owned();
    let (s, login) = anon.call("POST", "/v1/auth/sso/exchange", Some(json!({ "code": code }))).await;
    assert_eq!(s, S::OK, "{login}");
    assert_eq!(anon.call("POST", "/v1/auth/sso/exchange", Some(json!({ "code": code }))).await.0, S::UNAUTHORIZED); // single use
    let alice_c = Client { token: login["token"].as_str().map(str::to_owned), ..admin.clone() };
    let (_, me) = alice_c.call("GET", "/v1/me", None).await;
    assert_eq!(me["username"], "alice");
    assert_eq!(me["assignments"], json!([{ "role": "operator", "tenant": "acme" }]));
    assert_eq!(alice_c.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "a1" }))).await.0, S::CREATED);
    assert_eq!(alice_c.call("GET", "/v1/users", None).await.0, S::FORBIDDEN);

    // Groups follow the identity provider at every login; manual roles are not touched.
    admin.call("PUT", "/v1/users/alice", Some(json!({ "assignments": [{ "role": "viewer" }] }))).await;
    let back = browser_login(&anon, &idp, json!({ "sub": "u-1", "preferred_username": "alice", "groups": ["audit"] })).await;
    assert!(back.contains("code="));
    let (_, users) = admin.call("GET", "/v1/users", None).await;
    let roles: Vec<(String, Option<String>)> = users.as_array().unwrap().iter().find(|u| u["username"] == "alice").unwrap()["assignments"].as_array().unwrap().iter().map(|a| (a["role"].as_str().unwrap().to_owned(), a["tenant"].as_str().map(str::to_owned))).collect();
    assert_eq!(roles, vec![("auditor".to_owned(), None), ("viewer".to_owned(), None)]);

    // Refusals: no mapped group (and the old roles go), a local name, a replayed callback, a forged nonce.
    let back = browser_login(&anon, &idp, json!({ "sub": "u-1", "preferred_username": "alice", "groups": ["nobody"] })).await;
    assert!(back.contains("sso_error="), "{back}");
    let (_, users) = admin.call("GET", "/v1/users", None).await;
    assert_eq!(users.as_array().unwrap().iter().find(|u| u["username"] == "alice").unwrap()["assignments"], json!([{ "role": "viewer", "tenant": null }]));
    let back = browser_login(&anon, &idp, json!({ "sub": "u-9", "preferred_username": "bob", "groups": ["ops"] })).await;
    assert!(back.contains("sso_error="), "local account must not be taken over: {back}");
    assert_eq!(admin.call("GET", "/v1/me", None).await.0, S::OK);
    let (_, to_idp) = location(&anon, "/v1/auth/sso/mock/login").await;
    let code = idp.authorize(&to_idp, json!({ "sub": "u-2", "preferred_username": "mallory", "groups": ["ops"] }));
    let state = url_query(&to_idp)["state"].clone();
    assert!(location(&anon, &format!("/v1/auth/sso/mock/callback?code={code}&state={state}")).await.1.contains("code="));
    assert!(location(&anon, &format!("/v1/auth/sso/mock/callback?code={code}&state={state}")).await.1.contains("sso_error=")); // state is single use
    assert!(location(&anon, "/v1/auth/sso/mock/callback?code=x&state=forged").await.1.contains("sso_error="));
    let (_, to_idp) = location(&anon, "/v1/auth/sso/mock/login").await;
    let code = idp.authorize(&to_idp, json!({ "sub": "u-3", "preferred_username": "eve", "groups": ["ops"], "nonce": "not-the-one" }));
    let state = url_query(&to_idp)["state"].clone();
    let mut codes = idp.codes.lock().unwrap();
    codes.get_mut(&code).unwrap().1["nonce"] = json!("not-the-one");
    drop(codes);
    assert!(location(&anon, &format!("/v1/auth/sso/mock/callback?code={code}&state={state}")).await.1.contains("sso_error="), "wrong nonce must be rejected");
    let (_, users) = admin.call("GET", "/v1/users", None).await;
    assert!(users.as_array().unwrap().iter().all(|u| u["username"] != "eve"));

    // A disabled provider offers nothing; the audit trail has the story and stays intact.
    admin.call("PUT", "/v1/sso/providers/mock", Some(json!({ "display_name": "Mock IdP", "issuer": idp.issuer, "client_id": "delbert", "enabled": false, "mappings": mappings }))).await;
    assert_eq!(location(&anon, "/v1/auth/sso/mock/login").await.0, S::NOT_FOUND);
    let (_, ev) = admin.call("GET", "/v1/audit?action=auth.sso", None).await;
    assert!(ev["events"].as_array().unwrap().len() >= 4);
    assert_eq!(admin.call("GET", "/v1/audit/verify", None).await.1["first_bad"], Value::Null);
}
