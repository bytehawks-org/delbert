//! Authentication hardening: MFA, throttling, cookie sessions with CSRF, idle timeout.

mod common;

use axum::http::StatusCode as S;
use common::{ADMIN_PASSWORD, Client, admin_client, state};
use delbert_core::{api::MfaPolicy, compile::Strategy, totp};
use serde_json::{Value, json};
use sqlx::PgPool;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

async fn enroll(c: &Client) -> (Vec<u8>, Vec<String>) {
    let (s, e) = c.call("POST", "/v1/me/mfa/enroll", None).await;
    assert_eq!(s, S::OK, "{e}");
    let secret = data_encoding::BASE32_NOPAD.decode(e["secret"].as_str().unwrap().as_bytes()).unwrap();
    assert!(e["otpauth_uri"].as_str().unwrap().starts_with("otpauth://totp/Delbert:"));
    assert_eq!(c.call("POST", "/v1/me/mfa/confirm", Some(json!({ "code": "000000" }))).await.0, S::UNAUTHORIZED);
    let (s, r) = c.call("POST", "/v1/me/mfa/confirm", Some(json!({ "code": totp::generate(&secret, now()) }))).await;
    assert_eq!(s, S::OK, "{r}");
    let codes = r["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_owned()).collect::<Vec<_>>();
    assert_eq!(codes.len(), 10);
    (secret, codes)
}

#[sqlx::test]
async fn mfa_totp_recovery_and_reset(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    let (secret, codes) = enroll(&admin).await;
    assert_eq!(admin.call("POST", "/v1/me/mfa/enroll", None).await.0, S::CONFLICT);
    assert_eq!(admin.call("GET", "/v1/me", None).await.1["mfa_enabled"], true);

    // Password alone gives a pending session that opens nothing.
    let (s, l) = admin.login("admin", ADMIN_PASSWORD).await;
    assert_eq!((s, l["mfa_required"].clone()), (S::OK, json!(true)));
    let pending = Client { token: l["token"].as_str().map(str::to_owned), ..admin.clone() };
    assert_eq!(pending.call("GET", "/v1/tenants", None).await.0, S::UNAUTHORIZED);
    assert_eq!(admin.call("POST", "/v1/auth/mfa", Some(json!({ "code": "123456" }))).await.0, S::CONFLICT); // a full session has nothing pending
    assert_eq!(pending.call("POST", "/v1/auth/mfa", Some(json!({ "code": "000000" }))).await.0, S::UNAUTHORIZED);
    // The code of the confirmation step cannot be replayed; the next step's code works.
    assert_eq!(pending.call("POST", "/v1/auth/mfa", Some(json!({ "code": totp::generate(&secret, now()) }))).await.0, S::UNAUTHORIZED);
    assert_eq!(pending.call("POST", "/v1/auth/mfa", Some(json!({ "code": totp::generate(&secret, now() + 30) }))).await.0, S::OK);
    assert_eq!(pending.call("GET", "/v1/tenants", None).await.0, S::OK);

    // Recovery codes work once.
    let recover = |code: String| {
        let admin = admin.clone();
        async move {
            let (_, l) = admin.login("admin", ADMIN_PASSWORD).await;
            let p = Client { token: l["token"].as_str().map(str::to_owned), ..admin };
            p.call("POST", "/v1/auth/mfa", Some(json!({ "code": code }))).await.0
        }
    };
    assert_eq!(recover(codes[0].clone()).await, S::OK);
    assert_eq!(recover(codes[0].clone()).await, S::UNAUTHORIZED);
    assert_eq!(recover(codes[1].to_uppercase()).await, S::OK);

    // An administrator can reset the factor (and the user's sessions end).
    assert_eq!(admin.call("POST", "/v1/users", Some(json!({ "username": "bob", "password": "a-long-enough-password", "assignments": [] }))).await.0, S::CREATED);
    let bob = admin.as_user("bob", "a-long-enough-password").await;
    enroll(&bob).await;
    assert_eq!(admin.call("DELETE", "/v1/users/bob/mfa", None).await.0, S::NO_CONTENT);
    assert_eq!(bob.call("GET", "/v1/me", None).await.0, S::UNAUTHORIZED);
    let (_, l) = admin.login("bob", "a-long-enough-password").await;
    assert_eq!(l["mfa_required"], false);
}

#[sqlx::test]
async fn failed_logins_are_throttled_per_user_and_address(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    assert_eq!(admin.call("POST", "/v1/users", Some(json!({ "username": "bob", "password": "a-long-enough-password", "assignments": [] }))).await.0, S::CREATED);
    for _ in 0..5 {
        assert_eq!(admin.login("admin", "wrong-password-123").await.0, S::UNAUTHORIZED);
    }
    // Even the right password is refused now, and unknown users are throttled the same way.
    assert_eq!(admin.login("admin", ADMIN_PASSWORD).await.0, S::TOO_MANY_REQUESTS);
    // Other accounts are not locked out by it.
    assert_eq!(admin.login("bob", "a-long-enough-password").await.0, S::OK);
    for _ in 0..5 {
        admin.login("ghost", "whatever-password").await;
    }
    assert_eq!(admin.login("ghost", "whatever-password").await.0, S::TOO_MANY_REQUESTS);
}

#[sqlx::test]
async fn cookie_sessions_need_the_csrf_token_and_expire_when_idle(pool: PgPool) {
    let admin = admin_client(state(pool.clone(), vec![Strategy::Error], None)).await;
    let (s, l) = admin.login("admin", ADMIN_PASSWORD).await;
    assert_eq!(s, S::OK);
    assert!(l["csrf_token"].is_null());
    let anon = Client { token: None, ..admin.clone() };
    let (_, body) = anon.call("POST", "/v1/auth/login", Some(json!({ "username": "admin", "password": ADMIN_PASSWORD, "cookie": true }))).await;
    let (token, csrf) = (body["token"].as_str().unwrap().to_owned(), body["csrf_token"].as_str().unwrap().to_owned());
    let cookie = ("cookie", format!("delbert_session={token}"));
    let new_tenant = json!({ "name": "acme" }).to_string().into_bytes();
    let json_ct = ("content-type", "application/json".to_string());

    assert_eq!(anon.raw("GET", "/v1/tenants", vec![cookie.clone()], vec![]).await.0, S::OK);
    assert_eq!(anon.raw("POST", "/v1/tenants", vec![cookie.clone(), json_ct.clone()], new_tenant.clone()).await.0, S::FORBIDDEN);
    assert_eq!(anon.raw("POST", "/v1/tenants", vec![cookie.clone(), json_ct.clone(), ("x-csrf-token", "wrong".into())], new_tenant.clone()).await.0, S::FORBIDDEN);
    assert_eq!(anon.raw("POST", "/v1/tenants", vec![cookie.clone(), json_ct.clone(), ("x-csrf-token", csrf)], new_tenant).await.0, S::CREATED);
    // Bearer clients do not need the CSRF token; a cookie must not be accepted without a session behind it.
    assert_eq!(admin.call("GET", "/v1/tenants", None).await.0, S::OK);
    assert_eq!(anon.raw("GET", "/v1/tenants", vec![("cookie", "delbert_session=nope".into())], vec![]).await.0, S::UNAUTHORIZED);

    // Sessions are listed and revocable; idle ones end.
    let (_, list) = admin.call("GET", "/v1/me/sessions", None).await;
    assert!(list.as_array().unwrap().iter().any(|x| x["current"] == true));
    sqlx::query("UPDATE sessions SET last_seen = now() - interval '2 hours'").execute(&pool).await.unwrap();
    assert_eq!(admin.call("GET", "/v1/me", None).await.0, S::UNAUTHORIZED);
}

#[sqlx::test]
async fn mfa_can_be_made_mandatory(pool: PgPool) {
    let mut st = state(pool, vec![Strategy::Error], None);
    st.auth.mfa = MfaPolicy::Admins;
    let admin = admin_client(st).await;
    // The administrator can only reach the profile and the enrolment until a factor exists.
    assert_eq!(admin.call("GET", "/v1/tenants", None).await.0, S::FORBIDDEN);
    assert_eq!(admin.call("GET", "/v1/me", None).await.0, S::OK);
    let (secret, _) = enroll(&admin).await;
    assert_eq!(admin.call("GET", "/v1/tenants", None).await.0, S::OK);
    // And cannot switch it off again.
    let (s, b) = admin.call("POST", "/v1/me/mfa/disable", Some(json!({ "password": ADMIN_PASSWORD, "code": totp::generate(&secret, now() + 30) }))).await;
    assert_eq!(s, S::CONFLICT, "{b}");
    let _: Value = b;
}
