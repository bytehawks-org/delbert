//! Global artifacts (inherited by tenants) and layered template variables.

mod common;

use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use common::{Client, admin_client, enroll_agent, signing_key, state};
use delbert_core::compile::Strategy;
use delbert_wire::{EffectivePolicy, Expect, Verifier};
use serde_json::{Value, json};
use sqlx::PgPool;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn verify(token: &str, agent: &str) -> EffectivePolicy {
    let mut v = Verifier::default();
    v.add_key("k1", &URL_SAFE_NO_PAD.encode(signing_key().verifying_key().to_bytes())).unwrap();
    v.verify(token, &Expect { tenant: "acme", agent, now: now() }, |_| None).unwrap()
}

fn policy(name: &str, spec: &str, resources: &str) -> Value {
    json!({ "yaml": format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: {name}, tenant: acme }}\nspec:\n{spec}  resources:\n{resources}") })
}

const TEMPLATE: &str = "    - id: app\n      template: { src: \"artifact://app.j2\", dest: /etc/app.conf }\n";

async fn put_artifact(c: &Client, uri: &str, body: &[u8]) -> (StatusCode, Value) {
    let (s, b) = c.raw("PUT", uri.to_string(), vec![("content-type", "application/octet-stream".into())], body.to_vec()).await;
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

#[sqlx::test]
async fn global_artifacts_are_inherited_overridden_and_served(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let a1 = enroll_agent(&admin, "acme", "agent-1").await;
    admin.call("POST", "/v1/users", Some(json!({ "username": "olivia", "password": "a-long-enough-password", "assignments": [{ "role": "tenant-admin", "tenant": "acme" }] }))).await;
    let tenant_admin = admin.as_user("olivia", "a-long-enough-password").await;

    // Only a global grant manages the platform's files; a tenant administrator cannot.
    assert_eq!(put_artifact(&tenant_admin, "/v1/globals/artifacts/app.j2", b"x").await.0, StatusCode::FORBIDDEN);
    assert_eq!(tenant_admin.call("GET", "/v1/globals/artifacts", None).await.0, StatusCode::FORBIDDEN);
    let (s, g1) = put_artifact(&admin, "/v1/globals/artifacts/app.j2", b"global {{ vars.name }}\n").await;
    assert_eq!((s, g1["version"].clone(), g1["origin"].clone()), (StatusCode::CREATED, json!(1), json!("global")));
    assert_eq!(put_artifact(&admin, "/v1/globals/artifacts/app.j2", b"global {{ vars.name }}\n").await.0, StatusCode::OK);

    // The tenant sees it, marked as inherited, and its policies can use it without uploading anything.
    let (_, list) = tenant_admin.call("GET", "/v1/tenants/acme/artifacts", None).await;
    assert_eq!((list[0]["name"].clone(), list[0]["origin"].clone(), list[0]["shadows_global"].clone()), (json!("app.j2"), json!("global"), json!(false)));
    admin.call("POST", "/v1/tenants/acme/policies", Some(policy("p", "", TEMPLATE))).await;
    let (_, issued) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(issued["conflicts"], json!([]));
    let sha_global = g1["sha256"].as_str().unwrap().to_owned();
    assert_eq!(verify(issued["token"].as_str().unwrap(), "agent-1").artifacts["app.j2"].sha256, sha_global);

    // The agent downloads the global content by hash through its own tenant's endpoint.
    let anon = Client { token: None, ..admin.clone() };
    let download = |sha: &str| {
        let proof = delbert_pki::authn::prove(&a1.key_pem, "artifact", "acme", "agent-1", &Value::String(format!("app.j2:{sha}")), now()).unwrap();
        let header = format!("Delbert-Agent {}", STANDARD.encode(serde_json::to_vec(&proof).unwrap()));
        anon.raw("GET", format!("/v1/agent/acme/agent-1/artifacts/app.j2?sha256={sha}"), vec![("authorization", header)], vec![])
    };
    assert_eq!(download(&sha_global).await, (StatusCode::OK, b"global {{ vars.name }}\n".to_vec()));

    // A change of the global file moves every agent to a new version.
    let (s, g2) = put_artifact(&admin, "/v1/globals/artifacts/app.j2", b"global v2\n").await;
    assert_eq!((s, g2["version"].clone()), (StatusCode::CREATED, json!(2)));
    let (_, moved) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(moved["version"].as_i64().unwrap(), issued["version"].as_i64().unwrap() + 1);

    // The tenant overrides it by uploading its own file with the same name; its policies now pin that one.
    let (s, own) = put_artifact(&tenant_admin, "/v1/tenants/acme/artifacts/app.j2", b"tenant copy\n").await;
    assert_eq!(s, StatusCode::CREATED);
    let (_, overridden) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(verify(overridden["token"].as_str().unwrap(), "agent-1").artifacts["app.j2"].sha256, own["sha256"]);
    let (_, list) = admin.call("GET", "/v1/tenants/acme/artifacts", None).await;
    assert_eq!((list[0]["origin"].clone(), list[0]["shadows_global"].clone()), (json!("tenant"), json!(true)));

    let (_, trail) = admin.call("GET", "/v1/audit?action=artifact.global.upload", None).await;
    assert_eq!(trail["events"].as_array().unwrap().len(), 2);
    assert_eq!(admin.call("GET", "/v1/audit/verify", None).await.1["first_bad"], Value::Null);
}

#[sqlx::test]
async fn variables_resolve_by_layer_constants_hold_and_the_preview_renders(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    enroll_agent(&admin, "acme", "agent-1").await;
    enroll_agent(&admin, "acme", "agent-2").await;
    admin.call("PUT", "/v1/tenants/acme/secrets/db", Some(json!({ "value": "hunter2" }))).await;
    put_artifact(&admin, "/v1/tenants/acme/artifacts/app.j2", b"env={{ vars.env }} port={{ vars.port }} region={{ vars.region }} pw={{ secrets.db }} host={{ facts.hostname }}\n").await;
    let spec = "  secrets: [db]\n  vars: { port: 80, region: us }\n";
    assert_eq!(admin.call("POST", "/v1/tenants/acme/policies", Some(policy("p", spec, TEMPLATE))).await.0, StatusCode::CREATED);

    let var = |scope: &str, target: &str, name: &str| {
        let q = if scope == "tenant" { String::new() } else { format!("?scope={scope}&target={target}") };
        format!("/v1/tenants/acme/variables/{name}{q}")
    };
    // Layers: global < tenant < group < agent.
    assert_eq!(admin.call("PUT", "/v1/globals/variables/env", Some(json!({ "value": "prod" }))).await.0, StatusCode::CREATED);
    assert_eq!(admin.call("PUT", "/v1/globals/variables/env", Some(json!({ "value": "prod" }))).await.0, StatusCode::OK);
    assert_eq!(admin.call("PUT", &var("tenant", "", "port"), Some(json!({ "value": 8080 }))).await.0, StatusCode::CREATED);
    assert_eq!(admin.call("PUT", &var("group", "web", "port"), Some(json!({ "value": 9090 }))).await.0, StatusCode::CREATED);
    assert_eq!(admin.call("PUT", &var("agent", "agent-2", "env"), Some(json!({ "value": "canary" }))).await.0, StatusCode::CREATED);
    assert_eq!(admin.call("PUT", &var("agent", "ghost", "env"), Some(json!({ "value": "x" }))).await.0, StatusCode::NOT_FOUND);
    assert_eq!(admin.call("PUT", &var("tenant", "", "bad-name"), Some(json!({ "value": 1 }))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(admin.call("PUT", &var("tenant", "", "nothing"), Some(json!({ "value": null }))).await.0, StatusCode::UNPROCESSABLE_ENTITY);

    let (_, one) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/variables", None).await;
    let find = |v: &Value, name: &str| v["variables"].as_array().unwrap().iter().find(|x| x["name"] == name).unwrap().clone();
    assert_eq!((find(&one, "env")["value"].clone(), find(&one, "env")["source"].clone()), (json!("prod"), json!("global")));
    assert_eq!((find(&one, "port")["value"].clone(), find(&one, "port")["source"].clone(), find(&one, "port")["overrides"].clone()), (json!(9090), json!("group:web"), json!(["tenant"])));
    let (_, two) = admin.call("GET", "/v1/tenants/acme/agents/agent-2/variables", None).await;
    assert_eq!((find(&two, "env")["value"].clone(), find(&two, "env")["source"].clone()), (json!("canary"), json!("agent:agent-2")));

    // The signed policy carries the resolved values: they beat the policy's own defaults, per agent.
    let (_, e1) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    let (_, e2) = admin.call("GET", "/v1/tenants/acme/agents/agent-2/effective", None).await;
    let (v1, v2) = (verify(e1["token"].as_str().unwrap(), "agent-1").vars, verify(e2["token"].as_str().unwrap(), "agent-2").vars);
    assert_eq!((v1["env"].clone(), v1["port"].clone(), v1["region"].clone()), (json!("prod"), json!(9090), json!("us")));
    assert_eq!(v2["env"], "canary");

    // Preview: secrets masked, host facts as placeholders, undefined variables reported.
    let (s, prev) = admin.call("GET", "/v1/tenants/acme/agents/agent-2/render", None).await;
    assert_eq!(s, StatusCode::OK, "{prev}");
    assert_eq!(prev["templates"][0]["output"], "env=canary port=9090 region=us pw=******** host=<hostname>\n");
    assert!(!prev.to_string().contains("hunter2"));
    admin.call("DELETE", &var("group", "web", "port"), None).await;
    admin.call("DELETE", "/v1/tenants/acme/variables/port", None).await;
    admin.call("DELETE", &var("agent", "agent-2", "env"), None).await;
    admin.call("DELETE", "/v1/globals/variables/env", None).await;
    let (_, bare) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/render", None).await;
    assert!(bare["templates"][0]["output"].is_null() && bare["templates"][0]["error"].as_str().unwrap().contains("env"), "{bare}");

    // A constant: nothing below it changes the value, and trying is refused early.
    assert_eq!(admin.call("PUT", "/v1/globals/variables/region", Some(json!({ "value": "eu", "locked": true }))).await.0, StatusCode::CREATED);
    assert_eq!(admin.call("PUT", &var("tenant", "", "region"), Some(json!({ "value": "ap" }))).await.0, StatusCode::CONFLICT);
    let (_, locked) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(verify(locked["token"].as_str().unwrap(), "agent-1").vars["region"], "eu");
    assert!(locked["conflicts"].to_string().contains("constant overrides the policy"), "{locked}");

    // Tenant scope: a tenant administrator edits the tenant's layers, never the platform's.
    admin.call("POST", "/v1/users", Some(json!({ "username": "olivia", "password": "a-long-enough-password", "assignments": [{ "role": "tenant-admin", "tenant": "acme" }] }))).await;
    let tenant_admin = admin.as_user("olivia", "a-long-enough-password").await;
    assert_eq!(tenant_admin.call("PUT", &var("tenant", "", "owner"), Some(json!({ "value": "ops" }))).await.0, StatusCode::CREATED);
    assert_eq!(tenant_admin.call("PUT", "/v1/globals/variables/owner", Some(json!({ "value": "x" }))).await.0, StatusCode::FORBIDDEN);
    let (_, all) = tenant_admin.call("GET", "/v1/tenants/acme/variables", None).await;
    assert!(all.as_array().unwrap().iter().any(|v| v["scope"] == "global" && v["name"] == "region" && v["locked"] == true));

    // The audit trail records changes by hash, never the value.
    let (_, trail) = admin.call("GET", "/v1/audit?action=variable.*", None).await;
    assert!(!trail.to_string().contains("canary") && trail.to_string().contains("value_sha256"));
    assert_eq!(admin.call("GET", "/v1/audit/verify", None).await.1["first_bad"], Value::Null);
}
