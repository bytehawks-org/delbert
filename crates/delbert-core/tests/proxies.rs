//! Proxy administration, enrollment, relay over NATS, allow-list and forwarded reports.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{Client, admin_client, admin_raw_json, enroll_agent_via, enroll_proxy, state};
use delbert_core::{
    bus::{self, Bus},
    bus_auth::{self, proxy_hub_permissions},
    compile::Strategy,
};
use serde_json::{Value, json};
use sqlx::PgPool;

/// The Core subscribes in the queue group `core`: tests sharing one NATS server would steal each other's messages.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[sqlx::test]
async fn proxy_lifecycle_enrollment_and_agents_through_a_proxy(pool: PgPool) {
    let st = state(pool.clone(), vec![Strategy::Error], None);
    let ca = st.pki.clone().unwrap();
    let admin = admin_client(st).await;
    let anon = Client { token: None, ..admin.clone() };
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;

    // Validation and permissions.
    assert_eq!(admin.call("POST", "/v1/proxies", Some(json!({ "name": "a.b", "dns_names": ["x"] }))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(admin.call("POST", "/v1/proxies", Some(json!({ "name": "branch", "dns_names": [] }))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    admin.call("POST", "/v1/users", Some(json!({ "username": "olivia", "password": "a-long-enough-password", "assignments": [{ "role": "viewer" }] }))).await;
    let operator = admin.as_user("olivia", "a-long-enough-password").await;
    assert_eq!(operator.call("POST", "/v1/proxies", Some(json!({ "name": "branch", "dns_names": ["x"] }))).await.0, StatusCode::FORBIDDEN);

    // Create, enroll once, never twice.
    let (s, created) = admin.call("POST", "/v1/proxies", Some(json!({ "name": "branch", "dns_names": ["branch.example.com", "nats.branch.example.com"] }))).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(created["key"].as_str().unwrap().starts_with("dlp_"));
    assert_eq!(admin.call("POST", "/v1/proxies", Some(json!({ "name": "branch", "dns_names": ["x"] }))).await.0, StatusCode::CONFLICT);
    let (key_pem, csr) = delbert_pki::new_identity("branch").unwrap();
    let enroll = |psk: Value, name: &str, csr: &str| anon.call("POST", "/v1/proxies/enroll", Some(json!({ "name": name, "psk": psk, "csr_pem": csr })));
    assert_eq!(enroll(json!("dlp_wrong"), "branch", &csr).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(enroll(created["key"].clone(), "branch", "garbage").await.0, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, body) = enroll(created["key"].clone(), "branch", &csr).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(enroll(created["key"].clone(), "branch", &csr).await.0, StatusCode::UNAUTHORIZED, "the key is single use");
    let cert = body["cert_pem"].as_str().unwrap();

    // The certificate carries the proxy identity and both DNS names, for client AND server use.
    assert_eq!(delbert_pki::identity_from_pem(cert).unwrap(), delbert_pki::CertIdentity::Component { name: "proxy:branch".into() });
    let der = x509_parser::pem::parse_x509_pem(cert.as_bytes()).unwrap().1.contents;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
    let eku = parsed.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.client_auth && eku.server_auth);
    let sans = parsed.subject_alternative_name().unwrap().unwrap().value.general_names.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(" ");
    assert!(sans.contains("branch.example.com") && sans.contains("nats.branch.example.com"), "{sans}");

    // The Core's callout accepts the proxy certificate with exactly the proxy permissions, nothing else.
    let (name, perms) = bus_auth::decide(&pool, cert).await.unwrap();
    assert_eq!((name.as_str(), perms), ("proxy:branch", proxy_hub_permissions("branch")));
    let (other_key, other_csr) = delbert_pki::new_identity("branch").unwrap();
    let impostor = ca.sign_proxy_csr(&other_csr, "branch", &["branch.example.com".into()], 1).unwrap();
    assert!(bus_auth::decide(&pool, &impostor.cert_pem).await.is_err(), "same name, other key");
    assert!(bus_auth::decide(&pool, &ca.sign_proxy_csr(&other_csr, "ghost", &["x".into()], 1).unwrap().cert_pem).await.is_err(), "unknown proxy");
    let _ = (key_pem, other_key);

    // Agents enrolled through the proxy are assigned to it; a bad or foreign proof is refused.
    let proxy = common::EnrolledProxy { site: "branch".into(), key_pem: delbert_pki::new_identity("x").unwrap().0, cert_pem: cert.into() };
    let (_, k) = admin.call("POST", "/v1/tenants/acme/enrollment-keys", Some(json!({}))).await;
    let (_, csr2) = delbert_pki::new_identity("agent-1").unwrap();
    let req = json!({ "psk": k["key"], "agent_name": "agent-1", "csr_pem": csr2, "enc_public_key": age::x25519::Identity::generate().to_public().to_string() });
    let (s, _) = admin_raw_json(&admin, "POST", "/v1/proxy/enroll-agent", vec![("authorization", proxy.header("enroll-agent", &req))], &req).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "proof made with a key that is not the proxy's");
    assert_eq!(admin_raw_json(&admin, "POST", "/v1/proxy/enroll-agent", vec![], &req).await.0, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn proxy_enrolls_agents_and_assignment_is_visible(pool: PgPool) {
    let admin = admin_client(state(pool.clone(), vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let branch = enroll_proxy(&admin, "branch").await;
    let a1 = enroll_agent_via(&admin, &branch, "acme", "agent-1").await;
    assert!(bus_auth::decide(&pool, &a1.cert_pem).await.is_ok());

    let (_, agents) = admin.call("GET", "/v1/tenants/acme/agents", None).await;
    assert_eq!(agents[0]["proxy"], "branch");
    let (_, list) = admin.call("GET", "/v1/proxies", None).await;
    assert_eq!((list[0]["name"].clone(), list[0]["enrolled"].clone(), list[0]["agents"].clone()), (json!("branch"), json!(true), json!(1)));

    // A proxy with agents cannot be deleted; without them it can.
    assert_eq!(admin.call("DELETE", "/v1/proxies/branch", None).await.0, StatusCode::CONFLICT);
    admin.call("DELETE", "/v1/tenants/acme/agents/agent-1", None).await;
    assert_eq!(admin.call("DELETE", "/v1/proxies/branch", None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(admin.call("DELETE", "/v1/proxies/branch", None).await.0, StatusCode::NOT_FOUND);
    assert!(bus_auth::decide(&pool, &branch.cert_pem).await.is_err(), "a deleted proxy is refused by the callout");
}

#[sqlx::test]
async fn relay_allow_list_reports_and_artifacts_over_nats(pool: PgPool) {
    let _serial = ONE_AT_A_TIME.lock().await;
    let Ok(url) = std::env::var("NATS_URL") else {
        eprintln!("NATS_URL not set: skipping");
        return;
    };
    let client = async_nats::connect(&url).await.expect("NATS reachable");
    let app_state = state(pool, vec![Strategy::Error], Some(Bus::from_client(client.clone())));
    bus::serve(app_state.clone()).await.unwrap();
    let admin = admin_client(app_state).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let branch = enroll_proxy(&admin, "branch").await;
    let rival = enroll_proxy(&admin, "rival").await;
    let a1 = enroll_agent_via(&admin, &branch, "acme", "agent-1").await;
    let direct = common::enroll_agent(&admin, "acme", "agent-2").await; // not served by any proxy
    let yaml = "apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: p, tenant: acme }\nspec:\n  resources:\n    - id: f\n      file: { path: /etc/f }\n";
    admin.call("POST", "/v1/tenants/acme/policies", Some(json!({ "yaml": yaml }))).await;

    let ask = |subject: String, payload: Value| {
        let client = client.clone();
        async move {
            let reply = tokio::time::timeout(Duration::from_secs(5), client.request(subject, payload.to_string().into())).await.unwrap().unwrap();
            serde_json::from_slice::<Value>(&reply.payload).unwrap()
        }
    };
    let relay = |p: &common::EnrolledProxy, inner: Value| {
        let payload = json!({ "proof": p.proof("relay", &inner), "inner": inner });
        ask(format!("delbert.proxy.{}.relay", p.site), payload)
    };
    let agent_proof = |key: &str, agent: &str| delbert_pki::authn::prove(key, "req", "acme", agent, &Value::Null, unix_now()).unwrap();

    // The proxy relays its agent's policy request; the agent's proof inside is what the Core checks.
    let ok = relay(&branch, json!({ "kind": "effective", "tenant": "acme", "agent": "agent-1", "payload": agent_proof(&a1.key_pem, "agent-1") })).await;
    assert!(ok["token"].is_string(), "{ok}");
    // A forged agent proof, another proxy, an agent nobody relays for, and a bad proxy proof are all refused.
    let forged = relay(&branch, json!({ "kind": "effective", "tenant": "acme", "agent": "agent-1", "payload": agent_proof(&direct.key_pem, "agent-1") })).await;
    assert_eq!(forged["error"], "unauthorized");
    let wrong_proxy = relay(&rival, json!({ "kind": "effective", "tenant": "acme", "agent": "agent-1", "payload": agent_proof(&a1.key_pem, "agent-1") })).await;
    assert_eq!(wrong_proxy["error"], "unauthorized");
    let unserved = relay(&branch, json!({ "kind": "effective", "tenant": "acme", "agent": "agent-2", "payload": agent_proof(&direct.key_pem, "agent-2") })).await;
    assert_eq!(unserved["error"], "unauthorized");
    let inner = json!({ "kind": "effective", "tenant": "acme", "agent": "agent-1", "payload": agent_proof(&a1.key_pem, "agent-1") });
    let bad_proof = ask("delbert.proxy.branch.relay".into(), json!({ "proof": rival.proof("relay", &inner), "inner": inner })).await;
    assert_eq!(bad_proof["error"], "unauthorized");

    // Renewal through the proxy rotates the agent's key just like a direct one.
    let (new_key, csr) = delbert_pki::new_identity("agent-1").unwrap();
    let body = json!({ "csr_pem": csr });
    let renew_proof = delbert_pki::authn::prove(&a1.key_pem, "renew", "acme", "agent-1", &body, unix_now()).unwrap();
    let renewed = relay(&branch, json!({ "kind": "renew", "tenant": "acme", "agent": "agent-1", "payload": { "proof": renew_proof, "csr_pem": csr } })).await;
    assert!(renewed["cert_pem"].is_string(), "{renewed}");

    // The allow-list contains exactly the proxy's agents, with their current and previous keys.
    let list = ask("delbert.proxy.branch.agents".into(), json!({ "proof": branch.proof("agents", &Value::Null) })).await;
    let agents = list["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!((agents[0]["tenant"].clone(), agents[0]["agent"].clone()), (json!("acme"), json!("agent-1")));
    assert!(agents[0]["previous_public_key"].is_string(), "{list}");
    assert_eq!(ask("delbert.proxy.branch.agents".into(), json!({ "proof": rival.proof("agents", &Value::Null) })).await["error"], "unauthorized");
    let rival_list = ask("delbert.proxy.rival.agents".into(), json!({ "proof": rival.proof("agents", &Value::Null) })).await;
    assert_eq!(rival_list["agents"], json!([]));

    // Reports forwarded in a batch: valid ones are stored (judged as of when the proxy received them),
    // forged, tampered, too old and foreign ones are dropped, and an older report never replaces a newer one.
    let report_at = unix_now() - 120; // the proxy received it two minutes ago; a direct report this old would be stale
    let report = json!({ "version": 4, "compliant": true, "at": report_at, "resources": [] });
    let proof_at = |key: &str, agent: &str, body: &Value, at: i64| delbert_pki::authn::prove(key, "report", "acme", agent, body, at).unwrap();
    let item = |key: &str, agent: &str, body: &Value, proof_ts: i64, received_at: i64| {
        json!({ "tenant": "acme", "agent": agent, "received_at": received_at, "envelope": { "proof": proof_at(key, agent, body, proof_ts), "report": body } })
    };
    let tampered_body = json!({ "version": 99, "compliant": true, "at": report_at, "resources": [] });
    let mut tampered = item(&a1.key_pem, "agent-1", &report, report_at, report_at);
    tampered["envelope"]["report"] = tampered_body;
    // A batch is a request: the Core answers how many reports it stored.
    let batch = |items: Vec<Value>| {
        let (client, proof) = (client.clone(), branch.proof("proxy-report", &json!({ "reports": items })));
        async move {
            let inner = json!({ "reports": items });
            let reply = client.request("delbert.proxy.branch.report", json!({ "proof": proof, "inner": inner }).to_string().into()).await.unwrap();
            Ok::<Value, ()>(serde_json::from_slice(&reply.payload).unwrap())
        }
    };
    let dropped = batch(vec![tampered, item(&direct.key_pem, "agent-1", &report, report_at, report_at), item(&a1.key_pem, "agent-1", &report, report_at - 30 * 86_400, report_at - 30 * 86_400)]).await.unwrap();
    assert_eq!(dropped["accepted"], 0, "{dropped}");
    tokio::time::sleep(Duration::from_millis(600)).await;
    let (_, agents) = admin.call("GET", "/v1/tenants/acme/agents", None).await;
    let agent1 = agents.as_array().unwrap().iter().find(|a| a["name"] == "agent-1").unwrap().clone();
    assert_eq!(agent1["compliant"], Value::Null, "nothing forged may be stored: {agent1}");

    let accepted = batch(vec![item(&a1.key_pem, "agent-1", &report, report_at, report_at)]).await.unwrap();
    assert_eq!(accepted["accepted"], 1);
    let mut stored = Value::Null;
    for _ in 0..30 {
        let (_, agents) = admin.call("GET", "/v1/tenants/acme/agents", None).await;
        stored = agents.as_array().unwrap().iter().find(|a| a["name"] == "agent-1").unwrap().clone();
        if stored["reported_version"] == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(stored["reported_version"], 4, "{stored}");
    // An older report arriving later (a queue flushed out of order) does not overwrite the newer one.
    let older = json!({ "version": 2, "compliant": false, "at": report_at - 60, "resources": [] });
    // (signed with the NEW key now: the old one was retired by the first proof above... both are accepted until then)
    let key_for_old = &a1.key_pem;
    assert_eq!(batch(vec![item(key_for_old, "agent-1", &older, report_at - 60, report_at - 60)]).await.unwrap()["accepted"], 1, "valid, but stale: acknowledged and ignored");
    tokio::time::sleep(Duration::from_millis(600)).await;
    let (_, agents) = admin.call("GET", "/v1/tenants/acme/agents", None).await;
    assert_eq!(agents.as_array().unwrap().iter().find(|a| a["name"] == "agent-1").unwrap()["reported_version"], 4);
    let _ = new_key;

    // Artifacts through the proxy's own endpoint of the Core.
    let sha = "ab".repeat(32);
    let (name_ok, body_ok) = (admin.raw("PUT", "/v1/tenants/acme/artifacts/db.j2", vec![("content-type", "application/octet-stream".into())], b"hello".to_vec()).await.0, ());
    assert_eq!(name_ok, StatusCode::CREATED);
    let _ = body_ok;
    let real = {
        let (_, list) = admin.call("GET", "/v1/tenants/acme/artifacts", None).await;
        list[0]["sha256"].as_str().unwrap().to_owned()
    };
    let fetch = |p: &common::EnrolledProxy, site_in_path: &str, tenant: &str, sha: &str| {
        let header = p.header("proxy-artifact", &Value::String(format!("{tenant}:db.j2:{sha}")));
        let anon = Client { token: None, ..admin.clone() };
        let uri = format!("/v1/proxy/{site_in_path}/artifacts/{tenant}/db.j2?sha256={sha}");
        async move { anon.raw("GET", uri, vec![("authorization", header)], vec![]).await }
    };
    let (s, content) = fetch(&branch, "branch", "acme", &real).await;
    assert_eq!((s, content), (StatusCode::OK, b"hello".to_vec()));
    assert_eq!(fetch(&branch, "branch", "acme", &sha).await.0, StatusCode::NOT_FOUND);
    assert_eq!(fetch(&rival, "branch", "acme", &real).await.0, StatusCode::UNAUTHORIZED, "proof from another proxy");
    assert_eq!(fetch(&branch, "rival", "acme", &real).await.0, StatusCode::UNAUTHORIZED, "path names another proxy");
    client.drain().await.ok(); // leave the queue group before the next test joins it
}

#[sqlx::test]
async fn proxy_renews_its_certificate_with_a_new_key(pool: PgPool) {
    let admin = admin_client(state(pool.clone(), vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let old = enroll_proxy(&admin, "branch").await;
    let anon = Client { token: None, ..admin.clone() };
    let renew = |site: &str, header: String, body: Value| {
        let anon = anon.clone();
        let uri = format!("/v1/proxies/{site}/renew");
        async move { admin_raw_json(&anon, "POST", &uri, vec![("authorization", header)], &body).await }
    };

    // Authenticated with the current key, for this proxy only, and bound to the request kind.
    let (new_key, csr) = delbert_pki::new_identity("branch").unwrap();
    let body = json!({ "csr_pem": csr });
    assert_eq!(renew("branch", "Delbert-Proxy bogus".into(), body.clone()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(renew("branch", old.header("proxy-artifact", &body), body.clone()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(renew("other", old.header("proxy-renew", &body), body.clone()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(renew("branch", old.header("proxy-renew", &json!({ "csr_pem": "garbage" })), json!({ "csr_pem": "garbage" })).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, renewed) = renew("branch", old.header("proxy-renew", &body), body.clone()).await;
    assert_eq!(s, StatusCode::OK, "{renewed}");
    let new_cert = renewed["cert_pem"].as_str().unwrap().to_owned();
    assert_eq!(delbert_pki::identity_from_pem(&new_cert).unwrap(), delbert_pki::CertIdentity::Component { name: "proxy:branch".into() });

    // Both certificates work for NATS until the new key has been used; then only the new one.
    assert!(bus_auth::decide(&pool, &old.cert_pem).await.is_ok());
    assert!(bus_auth::decide(&pool, &new_cert).await.is_ok());
    let new = common::EnrolledProxy { site: "branch".into(), key_pem: new_key, cert_pem: new_cert.clone() };
    let probe = format!("/v1/proxy/branch/artifacts/acme/x?sha256={}", "00".repeat(32));
    let (s, _) = admin_raw_json(&anon, "GET", &probe, vec![("authorization", new.header("proxy-artifact", &Value::String(format!("acme:x:{}", "00".repeat(32)))))], &Value::Null).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "authenticated with the new key (the artifact does not exist)");
    assert!(bus_auth::decide(&pool, &old.cert_pem).await.is_err(), "the old key is retired once the new one is seen");
    assert!(bus_auth::decide(&pool, &new_cert).await.is_ok());
    let (_, trail) = admin.call("GET", "/v1/audit?action=proxy.renew", None).await;
    assert_eq!(trail["events"].as_array().unwrap().len(), 1);
}

#[sqlx::test]
async fn event_batches_forwarded_by_a_proxy_are_stored_once_and_only_when_authentic(pool: PgPool) {
    let Ok(url) = std::env::var("NATS_URL") else {
        eprintln!("NATS_URL not set: skipping");
        return;
    };
    let _serial = ONE_AT_A_TIME.lock().await;
    let client = async_nats::connect(&url).await.expect("NATS reachable");
    let app_state = state(pool, vec![Strategy::Error], Some(Bus::from_client(client.clone())));
    bus::serve(app_state.clone()).await.unwrap();
    let admin = admin_client(app_state).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let branch = enroll_proxy(&admin, "branch").await;
    let rival = enroll_proxy(&admin, "rival").await;
    let a1 = enroll_agent_via(&admin, &branch, "acme", "agent-1").await;
    let direct = common::enroll_agent(&admin, "acme", "agent-2").await; // served by no proxy

    // What the proxy queued: the agent's own batch, proven as of the time the proxy received it.
    let received_at = unix_now() - 3600; // held through an hour-long outage
    let events = |id: &str| json!([{ "id": id, "kind": "resource.changed", "at": received_at, "resource": "motd", "version": 1, "detail": "content" }]);
    let item = |key: &str, agent: &str, events: Value, proof_ts: i64, at: i64| {
        let proof = delbert_pki::authn::prove(key, "event", "acme", agent, &events, proof_ts).unwrap();
        json!({ "tenant": "acme", "agent": agent, "received_at": at, "envelope": { "proof": proof, "events": events } })
    };
    let forward = |p: &common::EnrolledProxy, items: Vec<Value>| {
        let client = client.clone();
        let inner = json!({ "batches": items });
        let payload = json!({ "proof": p.proof("proxy-event", &inner), "inner": inner });
        let subject = format!("delbert.proxy.{}.event", p.site);
        async move {
            let reply = tokio::time::timeout(Duration::from_secs(5), client.request(subject, payload.to_string().into())).await.unwrap().unwrap();
            serde_json::from_slice::<Value>(&reply.payload).unwrap()
        }
    };
    let stored = || async {
        let (_, page) = admin.call("GET", "/v1/audit?action=agent.resource.changed", None).await;
        page["events"].as_array().unwrap().len()
    };

    // Forged (another agent's key), too old, and an agent this proxy does not serve: dropped.
    let old = unix_now() - 40 * 86_400;
    let refused = forward(&branch, vec![item(&direct.key_pem, "agent-1", events("evt-forged-0001"), received_at, received_at), item(&a1.key_pem, "agent-1", events("evt-old-000001"), old, old), item(&direct.key_pem, "agent-2", events("evt-foreign-001"), received_at, received_at)]).await;
    assert_eq!(refused["accepted"], 0, "{refused}");
    // Another proxy cannot forward for this site.
    assert_eq!(forward(&rival, vec![item(&a1.key_pem, "agent-1", events("evt-rival-0001"), received_at, received_at)]).await["accepted"], 0);
    assert_eq!(stored().await, 0);

    // Authentic: stored, and a re-delivery (the proxy lost the acknowledgement) adds nothing.
    let good = item(&a1.key_pem, "agent-1", events("evt-good-00001"), received_at, received_at);
    assert_eq!(forward(&branch, vec![good.clone()]).await["accepted"], 1);
    assert_eq!(forward(&branch, vec![good]).await["accepted"], 1, "acknowledged again");
    assert_eq!(stored().await, 1);
    let (_, page) = admin.call("GET", "/v1/audit?action=agent.resource.changed", None).await;
    assert_eq!(page["events"][0]["actor"], "agent:acme/agent-1");
    client.drain().await.ok(); // leave the queue group before the next test joins it
}
