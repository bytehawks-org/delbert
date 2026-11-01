//! Configuration deliveries: environment bundles for the Kubernetes Operator.

mod common;

use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{Client, admin_client, enroll_agent, state};
use delbert_core::{compile::Strategy, deliveries::DeliveryBundle};
use serde_json::{Value, json};
use sqlx::PgPool;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn fetch(
    anon: &Client,
    key: &str,
    proof_agent: &str,
    path_agent: &str,
    name: &str,
) -> (StatusCode, Vec<u8>) {
    let proof = delbert_pki::authn::prove(
        key,
        "delivery",
        "acme",
        proof_agent,
        &Value::String(name.into()),
        now(),
    )
    .unwrap();
    let header = format!(
        "Delbert-Agent {}",
        STANDARD.encode(serde_json::to_vec(&proof).unwrap())
    );
    anon.raw(
        "GET",
        format!("/v1/agent/acme/{path_agent}/deliveries/{name}"),
        vec![("authorization", header)],
        vec![],
    )
    .await
}

#[sqlx::test]
async fn an_environment_is_delivered_to_its_operator_only(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    admin
        .call("POST", "/v1/tenants", Some(json!({ "name": "acme" })))
        .await;
    let operator = enroll_agent(&admin, "acme", "op-1").await;
    let other = enroll_agent(&admin, "acme", "agent-2").await;
    let anon = Client {
        token: None,
        ..admin.clone()
    };

    // Inputs: layered variables (the group named like the delivery), a secret and a file.
    admin
        .call(
            "PUT",
            "/v1/globals/variables/region",
            Some(json!({ "value": "eu" })),
        )
        .await;
    admin
        .call(
            "PUT",
            "/v1/tenants/acme/variables/LOG_LEVEL",
            Some(json!({ "value": "info" })),
        )
        .await;
    admin
        .call(
            "PUT",
            "/v1/tenants/acme/variables/LOG_LEVEL?scope=group&target=prod",
            Some(json!({ "value": "warn" })),
        )
        .await;
    admin
        .call(
            "PUT",
            "/v1/tenants/acme/variables/PORT?scope=group&target=prod",
            Some(json!({ "value": 8080 })),
        )
        .await;
    admin
        .call(
            "PUT",
            "/v1/tenants/acme/variables/ONLY_STAGING?scope=group&target=staging",
            Some(json!({ "value": "x" })),
        )
        .await;
    assert_eq!(
        admin
            .call(
                "PUT",
                "/v1/tenants/acme/secrets/db",
                Some(json!({ "value": "hunter2" }))
            )
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let (s, _) = admin
        .raw(
            "PUT",
            "/v1/tenants/acme/artifacts/app.toml",
            vec![("content-type", "application/octet-stream".into())],
            b"port = 80\n".to_vec(),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);

    // Administration: needs the policies permission, validates, audits.
    let body = json!({ "agent": "op-1", "secrets": ["db"], "files": ["app.toml"] });
    assert_eq!(
        admin
            .call(
                "PUT",
                "/v1/tenants/acme/deliveries/prod",
                Some(body.clone())
            )
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        admin
            .call("PUT", "/v1/tenants/acme/deliveries/prod", Some(body))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        admin
            .call(
                "PUT",
                "/v1/tenants/acme/deliveries/bad",
                Some(json!({ "agent": "nobody" }))
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        admin
            .call(
                "PUT",
                "/v1/tenants/acme/deliveries/bad",
                Some(json!({ "agent": "op-1", "files": ["bad name"] }))
            )
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let (_, list) = admin.call("GET", "/v1/tenants/acme/deliveries", None).await;
    assert_eq!(
        (list[0]["name"].clone(), list[0]["agent"].clone()),
        (json!("prod"), json!("op-1"))
    );
    let (_, audit) = admin
        .call("GET", "/v1/audit?action=delivery.set", None)
        .await;
    assert!(audit.to_string().contains("delivery.set"), "{audit}");

    // The bundle: resolved variables as text, the file, the secret sealed to the operator only.
    let (status, bytes) = fetch(&anon, &operator.key_pem, "op-1", "op-1", "prod").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let bundle: DeliveryBundle = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        bundle
            .variables
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
        vec![("LOG_LEVEL", "warn"), ("PORT", "8080"), ("region", "eu")]
    );
    assert_eq!(bundle.files["app.toml"], "port = 80\n");
    assert!(bundle.version > 0);
    let sealed = STANDARD.decode(&bundle.sensitive["db"]).unwrap();
    assert_eq!(age::decrypt(&operator.age, &sealed).unwrap(), b"hunter2");
    assert!(age::decrypt(&other.age, &sealed).is_err());
    assert!(!String::from_utf8_lossy(&bytes).contains("hunter2"));

    // Only the named identity, with a valid proof for this delivery.
    assert_eq!(
        fetch(&anon, &other.key_pem, "agent-2", "agent-2", "prod")
            .await
            .0,
        StatusCode::NOT_FOUND
    ); // not its delivery
    assert_eq!(
        fetch(&anon, &other.key_pem, "agent-2", "op-1", "prod")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    ); // someone else's key
    assert_eq!(
        fetch(&anon, &operator.key_pem, "op-1", "op-1", "nope")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        anon.raw("GET", "/v1/agent/acme/op-1/deliveries/prod", vec![], vec![])
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    // Never a half configuration: a vanished secret or file refuses the whole bundle.
    admin
        .call(
            "PUT",
            "/v1/tenants/acme/deliveries/prod",
            Some(json!({ "agent": "op-1", "secrets": ["gone"] })),
        )
        .await;
    assert_eq!(
        fetch(&anon, &operator.key_pem, "op-1", "op-1", "prod")
            .await
            .0,
        StatusCode::CONFLICT
    );
    admin
        .call(
            "PUT",
            "/v1/tenants/acme/deliveries/prod",
            Some(json!({ "agent": "op-1", "files": ["gone.txt"] })),
        )
        .await;
    assert_eq!(
        fetch(&anon, &operator.key_pem, "op-1", "op-1", "prod")
            .await
            .0,
        StatusCode::CONFLICT
    );

    assert_eq!(
        admin
            .call("DELETE", "/v1/tenants/acme/deliveries/prod", None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admin
            .call("DELETE", "/v1/tenants/acme/deliveries/prod", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fetch(&anon, &operator.key_pem, "op-1", "op-1", "prod")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

/// The Operator reports over HTTP: same proof and trail as the agents' bus batches.
#[sqlx::test]
async fn the_operator_reports_what_it_applied(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    admin
        .call("POST", "/v1/tenants", Some(json!({ "name": "acme" })))
        .await;
    let operator = enroll_agent(&admin, "acme", "op-1").await;
    let other = enroll_agent(&admin, "acme", "agent-2").await;
    let anon = Client {
        token: None,
        ..admin.clone()
    };

    let post = |key: String, proof_agent: &'static str, path_agent: &'static str, events: Value| {
        let anon = anon.clone();
        async move {
            let proof =
                delbert_pki::authn::prove(&key, "event", "acme", proof_agent, &events, now())
                    .unwrap();
            let body = serde_json::to_vec(&json!({ "proof": proof, "events": events })).unwrap();
            anon.raw(
                "POST",
                format!("/v1/agent/acme/{path_agent}/events"),
                vec![("content-type", "application/json".into())],
                body,
            )
            .await
            .0
        }
    };
    let event = json!([{ "id": "0123456789abcdef", "kind": "delivery.applied", "at": now(), "resource": "shop/prod", "version": 7, "detail": "environment 'prod' version 7 applied" }]);

    assert_eq!(
        post(operator.key_pem.clone(), "op-1", "op-1", event.clone()).await,
        StatusCode::OK
    );
    // Delivered twice (a lost reply): stored once. Someone else's key, or someone else's name: refused.
    assert_eq!(
        post(operator.key_pem.clone(), "op-1", "op-1", event.clone()).await,
        StatusCode::OK
    );
    assert_eq!(
        post(other.key_pem.clone(), "agent-2", "op-1", event).await,
        StatusCode::UNAUTHORIZED
    );

    let (_, audit) = admin
        .call("GET", "/v1/audit?action=agent.delivery.applied", None)
        .await;
    let items = audit["events"]
        .as_array()
        .unwrap_or_else(|| panic!("{audit}"));
    assert_eq!(items.len(), 1, "{audit}");
    assert_eq!(items[0]["actor"], "agent:acme/op-1");
    assert_eq!(items[0]["target"], "shop/prod");
}
