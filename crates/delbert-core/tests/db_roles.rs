//! The runtime database role must not be able to rewrite history.

use sqlx::PgPool;

#[sqlx::test]
async fn app_role_cannot_modify_audit_or_policy_versions(pool: PgPool) {
    sqlx::query("INSERT INTO audit_events (actor, action, outcome, hash) VALUES ('t', 'x', 'ok', '\\x00')").execute(&pool).await.unwrap();
    let tenant: sqlx::types::Uuid = sqlx::query_scalar("INSERT INTO tenants (name) VALUES ('t') RETURNING id").fetch_one(&pool).await.unwrap();
    let policy: sqlx::types::Uuid = sqlx::query_scalar("INSERT INTO policies (tenant_id, name) VALUES ($1, 'p') RETURNING id").bind(tenant).fetch_one(&pool).await.unwrap();
    sqlx::query("INSERT INTO policy_versions (policy_id, version, yaml, created_by) VALUES ($1, 1, 'y', 'u')").bind(policy).execute(&pool).await.unwrap();

    // Run statements as the runtime role (SET LOCAL ends with the transaction).
    for statement in [
        "UPDATE audit_events SET actor = 'evil'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
        "UPDATE policy_versions SET yaml = 'evil'",
        "DELETE FROM policy_versions",
    ] {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE delbert_app").execute(&mut *tx).await.unwrap();
        let err = sqlx::query(statement).execute(&mut *tx).await.unwrap_err().to_string();
        assert!(err.contains("permission denied"), "{statement}: {err}");
    }

    // ...while normal operation works for it.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL ROLE delbert_app").execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO audit_events (actor, action, outcome, hash) VALUES ('t', 'y', 'ok', '\\x01')").execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE agents SET groups = '{}'").execute(&mut *tx).await.unwrap();
    sqlx::query("SELECT count(*) FROM policy_versions").execute(&mut *tx).await.unwrap();
}
