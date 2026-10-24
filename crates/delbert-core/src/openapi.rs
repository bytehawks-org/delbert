//! OpenAPI document and Swagger UI (utoipa). Can be switched off with
//! `DELBERT_API_DOCS=false` to keep the public surface minimal.

use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
};
use utoipa_swagger_ui::SwaggerUi;

use crate::{api, auth};

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).description(Some("Session token from POST /v1/auth/login")).build()),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(title = "Delbert Core API", description = "Configuration management and state enforcement. See docs/API.md."),
    paths(
        api::healthz, auth::login, auth::logout, auth::me, auth::complete_mfa,
        auth::create_token, auth::list_tokens, auth::revoke_token, auth::mfa_enroll, auth::mfa_confirm, auth::mfa_disable, auth::admin_reset_mfa, auth::my_sessions, auth::revoke_session, auth::admin_revoke_sessions,
        auth::list_users, auth::create_user, auth::update_user, auth::delete_user,
        auth::list_permissions, auth::list_roles, auth::create_role, auth::update_role, auth::delete_role,
        auth::list_tenant_assignments, auth::set_tenant_assignments,
        api::create_tenant, api::list_tenants,
        api::create_agent, api::list_agents, api::update_agent, api::delete_agent, api::effective,
        api::create_policy, api::validate_policy_dry_run, api::list_policies, api::get_policy, api::delete_policy,
        crate::approval::get_settings, crate::approval::put_settings, crate::approval::list_versions, crate::approval::get_version,
        crate::approval::submit, crate::approval::approve, crate::approval::reject, crate::approval::activate, crate::approval::rollback,
        crate::sso::public_providers, crate::sso::start, crate::sso::callback, crate::sso::exchange,
        crate::sso::list_providers, crate::sso::get_provider, crate::sso::create_provider, crate::sso::update_provider, crate::sso::delete_provider, crate::sso::test_provider,
        crate::content::list_sources, crate::content::get_source, crate::content::create_source, crate::content::update_source, crate::content::delete_source,
        crate::content::sync_now, crate::content::list_snapshots, crate::content::get_snapshot,
        crate::signing::status, crate::signing::ca_status,
        api::audit_verify, crate::audit_api::list, crate::audit_api::export,
        crate::secrets::key_status, crate::secrets::reseal, crate::secrets::put_secret, crate::secrets::list_secrets, crate::secrets::delete_secret,
        crate::artifacts::put_artifact, crate::artifacts::list_artifacts, crate::artifacts::agent_download,
        crate::proxies::create_proxy, crate::proxies::list_proxies, crate::proxies::delete_proxy, crate::proxies::enroll_proxy, crate::proxies::renew_proxy,
        crate::proxies::proxy_enroll_agent, crate::proxies::proxy_artifact,
        crate::enroll::create_key, crate::enroll::list_keys, crate::enroll::revoke_key, crate::enroll::enroll,
    ),
    modifiers(&BearerAuth),
    tags(
        (name = "auth"), (name = "users"), (name = "roles"), (name = "tenants"),
        (name = "agents"), (name = "enrollment"), (name = "proxies"), (name = "secrets"), (name = "artifacts"), (name = "policies"), (name = "audit"), (name = "sso"), (name = "content"), (name = "system")
    )
)]
pub struct ApiDoc;

/// Routes serving `/openapi.json` and `/swagger-ui`.
pub fn docs() -> axum::Router<api::AppState> {
    SwaggerUi::new("/swagger-ui").url("/openapi.json", ApiDoc::openapi()).into()
}
