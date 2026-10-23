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
        api::healthz, auth::login, auth::logout, auth::me,
        auth::list_users, auth::create_user, auth::update_user, auth::delete_user,
        auth::list_roles, auth::create_role, auth::update_role, auth::delete_role,
        api::create_tenant, api::list_tenants,
        api::create_agent, api::list_agents, api::update_agent, api::delete_agent, api::effective,
        api::create_policy, api::list_policies, api::get_policy, api::delete_policy,
        api::audit_verify,
        crate::secrets::put_secret, crate::secrets::list_secrets, crate::secrets::delete_secret,
        crate::artifacts::put_artifact, crate::artifacts::list_artifacts, crate::artifacts::agent_download,
        crate::proxies::create_proxy, crate::proxies::list_proxies, crate::proxies::delete_proxy, crate::proxies::enroll_proxy,
        crate::proxies::proxy_enroll_agent, crate::proxies::proxy_artifact,
        crate::enroll::create_key, crate::enroll::list_keys, crate::enroll::revoke_key, crate::enroll::enroll,
    ),
    modifiers(&BearerAuth),
    tags(
        (name = "auth"), (name = "users"), (name = "roles"), (name = "tenants"),
        (name = "agents"), (name = "enrollment"), (name = "proxies"), (name = "secrets"), (name = "artifacts"), (name = "policies"), (name = "audit"), (name = "system")
    )
)]
pub struct ApiDoc;

/// Routes serving `/openapi.json` and `/swagger-ui`.
pub fn docs() -> axum::Router<api::AppState> {
    SwaggerUi::new("/swagger-ui").url("/openapi.json", ApiDoc::openapi()).into()
}
