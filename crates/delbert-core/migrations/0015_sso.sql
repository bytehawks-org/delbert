-- Single sign-on through OpenID Connect (Keycloak, Microsoft Entra ID, ...).

CREATE TABLE sso_providers (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL UNIQUE,          -- slug used in URLs
    display_name    text NOT NULL,
    issuer          text NOT NULL,
    client_id       text NOT NULL,
    client_secret   bytea,                         -- sealed with the Core key; NULL = public client (PKCE only)
    scopes          text[] NOT NULL DEFAULT '{openid,profile,email}',
    groups_claim    text NOT NULL DEFAULT 'groups',
    -- Refuse the login when none of the user's groups maps to a role.
    require_mapping boolean NOT NULL DEFAULT true,
    enabled         boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Group (or app role) of the identity provider -> role, globally or for one tenant.
CREATE TABLE sso_mappings (
    provider_id uuid NOT NULL REFERENCES sso_providers (id) ON DELETE CASCADE,
    group_name  text NOT NULL,
    role_id     uuid NOT NULL REFERENCES roles (id),
    tenant_id   uuid REFERENCES tenants (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX sso_mappings_key ON sso_mappings (provider_id, group_name, role_id, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'));

ALTER TABLE users
    ADD COLUMN sso_provider_id uuid REFERENCES sso_providers (id),
    ADD COLUMN sso_subject     text;
CREATE UNIQUE INDEX users_sso_key ON users (sso_provider_id, sso_subject) WHERE sso_provider_id IS NOT NULL;

-- Assignments written by a login are replaced at the next login; manual ones are never touched by it.
ALTER TABLE user_roles ADD COLUMN source text NOT NULL DEFAULT 'manual';

-- One-time state of a login in progress, and the one-time code the front end exchanges for a session.
CREATE TABLE sso_states (
    state_hash    bytea PRIMARY KEY,
    provider_id   uuid NOT NULL REFERENCES sso_providers (id) ON DELETE CASCADE,
    nonce         text NOT NULL,
    pkce_verifier text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sso_codes (
    code_hash  bytea PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
