-- Scoped, expiring API tokens for non-interactive clients (CI, GitOps). Only the SHA-256 is stored.
CREATE TABLE api_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name        text NOT NULL,
    token_hash  bytea NOT NULL UNIQUE,
    -- NULL = as global as the owner; otherwise the token only works inside this tenant.
    tenant_id   uuid REFERENCES tenants (id) ON DELETE CASCADE,
    -- A subset of what the owner holds (checked at creation and again at every use).
    permissions text[] NOT NULL,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_used   timestamptz,
    UNIQUE (user_id, name)
);
