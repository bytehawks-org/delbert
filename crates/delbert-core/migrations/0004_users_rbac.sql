-- Local users, customizable roles (RBAC) and API sessions.

CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    active        boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE roles (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    -- Permission strings, see crates/delbert-core/src/auth.rs ('*' = everything).
    permissions text[] NOT NULL DEFAULT '{}',
    builtin     boolean NOT NULL DEFAULT false
);

CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles (id),
    PRIMARY KEY (user_id, role_id)
);

-- Only the SHA-256 of the session token is stored.
CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

INSERT INTO roles (name, permissions, builtin) VALUES
    ('admin',    '{*}', true),
    ('operator', '{read,agents:write,policies:write,effective:issue}', true),
    ('auditor',  '{read,audit:read}', true);
