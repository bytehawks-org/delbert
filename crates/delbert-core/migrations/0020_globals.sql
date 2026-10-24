-- Platform-wide artifacts and template variables (docs/CONTENT.md, docs/POLICY.md "Variables").
--
-- Global artifacts are inherited by every tenant: a policy's `artifact://<name>` resolves to the
-- tenant's own artifact first and to the global one otherwise. Same rules as tenant artifacts:
-- immutable versions, content in the object store under the nil tenant id.
CREATE TABLE global_artifacts (
    name       text NOT NULL,
    version    bigint NOT NULL,
    sha256     bytea NOT NULL,
    size       bigint NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (name, version)
);
CREATE INDEX global_artifacts_by_hash ON global_artifacts (name, sha256);

CREATE FUNCTION global_artifacts_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'global_artifacts is immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER global_artifacts_no_update_delete
    BEFORE UPDATE OR DELETE ON global_artifacts
    FOR EACH ROW EXECUTE FUNCTION global_artifacts_immutable();

REVOKE UPDATE, DELETE, TRUNCATE ON global_artifacts FROM delbert_app;

-- Variables in layers, from the most general to the most specific: global, tenant, group, agent.
-- A more specific layer overrides a more general one unless the general one is `locked` (a
-- constant). `target` is the group or agent name for those scopes, empty otherwise.
CREATE TABLE variables (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope      text NOT NULL CHECK (scope IN ('global', 'tenant', 'group', 'agent')),
    tenant_id  uuid REFERENCES tenants (id),
    target     text NOT NULL DEFAULT '',
    name       text NOT NULL,
    value      jsonb NOT NULL,
    locked     boolean NOT NULL DEFAULT false,
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope = 'global') = (tenant_id IS NULL)),
    CHECK ((scope IN ('group', 'agent')) = (target <> ''))
);
CREATE UNIQUE INDEX variables_key ON variables (scope, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'), target, name);

-- Reading the platform's shared content is part of the read-only built-in roles.
UPDATE roles SET permissions = array_append(permissions, 'globals:read') WHERE name IN ('viewer', 'auditor') AND NOT ('globals:read' = ANY (permissions));
