-- Agents, policies and their immutable versions.

CREATE TABLE agents (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid NOT NULL REFERENCES tenants (id),
    -- Identity used inside signed policies ("agent" field); unique per tenant.
    name              text NOT NULL,
    groups            text[] NOT NULL DEFAULT '{}',
    -- Monotonic version of the compiled policy and hash of its content: the
    -- version only increases when the compiled content changes.
    effective_version bigint NOT NULL DEFAULT 0,
    effective_hash    bytea,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE policies (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    name       text NOT NULL,
    -- Soft delete: history stays for audit.
    active     boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE policy_versions (
    policy_id  uuid NOT NULL REFERENCES policies (id),
    version    bigint NOT NULL,
    yaml       text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, version)
);

CREATE FUNCTION policy_versions_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'policy_versions is immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER policy_versions_no_update_delete
    BEFORE UPDATE OR DELETE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION policy_versions_immutable();
