-- Tenant secrets (encrypted at rest with the Core's age key) and content-addressed artifacts.

CREATE TABLE secrets (
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    name       text NOT NULL,
    -- age ciphertext for the Core's secrets key; never returned by the API.
    ciphertext bytea NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name)
);

-- Immutable versions; agents fetch by hash.
CREATE TABLE artifacts (
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    name       text NOT NULL,
    version    bigint NOT NULL,
    sha256     bytea NOT NULL,
    size       bigint NOT NULL,
    content    bytea NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name, version)
);
CREATE INDEX artifacts_by_hash ON artifacts (tenant_id, name, sha256);

CREATE FUNCTION artifacts_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'artifacts is immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER artifacts_no_update_delete
    BEFORE UPDATE OR DELETE ON artifacts
    FOR EACH ROW EXECUTE FUNCTION artifacts_immutable();

REVOKE UPDATE, DELETE, TRUNCATE ON artifacts FROM delbert_app;
