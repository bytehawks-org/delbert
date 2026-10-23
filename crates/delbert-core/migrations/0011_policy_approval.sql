-- Policy lifecycle (docs/RBAC.md): optional four-eyes approval per tenant and an
-- explicit pointer to the version that is live. Versions stay immutable.

ALTER TABLE tenants ADD COLUMN approval_required boolean NOT NULL DEFAULT false;

-- The compiler uses this version; NULL = nothing live yet (e.g. a first draft awaiting approval).
ALTER TABLE policies ADD COLUMN active_version bigint;
UPDATE policies p SET active_version = (SELECT MAX(version) FROM policy_versions v WHERE v.policy_id = p.id);

-- What happened to a version, append-only. The state of a version is its latest
-- submitted/approved/rejected event (none = draft).
CREATE TABLE policy_version_events (
    id         bigserial PRIMARY KEY,
    policy_id  uuid NOT NULL REFERENCES policies (id),
    version    bigint NOT NULL,
    event      text NOT NULL CHECK (event IN ('submitted', 'approved', 'rejected', 'activated', 'rolled_back')),
    actor      text NOT NULL,
    comment    text,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (policy_id, version) REFERENCES policy_versions (policy_id, version)
);
CREATE INDEX policy_version_events_idx ON policy_version_events (policy_id, version, id);

CREATE FUNCTION policy_version_events_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'policy_version_events is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER policy_version_events_no_update_delete
    BEFORE UPDATE OR DELETE ON policy_version_events
    FOR EACH ROW EXECUTE FUNCTION policy_version_events_immutable();

REVOKE UPDATE, DELETE, TRUNCATE ON policy_version_events FROM delbert_app;
