-- Initial schema: tenants and the append-only audit trail.

CREATE TABLE tenants (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Every event embeds the hash of the previous one (hash chain, computed by the
-- application) so tampering is detectable. See docs/ABSTRACT.md §6.
CREATE TABLE audit_events (
    seq         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    tenant_id   uuid REFERENCES tenants (id),
    actor       text NOT NULL,
    action      text NOT NULL,
    target      text,
    outcome     text NOT NULL,
    details     jsonb NOT NULL DEFAULT '{}',
    prev_hash   bytea,
    hash        bytea NOT NULL
);

CREATE FUNCTION audit_events_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_immutable();
