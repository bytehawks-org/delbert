-- Signed anchors of the audit hash chain.
--
-- The chain alone proves consistency, not completeness: whoever can write to the database
-- can drop the newest events, or rewrite everything and recompute every hash, and the
-- chain still verifies. An anchor is a signature, made with the Core's policy-signing key
-- (which the database does not hold), over the head of the chain at a point in time.
-- Verification recomputes the chain and checks that every anchor still matches it, so a
-- truncation or a rewrite of anchored history is detected. Export the anchors to a place
-- the database administrators cannot reach (SIEM, WORM storage): deleting the newest
-- anchors together with the events is only detectable against an external copy.

CREATE TABLE audit_anchors (
    id          bigserial PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- Head of the chain: sequence number and hash of the newest event, and the event count.
    seq         bigint NOT NULL,
    hash        bytea NOT NULL,
    events      bigint NOT NULL,
    -- Key id and detached Ed25519 signature (base64url) over the canonical anchor document.
    kid         text NOT NULL,
    signature   text NOT NULL
);

CREATE FUNCTION audit_anchors_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_anchors is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_anchors_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_anchors
    FOR EACH ROW EXECUTE FUNCTION audit_anchors_immutable();

CREATE TRIGGER audit_anchors_no_truncate
    BEFORE TRUNCATE ON audit_anchors
    FOR EACH STATEMENT EXECUTE FUNCTION audit_anchors_immutable();

REVOKE UPDATE, DELETE, TRUNCATE ON audit_anchors FROM delbert_app;
