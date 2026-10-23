-- Agent identities (enrollment with pre-shared keys) -- docs/ABSTRACT.md §3, §4.

ALTER TABLE agents
    -- Raw Ed25519 public key certified at enrollment; verifies the agent's request proofs.
    ADD COLUMN public_key     bytea,
    -- age (X25519) recipient: secrets in policies are encrypted to it.
    ADD COLUMN enc_public_key text,
    ADD COLUMN enrolled_at    timestamptz;

CREATE TABLE enrollment_keys (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    -- Only the SHA-256 of the key is stored; the key is shown once at creation.
    secret_hash bytea NOT NULL UNIQUE,
    -- Groups given to agents that enroll with this key and do not exist yet.
    groups      text[] NOT NULL DEFAULT '{}',
    max_uses    integer NOT NULL DEFAULT 1,
    uses        integer NOT NULL DEFAULT 0,
    expires_at  timestamptz NOT NULL,
    revoked     boolean NOT NULL DEFAULT false,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
