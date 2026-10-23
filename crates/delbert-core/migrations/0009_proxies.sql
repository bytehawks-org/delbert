-- Proxy / relay servers for branch offices (docs/ABSTRACT.md §2).

CREATE TABLE proxies (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Site name; becomes a NATS subject token (no dots).
    name               text NOT NULL UNIQUE,
    -- DNS names of the proxy's HTTPS and NATS endpoints (certificate SANs).
    dns_names          text[] NOT NULL DEFAULT '{}',
    -- One-time enrollment key (hash), cleared once used.
    enroll_secret_hash bytea UNIQUE,
    enroll_expires_at  timestamptz,
    -- Raw Ed25519 public key certified at enrollment.
    public_key         bytea,
    enrolled_at        timestamptz,
    last_seen_at       timestamptz,
    created_by         text NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now()
);

-- Agents enrolled through a proxy are served by it.
ALTER TABLE agents ADD COLUMN proxy_id uuid REFERENCES proxies (id);
