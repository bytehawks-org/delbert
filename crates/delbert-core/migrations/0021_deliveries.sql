-- Configuration deliveries to workloads (docs/ABSTRACT.md §5, "Container configuration delivery").
--
-- A delivery is one tenant environment handed to the Kubernetes Operator as a bundle. Its name is
-- the environment: the variables of the group of that name are its variables. `agent` is the
-- enrolled identity (the Operator) allowed to fetch it; `secrets` are tenant secrets re-encrypted
-- to that identity; `files` are artifacts delivered as text files.
CREATE TABLE deliveries (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    name       text NOT NULL,
    agent      text NOT NULL,
    secrets    text[] NOT NULL DEFAULT '{}',
    files      text[] NOT NULL DEFAULT '{}',
    updated_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
