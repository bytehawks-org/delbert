-- Content sources (docs/CONTENT.md): policies, artifacts and tenant settings loaded from a
-- local directory or a git remote, with snapshots, recorded changes and ownership.

CREATE TABLE content_sources (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL UNIQUE,
    kind         text NOT NULL CHECK (kind IN ('directory', 'git')),
    -- NULL = platform source (may touch any tenant); otherwise it can only touch this tenant.
    tenant_id    uuid REFERENCES tenants (id) ON DELETE CASCADE,
    -- directory: a name under the Core's content directory; git: the remote URL.
    location     text NOT NULL,
    branch       text NOT NULL DEFAULT 'main',
    subdir       text NOT NULL DEFAULT '',
    -- https access: user name and sealed token (never returned).
    auth_user    text,
    auth_token   bytea,
    prune        boolean NOT NULL DEFAULT false,
    enabled      boolean NOT NULL DEFAULT true,
    poll_secs    integer CHECK (poll_secs IS NULL OR poll_secs >= 30),
    last_sync_at timestamptz,
    last_revision text,     -- revision of the last successful read
    last_error   text,      -- why the last sync failed, cleared by the next success
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- One row per sync that found something to say.
CREATE TABLE content_snapshots (
    id         bigserial PRIMARY KEY,
    source_id  uuid NOT NULL REFERENCES content_sources (id) ON DELETE CASCADE,
    revision   text NOT NULL,
    status     text NOT NULL CHECK (status IN ('applied', 'rejected', 'failed')),
    error      text,
    actor      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX content_snapshots_idx ON content_snapshots (source_id, id DESC);

CREATE TABLE content_changes (
    id          bigserial PRIMARY KEY,
    snapshot_id bigint NOT NULL REFERENCES content_snapshots (id) ON DELETE CASCADE,
    tenant      text NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('policy', 'artifact', 'tenant')),
    name        text NOT NULL,
    change      text NOT NULL CHECK (change IN ('added', 'changed', 'removed')),
    version     bigint,
    applied     boolean NOT NULL DEFAULT true,
    diff        text
);

-- What a source owns and the hash of what it applied last: the base of the next diff, and the
-- reason the API refuses to edit the item (two writers would fight).
CREATE TABLE content_items (
    source_id uuid NOT NULL REFERENCES content_sources (id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind      text NOT NULL CHECK (kind IN ('policy', 'artifact', 'tenant')),
    name      text NOT NULL,
    last_hash bytea NOT NULL,
    PRIMARY KEY (tenant_id, kind, name)
);

-- Permissions for the new roles.
UPDATE roles SET permissions = permissions || '{content:read,content:write,content:sync}' WHERE name = 'tenant-admin';
UPDATE roles SET permissions = permissions || '{content:read,content:sync}' WHERE name = 'operator';
UPDATE roles SET permissions = permissions || '{content:read}' WHERE name IN ('auditor', 'viewer', 'approver');
