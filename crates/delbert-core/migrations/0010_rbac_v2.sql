-- RBAC v2 (docs/RBAC.md): tenant-scoped role assignments and `resource:action` permissions.

-- A role is meant for global assignments, for one tenant, or for both.
ALTER TABLE roles ADD COLUMN scope text NOT NULL DEFAULT 'global' CHECK (scope IN ('global', 'tenant', 'any'));

-- An assignment is (user, role, scope); tenant_id NULL means global.
ALTER TABLE user_roles DROP CONSTRAINT user_roles_pkey;
ALTER TABLE user_roles ADD COLUMN tenant_id uuid REFERENCES tenants (id) ON DELETE CASCADE;
CREATE UNIQUE INDEX user_roles_scope_key ON user_roles (user_id, role_id, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'));
CREATE INDEX user_roles_tenant_idx ON user_roles (tenant_id);

-- Custom roles of v1 installations: map the ten coarse permissions onto the new ones.
UPDATE roles r SET permissions = ARRAY(
    SELECT DISTINCT m FROM unnest(r.permissions) AS p, LATERAL unnest(CASE p
        WHEN 'read'           THEN ARRAY['tenants:read', 'agents:read', 'policies:read', 'secrets:read', 'artifacts:read', 'proxies:read', 'users:read', 'roles:read']
        WHEN 'tenants:write'  THEN ARRAY['tenants:create', 'tenants:delete', 'tenants:settings']
        WHEN 'agents:write'   THEN ARRAY['agents:write', 'agents:enroll']
        WHEN 'policies:write' THEN ARRAY['policies:write', 'policies:approve', 'artifacts:write']
        WHEN 'effective:issue' THEN ARRAY['agents:preview']
        WHEN 'audit:read'     THEN ARRAY['audit:read', 'audit:export', 'audit:verify']
        WHEN 'users:admin'    THEN ARRAY['users:read', 'users:write', 'roles:read', 'roles:write', 'roles:assign']
        ELSE ARRAY[p] END) AS m ORDER BY m
) WHERE NOT builtin;

-- Built-in roles (immutable).
UPDATE roles SET name = 'platform-admin', permissions = '{*}', scope = 'global' WHERE name = 'admin';
UPDATE roles SET scope = 'tenant', permissions = '{tenants:read,agents:read,agents:write,agents:enroll,agents:preview,policies:read,policies:write,secrets:read,artifacts:read,artifacts:write}' WHERE name = 'operator';
UPDATE roles SET scope = 'any', permissions = '{tenants:read,agents:read,policies:read,secrets:read,artifacts:read,proxies:read,users:read,roles:read,audit:read,audit:export,audit:verify}' WHERE name = 'auditor';

INSERT INTO roles (name, permissions, builtin, scope) VALUES
    ('tenant-admin', '{tenants:read,tenants:settings,agents:read,agents:write,agents:enroll,agents:preview,policies:read,policies:write,policies:approve,secrets:read,secrets:write,artifacts:read,artifacts:write,audit:read,audit:export,roles:assign,tokens:manage}', true, 'tenant'),
    ('approver',     '{tenants:read,agents:read,policies:read,policies:approve,artifacts:read}', true, 'tenant'),
    ('viewer',       '{tenants:read,agents:read,policies:read,secrets:read,artifacts:read,proxies:read}', true, 'any');
