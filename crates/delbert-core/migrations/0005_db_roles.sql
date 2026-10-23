-- Least-privilege runtime role.
--
-- Migrations run as the schema owner (DATABASE_MIGRATE_URL); the Core runs as a
-- login role that is a MEMBER of `delbert_app` (DATABASE_URL). That role cannot
-- alter or delete audit events or policy versions, so a compromised Core
-- cannot rewrite history.

-- Creating a role is not safe against a concurrent creation by another database of the same
-- cluster (a check-then-create races), so create and tolerate "already exists".
DO $$
BEGIN
    CREATE ROLE delbert_app NOLOGIN;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL;
END
$$;

GRANT USAGE ON SCHEMA public TO delbert_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO delbert_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO delbert_app;

-- Tables created by later migrations get the same grants automatically;
-- append-only tables must revoke explicitly, like below.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO delbert_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO delbert_app;

REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM delbert_app;
REVOKE UPDATE, DELETE, TRUNCATE ON policy_versions FROM delbert_app;
