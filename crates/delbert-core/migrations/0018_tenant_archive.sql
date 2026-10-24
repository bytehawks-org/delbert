-- Tenants are archived, never deleted: audit events and policy versions are append-only and
-- reference them. An archived tenant disappears from every API; its name stays reserved.
ALTER TABLE tenants ADD COLUMN archived_at timestamptz;
