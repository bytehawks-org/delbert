-- An enrollment key may be bound to one agent name: only that agent can use it, so a leaked key
-- cannot claim another (pre-created, not yet enrolled) agent of the tenant. NULL = any name.
ALTER TABLE enrollment_keys ADD COLUMN agent_name text;
