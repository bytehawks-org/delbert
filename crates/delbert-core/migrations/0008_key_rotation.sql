-- Certificate renewal rotates the agent's key. The previous key stays valid until a
-- request signed with the new one is seen, so an agent that loses the renewal reply
-- (or crashes before saving it) is never locked out.
ALTER TABLE agents ADD COLUMN previous_public_key bytea;
