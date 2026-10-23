-- Proxy certificate renewal with key rotation, like agents (migration 0008): the previous key
-- stays valid until the proxy proves it holds the new one.
ALTER TABLE proxies ADD COLUMN previous_public_key bytea;
