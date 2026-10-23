-- Artifact content moves out of the database into an object store (local directory or
-- S3-compatible, e.g. Garage), addressed by tenant and SHA-256. PostgreSQL keeps the metadata.
-- Development databases that held artifacts in `content` must re-upload them.
ALTER TABLE artifacts DROP COLUMN content;
