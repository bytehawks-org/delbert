-- Editing a repository from the console (docs/REPOSITORY.md). The Core only reads by default: a
-- source has to be made `writable` on purpose (its token must be allowed to push), and the editor
-- never writes to the tracked branch of a git remote: it pushes a new branch for review.

ALTER TABLE content_sources ADD COLUMN writable boolean NOT NULL DEFAULT false;

UPDATE roles SET permissions = array_append(permissions, 'content:edit')
 WHERE name IN ('tenant-admin', 'operator') AND NOT ('content:edit' = ANY (permissions));
