-- Variables can come from a repository (docs/REPOSITORY.md): a content source owns them like
-- policies and artifacts, so the API refuses to edit them.

ALTER TABLE content_items   DROP CONSTRAINT content_items_kind_check;
ALTER TABLE content_items   ADD  CONSTRAINT content_items_kind_check   CHECK (kind IN ('policy', 'artifact', 'tenant', 'variable'));
ALTER TABLE content_changes DROP CONSTRAINT content_changes_kind_check;
ALTER TABLE content_changes ADD  CONSTRAINT content_changes_kind_check CHECK (kind IN ('policy', 'artifact', 'tenant', 'variable'));
