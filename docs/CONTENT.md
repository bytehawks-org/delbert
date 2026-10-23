# Delbert - Content sources (files and configurations from a repository)

Design for loading policies, artifacts and tenant settings from a repository the operator controls, instead of (or next to) the API and the web UI. Status: **implemented** for `directory` and https `git` sources (see [API.md](API.md)); not yet: SSH remotes and deploy keys, required signed commits/tags, webhooks with their own secret, UI. Related: [RBAC.md](RBAC.md) (approval workflow), [POLICY.md](POLICY.md), [FRONTEND.md](FRONTEND.md).

## Goals

- A repository is a **source of truth** the Core interprets: it detects what changed, records the differences, versions the content, and feeds the same pipeline as the API (validation, approval, signing, audit).
- The operator chooses where the content lives, per source:
  - **`directory`**: a local directory on the Core's host (or a mounted volume). No git needed; the Core hashes files and versions what changes.
  - **`git`**: any git remote: a **local git server run as a component** (Forgejo/Gitea in the compose or Kubernetes stack, the same way Garage is the artifact store) or a **public/hosted one** (GitHub, GitLab, Codeberg, ...).
- Nothing about git is written in Rust: the Core uses the `git` program, like it uses Garage for objects.

## Layout of a source

```text
<root>/
  tenants/<tenant>/
    tenant.yaml            # settings (approval_required, ...)         [optional]
    policies/<name>.yaml   # one policy each, the format of POLICY.md
    artifacts/<name>       # file content, pinned by SHA-256 as today
```

Secrets are never in a repository (the secret store is write-only and sealed). A path outside this layout, a symlink leaving the root, a file over the artifact limit or a name that does not validate is an error.

## Sync

1. **Fetch.** `directory`: read the tree. `git`: `git fetch` into a bare mirror kept under the Core's data directory, then check out the configured branch/tag at a commit. Triggered by a poll interval, by `POST /v1/content/sources/{id}/sync` (a webhook from the git server or a CI job, authenticated with a scoped API token) or by the UI.
2. **Snapshot.** The result is identified by the commit id (`git`) or the tree hash (`directory`).
3. **Validate the whole snapshot first.** Every policy parses and validates, every referenced artifact exists, tenants exist. One error rejects the snapshot and **nothing is applied** (fail closed); the error is recorded and shown.
4. **Diff.** The snapshot is compared with the previous applied one per item (policy, artifact, tenant settings): added, changed, removed. The unified diff of each changed text file is stored.
5. **Apply** through the normal code paths, as the actor `source:<name>@<commit>`:
   - a changed policy becomes a **new immutable version**; with `approval_required` on the tenant it is a draft and the four-eyes rule applies, with the source as author;
   - a changed artifact becomes a new artifact version (stored in the object store);
   - a **removed** item is only deactivated if the source is configured with `prune: true`; by default removals are reported, not applied.
6. **Record.** Tables `content_sources`, `content_snapshots` (id, source, revision, status, error, applied_at) and `content_changes` (snapshot, item, kind, diff, resulting version) plus audit events. History and diffs are browsable in the UI.

An item **owned by a source** cannot be edited through the API or the UI (409 naming the source): two writers would fight. The UI shows the owning source, the last sync, the pending diff and a "sync now" button. Editing in the UI for a repository-backed item means opening a change in the repository; committing from the UI is out of scope for the first release.

## Git specifics

- Remotes: `https://` with a token (stored sealed like secrets) or `ssh://` with a deploy key; the Core verifies host keys (pinned in the source definition, no trust-on-first-use).
- The `git` program runs on the Core's host, never on a managed system, with a fixed argument list (no shell), a private `HOME`, `GIT_TERMINAL_PROMPT=0`, hooks disabled (`core.hooksPath=/dev/null`), only `https`/`ssh` protocols allowed, and a timeout. The container image carries `git`; the repository content is treated as untrusted input.
- Signed commits/tags can be required (`require_signed: true`, keys configured per source) so that only reviewed changes are applied.
- The Core only reads. Branch protection and review live in the git server, where they belong.

## API and permissions (planned)

`GET/POST/PUT/DELETE /v1/content/sources`, `POST .../{id}/sync`, `GET .../{id}/snapshots`, `GET .../snapshots/{s}` (changes and diffs). Permissions `content:read`, `content:write` (global-only: a source can write to any tenant it lists) and `content:sync` (scoped by tenant for a tenant-owned source).

## Open points

- Whether a source may be owned by a single tenant (a tenant admin brings their own repository) or only by the platform. Proposal: both; a tenant-owned source can only touch its own `tenants/<tenant>/`.
- Pull request preview: show the impact (conflicts per agent) of a branch before merging, using the same dry-run as the approval preview.
