# Repository layout and the online editor

How a git repository (or a directory) describes the configuration of a tenant, and how to edit it from the console. It builds on [CONTENT.md](CONTENT.md) (how a content source is read and applied); a ready-to-copy skeleton is in [deploy/repository-template/](../deploy/repository-template/).

## Layout

Four kinds of content, each organized by **scope**. The tree is the configuration of **one tenant**:

```text
README.md              ignored by the sync
tenant.yaml            settings of the tenant (approval_required)                  [optional]
policies/
  tenant/<name>.yaml           applies to every agent of the tenant
  groups/<group>/<name>.yaml   applies to the agents in that group
  hosts/<host>/<name>.yaml     applies to one agent
files/                 content copied as it is      (artifact://<name>, used by `copy`)
  tenant/<name>
templates/             MiniJinja templates          (artifact://<name>, used by `template`)
  tenant/<name>
variables/
  tenant.yaml                  variables for the whole tenant
  groups/<group>.yaml          for a group, over the tenant's
  hosts/<host>.yaml            for one agent, over its groups'
```

Two shapes of repository, same tree:

- **A repository per tenant** (a source with `tenant: <name>`): the tree is at the root. The source can only ever touch that tenant, and access is controlled per repository. This is the shape of the template.
- **One repository for several tenants** (a platform source): the same tree under `tenants/<tenant>/`. The old flat form (`policies/<name>.yaml`, `artifacts/<name>`) is still read.

Groups and hosts belong to a tenant, which is why they sit *inside* the tenant's tree and not beside it: `web` or `agent-1` can exist in two tenants.

### Rules

- **The folder decides who a policy applies to.** `groups/web/` sets `target.groups: [web]` and `hosts/web01/` sets `target.agents: [web01]` (the stored policy carries it, so the Core compiles it like any other). A `target` in the file must agree with the folder or be absent; a contradiction rejects the whole snapshot. `tenant/` keeps whatever the file says, which by default is every agent.
- A policy file is called `<metadata.name>.yaml`; names are unique in a tenant, whatever the folder (the same name in two folders is an error). Moving a policy to another folder moves who gets it, as one new version.
- `files/` and `templates/` are artifacts and share one namespace (same name in both is an error). Which one a name is depends on how a policy uses it (`copy.src` or `template.src`).
- A variables file is `vars:` (name → value) and optionally `locked:` (constants that nothing below can override). Scopes map one to one to the variable layers: tenant, group, agent. A `hosts/` file needs the agent to exist.
- `README.md`, `.gitkeep` and `*.example` anywhere in the tree are not content and are ignored.
- **No secrets.** Secrets go to the write-only store and are referenced by name (`spec.secrets`).
- The sync validates the whole tree first and applies nothing if anything is wrong; the error names the file ([CONTENT.md](CONTENT.md)). Variables, like policies and artifacts, are **owned** by the source: the API refuses to edit them (409 naming the source). With `prune`, a variable that left the repository is deleted.

### Not supported yet

| Item | Why |
|------|-----|
| `files/` and `templates/` per **group** or **host** | Artifacts exist at tenant and shared scope only. It needs layering by name (host > group > tenant > shared), like variables, plus a way to preview which version an agent gets. The sync refuses such files with a clear message. |
| Shared (**global**) content from a repository: variables, files, templates | A platform-wide scope in a multi-tenant repository (`globals/`); content ownership is per tenant today. |
| **Global policies** (applying to every tenant) | Not in the model: it touches isolation between tenants (platform approval, priority, opt-out). |
| Variables of a **host that does not exist yet** | Same rule as the API: enroll the agent first. |

## Editing from the console

`Content` → a source → **Edit** opens an editor with the file tree on the left and [Monaco](https://github.com/microsoft/monaco-editor) (MIT, the editor of VS Code) on the right. Monaco is copied from `node_modules` into `public/monaco` at build time and served by the console itself: no CDN.

1. **Nothing is written while you edit.** Changes are kept in the browser (added `+`, modified `●`, deleted `−`).
2. **Every pause asks the Core to validate** (`POST .../validate`): it builds the repository as it would be after the change and runs the sync's own parser on it. The problems are shown with the file name. Commit is disabled until the result is valid. A change is refused only for the problems it **introduces**: a repository that is already broken can be repaired one file at a time.
3. **Commit** (`POST .../commits`) with a message:
   - **git source:** the Core clones the tracked branch, writes the files, commits as the user (author `<user>`, `<user>@delbert.invalid`) and pushes a **new branch** `delbert/<user>-<time>`. **The tracked branch is never written.** Review and merge happen in the forge (branch protection, four-eyes, CODEOWNERS live there); the sync applies it once merged.
   - **directory source:** the files are written in place and applied by the next sync (there is nothing to review in a folder).
4. The commit is audited (`content.commit`: user, branch, commit, files, message).

A source is editable only if it is **`writable`** (a flag set by an administrator; the token of the source must be allowed to push) and the user has **`content:edit`** (held by `tenant-admin` and `operator`; for a platform source a global grant). Reading the tree needs `content:read`. Limits: 200 files and 1 MiB each per change (4 MiB in all); binary files can be listed but not edited; the sync's own limits apply to the repository.

API: [API.md](API.md) "Content sources". Console: [FRONTEND.md](FRONTEND.md).

### Security notes

- The Core runs `git` with a fixed argument list (no shell), a private `HOME`, hooks disabled, only `https`/`ssh`/`file` as allowed, and a timeout; the token travels in the environment, never in a command line. Pushing uses the same path. Paths in a change are checked (no `..`, no `.git`, no absolute paths, no links).
- The console's pass-through allows exactly: `GET .../files`, `GET .../file`, `POST .../validate`, `POST .../commits` for the editor, and the query keys `path`/`refresh`.
- **CSP.** The console keeps a strict CSP (nonce for scripts and styles). Monaco needs two relaxations that were measured, not assumed: `style-src-attr 'unsafe-inline'` (inline style *attributes*; no inline `<style>` element is allowed: Monaco's own `<style>` elements are given the page's nonce) and `font-src data:` (its icon font is embedded in its stylesheet). `worker-src` is not opened: the editor runs without language-service workers (YAML, Markdown and plain text need none).
- A repository is trusted input only after it validates. Anyone who can merge into the tracked branch can change what agents receive; use branch protection and, for tenants that need it, `approval_required` (policies then wait for a second person).

## Roadmap of this feature

Done: the layout above (policies, files and templates at tenant scope, variables), the folder-implied target, `target.agents`, ownership of variables, the template repository, the editor with validation and commit to a new branch, and `writable` / `content:edit`.

To do (also in [ROADMAP.md](ROADMAP.md)): layering of files and templates by group and host; shared content from a repository; schema-driven completion in the editor (the policy JSON schema is available from `delbert-agent schema`; it needs a YAML language service and the `worker-src` relaxation above); opening the merge request from the console (forge APIs differ: Forgejo/Gitea, GitHub, GitLab); a diff view and a preview of which agents a change reaches; creating a repository from the template.
