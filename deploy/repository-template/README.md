# Delbert repository (template)

The configuration of **one tenant**, read by a Delbert *content source*. Copy this directory as a
new git repository, then point a content source at it (`kind: git`, `tenant: <name>`).
To keep several tenants in one repository, put the same tree under `tenants/<tenant>/`.

```text
tenant.yaml            settings of the tenant (approval_required)              [optional]
policies/              what to enforce
  tenant/              applies to every agent of the tenant
  groups/<group>/      applies to the agents in that group
  hosts/<host>/        applies to one agent
files/                 content copied as it is      (artifact://<name>, used by `copy`)
templates/             MiniJinja templates          (artifact://<name>, used by `template`)
  tenant/              (groups/ and hosts/ are reserved: not supported yet)
variables/
  tenant.yaml          variables for the whole tenant
  groups/<group>.yaml  for a group, over the tenant's
  hosts/<host>.yaml    for one agent, over its groups'
```

- The **folder decides who a policy applies to**: a `target` in the file must agree with it or be absent.
- A policy file is called `<metadata.name>.yaml`; names are unique in a tenant.
- `files/` and `templates/` share one namespace of artifact names.
- A variables file is `vars:` (name: value) and optionally `locked:` (names that nothing below can override).
- **No secrets here.** Secrets are written to Delbert's write-only store and referenced by name (`spec.secrets`).
- Files named `README.md`, `.gitkeep` or `*.example` are ignored by the sync.
- Edit in the console (a commit goes to a new branch for review) or with any editor and merge as usual.

Reference: docs/REPOSITORY.md, docs/POLICY.md.
