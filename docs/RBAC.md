# Delbert - RBAC v2 and authentication

Design for the next iteration of access control, driven by the web frontend ([FRONTEND.md](FRONTEND.md)). Status: **OIDC single sign-on, cookie sessions, CSRF, TOTP MFA, throttling, tenant-scoped roles and permissions implemented** (migration `0010`, [API.md](API.md)); the approval workflow is implemented too (migration `0011`: submit/approve/reject/activate/rollback, no diff or preview yet); authentication hardening and tokens are still design. What exists today is described in [API.md](API.md) ("Authentication and RBAC").

## Where we are (v1)

- Local users (Argon2id), sessions of 8 hours (random token, only its SHA-256 stored), bearer token.
- Roles are lists of permission strings assigned **globally**; a user with `policies:write` can change the policies of every tenant.
- Ten coarse permissions: `*`, `read`, `tenants:write`, `agents:write`, `policies:write`, `secrets:write`, `proxies:write`, `effective:issue`, `audit:read`, `users:admin`. Built-in roles: `admin`, `operator`, `auditor`.
- Policy versions become active the moment they are uploaded (the compiler uses the latest version).
- No MFA, no login throttling, no SSO, no scoped API tokens, no way to browse the audit trail (only `GET /v1/audit/verify`).

## Goals of v2

1. **Tenant scope**: a role is assigned globally or for one tenant; every list and every action is filtered by what the caller may access.
2. **Finer permissions**: `resource:action`, so that "read" no longer means "read everything".
3. **Optional four-eyes approval of policies, per tenant** (NIS2-relevant separation of duties).
4. **Browser-grade authentication**: cookie sessions with CSRF protection, TOTP MFA, login throttling, then OIDC/LDAP.
5. **Non-interactive access**: scoped, expiring API tokens for CI/GitOps.
6. **Audit browsing** with the same scoping rules.

## Scopes

`user_roles` gains `tenant_id` (NULL = global). A grant is therefore *(user, role, scope)*. Authorization asks `can(user, permission, tenant?)`:

- allowed if the user holds the permission through a **global** assignment, or through an assignment scoped to that very tenant;
- permissions marked *global-only* (below) are never granted by a tenant-scoped assignment;
- list endpoints return only the tenants/agents/policies the caller can reach; an unreachable tenant looks like a missing one (404, not 403) to avoid probing.

Roles carry a `scope` (`global` or `tenant`): a role meant for tenants cannot be assigned globally by mistake, and a tenant admin may assign **tenant-scoped roles within their own tenant** (delegated administration) but nothing else.

## Permissions

| Permission | Meaning | Global-only |
|------------|---------|:-----------:|
| `tenants:read` | see a tenant and its settings | |
| `tenants:create`, `tenants:delete` | create / delete tenants | yes |
| `tenants:settings` | change tenant settings (e.g. approval policy) | |
| `agents:read` | list agents, reports, compliance | |
| `agents:write` | create, change groups, delete agents | |
| `agents:enroll` | create / revoke enrollment keys | |
| `agents:preview` | issue/preview the effective policy of an agent (today `effective:issue`) | |
| `policies:read` | read policies, versions, diffs | |
| `policies:write` | create a version (a *draft* when approval is required, else it goes live) | |
| `policies:approve` | approve or reject a submitted version, roll back | |
| `secrets:read` | list secret names | |
| `secrets:write` | set / delete secrets | |
| `artifacts:read`, `artifacts:write` | list / upload artifacts | |
| `proxies:read`, `proxies:write` | list / manage proxies | yes |
| `globals:read`, `globals:write` | shared artifacts and shared variables (inherited by every tenant); `read` is in the built-in `viewer` and `auditor` | yes |
| `users:read`, `users:write` | users, MFA reset, deactivation | yes |
| `roles:read`, `roles:write` | custom roles and assignments | yes (tenant admins assign only) |
| `audit:read` | browse the audit trail (scoped to the tenant for tenant grants) | |
| `audit:export` | export it | |
| `audit:verify` | recompute the hash chain | yes |
| `roles:assign` | assign roles inside a tenant, limited to permissions the assigner holds there (delegated administration) | |
| `tokens:manage` | create API tokens for oneself (always limited to own permissions) | |

`*` remains the wildcard of the built-in platform administrator. v1 permissions map onto these in the migration (`read` → all `*:read`, `policies:write` → `policies:write` + `policies:approve` for existing installations so that nothing breaks, `effective:issue` → `agents:preview`, `users:admin` → `users:*` + `roles:*`).

### Built-in roles

| Role | Scope | Permissions |
|------|-------|-------------|
| `platform-admin` | global | `*` |
| `tenant-admin` | tenant | everything tenant-scoped, including delegated role assignment; **not** `policies:approve` on its own submissions (see below) |
| `operator` | tenant | `*:read`, `agents:write`, `agents:enroll`, `agents:preview`, `policies:write`, `artifacts:write` |
| `approver` | tenant | `*:read`, `policies:approve` |
| `auditor` | global or tenant | `*:read`, `audit:read`, `audit:export` (no `secrets:write`, no writes at all) |
| `viewer` | global or tenant | `*:read` except audit |

Built-in roles stay immutable; custom roles are composed from the permissions above.

## Policy lifecycle and optional approval

Tenant setting `approval_required` (default for new tenants set by the platform configuration, `DELBERT_APPROVAL_DEFAULT`, initially `false`).

```text
approval_required = false :  upload ──────────────────────────────▶ active
approval_required = true  :  upload ─▶ submitted ─▶ approved ─▶ active
                                          └────▶ rejected
```

- **Four-eyes**: the approver must be a different user from the author (and from whoever last edited the version). This holds for platform administrators too; there is no silent override. An emergency path (`policies:emergency`, off by default, always audited with a mandatory reason) is the only exception and is part of the design review, not of the first release.
- **Active version pointer.** Policy versions stay immutable. A mutable `policies.active_version` says which one the compiler uses (today it uses the latest). Events (`submitted`, `approved`, `rejected`, `activated`, `rolled_back`) go to an append-only table `policy_version_events` with actor, comment and time, and into the audit trail.
- **Rollback** sets `active_version` to an earlier approved version, through the same approval rule.
- **Impact preview** (conflicts per agent, planned in [ROADMAP.md](ROADMAP.md)) is shown to the approver before approving.
- Switching `approval_required` on does not touch versions already active; switching it off while versions are *submitted* asks what to do with them (approve or reject all) instead of silently activating them.

## Authentication

| Item | Decision |
|------|----------|
| Browser sessions | `HttpOnly; Secure; SameSite=Strict` cookie set by the frontend's backend-for-frontend; CSRF token (double submit) on unsafe methods; 8 h absolute, 30 min idle. Bearer tokens remain for API clients. |
| MFA | TOTP (RFC 6238) with hashed recovery codes; can be **required** per platform, per role or per tenant; mandatory for roles with global write permissions. WebAuthn later. |
| Login throttling | Counters per username and per IP with exponential delay and temporary lock, stored in the database; optional Turnstile/reCAPTCHA verification after the first failures (`CLAUDE.md`). Failures are audited without revealing whether the user exists. |
| Password policy | minimum length 12 (today), breached-password check optional, change on first login for bootstrap users. |
| SSO | OIDC (authorization code + PKCE) first; claims or groups map to *(role, scope)* assignments; LDAP/AD bind after that. Local users can be disabled when SSO is on, except one break-glass account. |
| API tokens | table `api_tokens`: hashed, owner, optional tenant scope, **subset** of the owner's permissions, expiry (required), last-used, revocable; shown once. Service accounts are users of `kind = service` without password or interactive login. |
| Sessions | listable and revocable by the user and by administrators; password change or deactivation revokes all (already true). |

## Data model changes (migrations 0010+)

- `roles.scope`, `user_roles.tenant_id` (+ unique on the triple), backfill of v1 data.
- `tenants.approval_required`, `tenants.settings jsonb`.
- `policies.active_version`, `policy_version_events` (append-only, `REVOKE UPDATE, DELETE` for `delbert_app` like the audit trail).
- `users.totp_secret` (sealed with the Core key), `user_recovery_codes`, `users.must_change_password`, `users.kind`.
- `login_attempts`, `api_tokens`.
- Optional: `audit_events.tenant_id` index and a search index for the audit browser.

## API changes

- Authorization helper `require(permission, tenant)` replaces `require(permission)`; handlers take the tenant from the path.
- `GET /v1/me` returns assignments with scopes, the effective permission set per tenant, MFA state.
- Roles and assignments: `GET/POST/PUT/DELETE /v1/roles`, `GET/PUT /v1/users/{u}/assignments`, tenant-level `GET/PUT /v1/tenants/{t}/assignments` for delegated admins.
- Approval: `POST /v1/tenants/{t}/policies/{name}/versions/{v}/submit|approve|reject|activate|rollback`, `GET .../versions`, `GET .../versions/{v}/diff?against=`.
- Tenant settings: `GET/PUT /v1/tenants/{t}/settings`.
- MFA: `POST /v1/me/mfa/enroll|confirm|disable`, `POST /v1/auth/mfa`.
- Tokens: `GET/POST/DELETE /v1/me/tokens`.
- Audit: `GET /v1/audit` with filters (tenant, actor, action, target, outcome, time range) and keyset pagination; `GET /v1/audit/export`.
- All list endpoints: keyset pagination (`limit`, `after`), `q` search and `sort` where meaningful.

## Tests to write first

- Matrix test: for every endpoint, a user with no grant, with a grant on another tenant, with the right tenant grant, and with a global grant.
- Four-eyes: author cannot approve, platform admin cannot approve their own submission, rollback needs approval when required, switching the setting is safe.
- MFA/throttling flows, token scoping (a token can never exceed its owner), CSRF rejection, migration of v1 roles.

## Open points

- Whether `tenant-admin` may disable `approval_required` for their own tenant (implemented: only a global grant, not configurable yet).
- The emergency path (`policies:emergency`) and who may hold it.
- Per-group scoping inside a tenant (e.g. an operator limited to agents of group `web`): deliberately out of v2, the data model leaves room for it.
