# Delbert - Core API

JSON over HTTP, served by `delbert-core` (Axum). Interactive documentation: `/swagger-ui` and `/openapi.json` (generated with utoipa; disable with `DELBERT_API_DOCS=false`). Everything except `/healthz`, `POST /v1/auth/login` and the documentation requires `Authorization: Bearer <session token>` and the permission listed below. Agents do not use this API: they talk to the Core over NATS ([ABSTRACT.md](ABSTRACT.md) §2).

## Configuration (file and environment)

`delbert-core --config <file>` (or `DELBERT_CONFIG`) reads a TOML file whose settings map one-to-one to the variables below (`[server] bind` is `DELBERT_BIND`; the example [deploy/delbert-core.example.toml](../deploy/delbert-core.example.toml) lists every key). **The environment wins over the file**, which wins over the default. Unknown keys and wrong types are errors. `delbert-core [--config <file>] --check-config` prints the effective configuration with the origin of each value (secrets masked), reports missing files, bad numbers and invalid choices, and exits non-zero on problems without starting anything. Use the `*_file` settings for secrets.

| Variable | Meaning |
|----------|---------|
| `DELBERT_TLS_CERT_FILE`, `DELBERT_TLS_KEY_FILE` | Serve the API over HTTPS (required in production: enrollment keys and artifacts travel here); without them plain HTTP with a warning |
| `DELBERT_CA_CERT_FILE`, `DELBERT_CA_KEY_FILE` | The Delbert CA (create with `delbert-pki init`); without it enrollment is disabled |
| `DELBERT_AGENT_CERT_DAYS` | Validity of agent certificates, default 365; agents renew on their own |
| `DELBERT_SECRETS_KEY_FILE` | age identity that seals tenant secrets at rest (`delbert-pki secrets-key`); without it the secret store is disabled |
| `NATS_CA_FILE`, `NATS_CLIENT_CERT_FILE`, `NATS_CLIENT_KEY_FILE` | mTLS towards NATS (client certificate from `delbert-pki issue-client core-nats`) |
| `DELBERT_NATS_ISSUER_SEED_FILE`, `NATS_AUTH_USER`, `NATS_AUTH_PASSWORD` | Enable the NATS authorization callout (seed from `delbert-pki nats-issuer`; the Core's callout service connects with this static user) |
| `DELBERT_NATS_ACCOUNT`, `DELBERT_NATS_SESSION_SECS` | NATS account the clients are placed in (default `APP`) and how long a connection may live before it must be authorized again (default 900) |
| `DELBERT_PUBLIC_NATS_URL` | NATS URL handed to agents at enrollment |
| `DELBERT_ARTIFACT_STORE` | Where artifact content lives: `local` (default; directory `DELBERT_ARTIFACT_DIR`, default `./data/artifacts`, `/var/lib/delbert-core/artifacts` in the image) or `s3` (any S3-compatible service, e.g. Garage). PostgreSQL only keeps metadata |
| `DELBERT_S3_ENDPOINT`, `DELBERT_S3_BUCKET`, `DELBERT_S3_REGION` (default `garage`), `DELBERT_S3_ACCESS_KEY`, `DELBERT_S3_SECRET_KEY` or `DELBERT_S3_SECRET_KEY_FILE` | S3 settings (path-style addressing; `http://` endpoints are accepted for development only). The Core checks reachability and credentials at startup |
| `DELBERT_PUBLIC_URL` | Public base URL of the Core (`https://delbert.example.com`); SSO redirect URIs are `<url>/v1/auth/sso/<provider>/callback` |
| `DELBERT_UI_URL` | Where the browser is sent after SSO (with `?code=`, or `?sso_error=`); default `/` |
| `DELBERT_LOCAL_LOGIN` | `all` (default) or `admins`: with SSO in charge, only users holding a global role (break-glass administrators) may use a local password |
| `DELBERT_CONTENT_DIR` | Base directory for content sources: `directory` sources are names under it, git mirrors live in `.git-mirrors` (default `./data/content`, `/var/lib/delbert-core/content` in the image) |
| `DELBERT_CONTENT_ALLOW_TENANT_GIT` | `true` lets tenant administrators define git sources (the Core then fetches from URLs they choose); default `false` |
| `DELBERT_CONTENT_ALLOW_FILE` | `true` allows `file://` remotes (air-gapped local repositories, tests); default `false` |
| `DELBERT_CONTENT_POLL` | `false` disables the background polling of sources with `poll_secs` (default on) |
| `DELBERT_MFA_REQUIRED` | `none` (default), `admins` (users with a global role) or `all`: who must set up TOTP. Without it such a user only reaches the profile and the enrolment endpoints |
| `DELBERT_COOKIE_INSECURE` | `true` drops the `Secure` flag of the session cookie (plain-HTTP development only) |
| `DELBERT_TRUST_FORWARDED` | `true` takes the client address from `X-Forwarded-For` (only behind a trusted reverse proxy); used for login throttling and the session list |
| `DELBERT_APPROVAL_DEFAULT` | `true` = new tenants require policy approval (default `false`) |
| `DATABASE_URL` | PostgreSQL connection of the runtime role (member of `delbert_app`, see Database) (required) |
| `DATABASE_MIGRATE_URL` | Schema owner connection used only to run migrations; defaults to `DATABASE_URL` |
| `DELBERT_BOOTSTRAP_ADMIN_PASSWORD` | Creates user `admin` (role `admin`) when the database has no users; at least 12 characters |
| `NATS_URL`, `NATS_USER`, `NATS_PASSWORD` | Message bus; without it there are no notifications and agents cannot pull |
| `DELBERT_BIND` | Listen address, default `0.0.0.0:8080` |
| `DELBERT_SIGNING_KEY_FILE`, `DELBERT_SIGNING_KID` | Policy Signing Key (base64 seed from `delbert-sign keygen`) and its key id; without them no policy can be issued |
| `DELBERT_SIGNING_PUBLISH_KEYS`, `DELBERT_SIGNING_RETIRE_KEYS` | Signing-key rotation: `kid=publickey,...` announced to agents, `kid,...` agents forget ([ROTATION.md](ROTATION.md)) |
| `DELBERT_POLICY_TTL_SECS` | Validity of issued policies, default 86400 |
| `DELBERT_CONFLICT_STRATEGY` | Comma-separated chain, `priority`, `error` (default `error`); `error` is always the implicit last resort |
| `DELBERT_API_DOCS` | `false` disables Swagger UI and `/openapi.json` |

## Authentication and RBAC

- `POST /v1/auth/login` with `{username, password}` returns a session token valid 8 hours (Argon2id passwords; only the SHA-256 of the token is stored). `POST /v1/auth/logout` revokes it; changing a password or deactivating a user revokes their sessions.
- **Sessions:** 8 h absolute, 30 min idle. `POST /v1/auth/login` with `"cookie": true` also sets `delbert_session` (`HttpOnly; SameSite=Strict; Secure`) and returns a `csrf_token`; cookie-authenticated unsafe requests must carry it as `X-CSRF-Token`. Bearer use needs no CSRF token. `GET/DELETE /v1/me/sessions[/{id}]` list and revoke own sessions, `DELETE /v1/users/{u}/sessions` revokes a user's.
- **MFA (TOTP, RFC 6238):** `POST /v1/me/mfa/enroll` → secret and `otpauth://` URI (the secret is sealed with the Core key; MFA needs `DELBERT_SECRETS_KEY_FILE`), `POST /v1/me/mfa/confirm {code}` → 10 single-use recovery codes (shown once), `POST /v1/me/mfa/disable {password, code}`. With MFA on, login returns `mfa_required: true` and a 5-minute pending session that opens nothing but `POST /v1/auth/mfa {code}` (TOTP or recovery code). A TOTP step is accepted once (replay protection). `DELETE /v1/users/{u}/mfa` resets a user's factor and ends their sessions.
- **Throttling:** failed logins (and failed second factors) within 15 minutes are counted per (user, address) — 5 —, per address — 30 — and per user — 20 —; beyond that login answers 429, even with the right password. Counting per pair keeps a stranger from locking the real user out. Attempts, throttling and MFA results are audited.
- **API tokens** (`dlb_...`): `POST /v1/me/tokens {name, permissions, tenant?, expires_in_days}` (needs `tokens:manage`; 1-365 days, always expiring) returns the token once; `GET /v1/me/tokens`, `DELETE /v1/me/tokens/{id}`. A token acts as its owner reduced to the listed permissions (and to one tenant if set); the owner's rights are read at every use, so a token never exceeds them, and it stops with the owner. Tokens cannot create tokens, use `/v1/me` or manage MFA and sessions, and tenant tokens cannot carry platform-wide permissions.
- **Single sign-on (OpenID Connect):** providers are managed at `/v1/sso/providers` (`sso:read`/`sso:write`, global; the client secret is sealed and never returned) with group → role mappings (`{group, role, tenant?}`; the role's scope must fit). Any compliant provider works: Keycloak (verified against 26.4 with a group-membership mapper to the `groups` claim), Microsoft Entra ID (v2.0 issuer `https://login.microsoftonline.com/<tenant id>/v2.0`; map group object IDs or app roles via `groups_claim: "roles"`; users in more than ~200 groups get a claim overage that is not followed yet). Flow: `GET /v1/auth/sso/{provider}/login` → provider → `/callback` (authorization code + PKCE S256, state and nonce single use, signature/issuer/audience/expiry checked by the `openidconnect` crate) → redirect to `DELBERT_UI_URL?code=…` → `POST /v1/auth/sso/exchange {code, cookie?}` returns a normal session (the code lives 60 s and works once). `GET /v1/auth/sso/providers` lists the enabled ones for the login page. Users are keyed by the stable `sub`; a **name that already exists locally is never adopted** (refused, no linking by name or email); `require_mapping` (default) refuses logins with no mapped group and strips the previously granted roles; roles given by a login are replaced at the next login and never touch manually assigned ones; MFA is the provider's job for SSO users. Issuers must be `https://` (plain `http://` only when `DELBERT_COOKIE_INSECURE=true`).
- A role is a list of `resource:action` permissions (`*` = everything, `resource:*` = every action on a resource) and has a **scope**: `global`, `tenant` or `any`. A user holds roles through **assignments** `{role, tenant?}`: global, or for one tenant. A tenant-scoped assignment grants its permissions only inside that tenant and never the global-only ones (`tenants:create|delete`, `proxies:*`, `users:*`, `roles:read|write`, `audit:verify`). A tenant the caller has no role in answers 404, not 403. Full model: [RBAC.md](RBAC.md).
- Permissions: `tenants:{read,create,delete,settings}`, `agents:{read,write,enroll,preview}`, `policies:{read,write,approve}`, `secrets:{read,write}`, `artifacts:{read,write}`, `proxies:{read,write}`, `users:{read,write}`, `roles:{read,write,assign}`, `audit:{read,export,verify}`, `tokens:manage`. Built-in roles (immutable): `platform-admin` (`*`, global), `tenant-admin`, `operator`, `approver` (tenant), `auditor`, `viewer` (any). Custom roles can be created, changed and deleted (not while assigned).
- Delegation: a holder of `roles:assign` in a tenant (the `tenant-admin`) manages assignments of that tenant only, and can only grant permissions they hold there.
- The last active holder of a global `*` cannot be deleted, deactivated or demoted.
- Policy lifecycle: with `approval_required` on a tenant, a new version is a draft (`live: false` in the upload answer) until submitted, approved by someone else and activated; without it, an upload goes live at once. The compiler uses `policies.active_version`. New tenants take the default of `DELBERT_APPROVAL_DEFAULT` (`true`/`false`, default `false`).
- Not done yet: SAML, LDAP/AD, captcha (Turnstile) after failures, WebAuthn ([ROADMAP.md](ROADMAP.md)).

## Content sources

Policies, artifacts and tenant settings can come from a repository instead of the API ([CONTENT.md](CONTENT.md)). Layout: `tenants/<tenant>/{tenant.yaml, policies/<name>.yaml, artifacts/<name>}`; everything else at the top level (README, CI files) is ignored, anything unknown under `tenants/` is an error. A source is a `directory` (a folder under `DELBERT_CONTENT_DIR`; platform only) or `git` (`https://` remote, optional user and access token sealed in the database; `http://` and `file://` only in development/air-gapped setups). It belongs to the platform (may touch any tenant) or to one tenant (only that tenant, and only if `DELBERT_CONTENT_ALLOW_TENANT_GIT` is on for git). A sync reads the snapshot, validates all of it (one bad item rejects everything and applies nothing), diffs it against what the source applied last, and applies through the normal paths: policies become new immutable versions (drafts when the tenant requires approval, authored by `source:<name>@<revision>`), artifacts new artifact versions, `tenant.yaml` sets `approval_required` (never off from a tenant-owned source). Removed items are reported and, only with `prune`, deactivated (artifacts just lose their owner). Items a source applied are **read-only in the API** (409 naming the source). `POST .../sync` (also from a CI job with a scoped token), `poll_secs` (at least 30) and a background poller trigger syncs; git is the `git` program on the Core host with fixed arguments, no shell, hooks off, a private HOME, no prompts, a timeout, and the token passed through the environment. Verified against a local git server (Forgejo 11) with a private repository and a token.

## Endpoints

| Method and path | Permission | Purpose |
|-----------------|------------|---------|
| `GET /healthz` | public | Liveness and database reachability |
| `POST /v1/auth/login`, `POST /v1/auth/mfa`, `POST /v1/auth/logout`, `GET /v1/me` | public / pending / any session | Session handling |
| `POST /v1/me/mfa/enroll|confirm|disable`, `GET/DELETE /v1/me/sessions` | any session | Own MFA and sessions |
| `GET/POST /v1/sso/providers`, `GET/PUT/DELETE /v1/sso/providers/{name}`, `POST .../test` | `sso:read` / `sso:write` (global) | OIDC providers and group mappings; `test` runs discovery |
| `GET /v1/auth/sso/providers`, `GET /v1/auth/sso/{p}/login`, `GET /v1/auth/sso/{p}/callback`, `POST /v1/auth/sso/exchange` | public | SSO login |
| `DELETE /v1/users/{u}/mfa`, `DELETE /v1/users/{u}/sessions` | `users:write` | Reset MFA / revoke sessions of a user |
| `GET/POST /v1/users`, `PUT/DELETE /v1/users/{username}` | `users:read` / `users:write` | Users (password, active, `assignments`) |
| `GET/POST /v1/roles`, `PUT/DELETE /v1/roles/{name}` | `roles:read` (or `roles:assign` in a tenant) / `roles:write` | Roles (`permissions`, `scope`) |
| `GET /v1/tenants/{t}/assignments`, `PUT .../assignments/{username}` | `roles:assign` in the tenant | Delegated administration: who holds which role in the tenant; set a user's roles there |
| `POST /v1/tenants`, `GET /v1/tenants` | `tenants:create` (global) / `tenants:read` | Tenants (the list is limited to reachable tenants) |
| `POST/GET /v1/tenants/{t}/agents` | `agents:write` / `agents:read` | Create / list agents (`name`, `groups`; list includes the last report) |
| `PUT/DELETE /v1/tenants/{t}/agents/{a}` | `agents:write` | Change groups / delete |
| `POST/GET /v1/tenants/{t}/enrollment-keys`, `DELETE .../{id}` | `agents:enroll` | Enrollment keys: expiring, limited uses, revocable; the key is shown once |
| `POST/GET /v1/proxies`, `DELETE /v1/proxies/{name}` | `proxies:write` / `proxies:read` (global) | Branch-office proxies ([PROXY.md](PROXY.md)): create (one-time key), list (agents, last seen), delete (refused while agents are assigned) |
| `POST /v1/proxies/enroll` | the proxy\'s one-time key | Proxy enrollment: CSR in, certificate (client and server) out |
| `POST /v1/proxy/enroll-agent`, `GET /v1/proxy/{site}/artifacts/{tenant}/{name}` | proxy proof | Used by a proxy for its agents: enrollment relay, artifact fetch |
| `POST /v1/enroll` | the enrollment key | Agent enrollment: CSR + age public key in, certificate + CA + signing keys out |
| `PUT/GET /v1/tenants/{t}/secrets[/{name}]`, `DELETE` | `secrets:write` / `secrets:read` | Tenant secrets: write-only, the list shows names only |
| `PUT /v1/tenants/{t}/artifacts/{name}`, `GET .../artifacts` | `artifacts:write` / `artifacts:read` | Immutable artifact versions (64 MiB at most); same content is a no-op |
| `GET /v1/agent/{t}/{a}/artifacts/{name}?sha256=` | agent proof | Download by hash, authenticated with `Authorization: Delbert-Agent <base64 proof>` |
| `POST/GET /v1/tenants/{t}/policies` | `policies:write` / `policies:read` | Upload a policy YAML (`{"yaml": "..."}`, new immutable version) / list |
| `GET/DELETE /v1/tenants/{t}/policies/{name}` | `policies:read` / `policies:write` | Latest version / deactivate (soft delete, history kept) |
| `GET/PUT /v1/tenants/{t}/settings` | `tenants:read` / `tenants:settings` | Tenant settings: `approval_required`. Switching it off needs a global grant and no version waiting for approval |
| `GET .../policies/{name}/versions`, `GET .../versions/{v}` | `policies:read` | Versions with state (`draft`, `submitted`, `approved`, `rejected`), the live one, YAML and event history |
| `POST .../versions/{v}/submit`, `.../activate` | `policies:write` | Put a draft up for review / make an approved version live |
| `POST .../versions/{v}/approve`, `.../reject`, `.../rollback` | `policies:approve` | Review (the author and the submitter cannot, nobody is exempt; reject needs a `comment`) / go back to a previously approved older version |
| `GET /v1/tenants/{t}/agents/{a}/effective` | `agents:preview` | Compile the policies targeting the agent, resolve conflicts, sign: `{token, version, conflicts}` |
| `GET/POST /v1/content/sources`, `GET/PUT/DELETE .../{name}` | `content:read` / `content:write` (tenant-scoped; global for platform sources) | Content sources |
| `POST /v1/content/sources/{name}/sync` | `content:sync` | Sync now: `{revision, status (unchanged/applied/rejected/failed), changes[] with diffs, errors}` |
| `GET .../{name}/snapshots`, `GET .../snapshots/{id}` | `content:read` | History: every applied/rejected snapshot with its changes and diffs |
| `GET /v1/signing/keys` | `keys:read` (global) | Active / published / retiring signing keys and which agents know each |
| `GET /v1/audit` | `audit:read` (scoped) | Browse the trail, newest first. Filters `tenant`, `actor`, `action` (`policy.*` = prefix), `target`, `outcome`, `from`, `to` (unix seconds); keyset paging with `limit` (max 1000) and `before` = the `next` of the previous page. A tenant-scoped grant sees only its tenants' events |
| `GET /v1/audit/export` | `audit:export` (scoped) | Same filters, NDJSON oldest first, with `occurred_at_micros`, `prev_hash` and `hash` to recompute the chain offline / feed a SIEM. The export records itself (`audit.export`) |
| `GET /v1/audit/verify` | `audit:verify` (global) | Recompute the audit hash chain: `{events, first_bad}` |

Errors are `{"error": "..."}` with 401, 403, 404, 409 (duplicate or in use), 422 (invalid input) or 503.

## Message bus (agents)

| Subject | Direction | Purpose |
|---------|-----------|---------|
| `delbert.notify.<t>.<a>` | Core to agent | "pull again" hint after policy, group, secret or artifact changes (no content) |
| `delbert.req.<t>.<a>.effective` | agent to Core, request/reply | Fetch the signed effective policy (`{token, version}` or `{error}`); payload is the agent's proof |
| `delbert.report.<t>.<a>` | agent to Core | `{proof, report}`; stored as the latest report of the agent |
| `delbert.proxy.<s>.relay`, `.agents`, `.report`, `.notify` | proxy to Core (and back) | relay of an agent request, the proxy's agent list, forwarded reports (acknowledged), "refresh" hint; see [PROXY.md](PROXY.md) |

Tenant and agent names contain no dots, so they are safe subject tokens.

Security layers: (1) NATS requires TLS with a client certificate issued by the Delbert CA; (2) an **authorization callout** served by the Core (`bus_auth.rs`) reads the identity from the certificate, checks that it is still the one on record and returns a short-lived user JWT that confines the connection to its own subjects (below); (3) every request and report carries a proof (`delbert_pki::authn`: Ed25519 over kind, tenant, agent, timestamp, nonce and the hash of the canonical body) checked against the certified public key, valid for 60 seconds; (4) policies are signed; (5) secrets are encrypted to the target agent.

| Who | May publish | May subscribe |
|-----|-------------|---------------|
| agent `t/a` | `delbert.req.t.a.effective`, `delbert.req.t.a.renew`, `delbert.report.t.a` | `delbert.notify.t.a`, `_INBOX.t.a.>` (the agent uses that inbox prefix) |
| the Core | `delbert.notify.*.*`, `_INBOX.>` | `delbert.req.*.*.effective`, `delbert.req.*.*.renew`, `delbert.report.*.*` |

Anything else is refused by the NATS server (`Permissions Violation`). A certificate whose key is not the one on record (deleted agent, rotated key, forged name) is not authorized at all. Not done: encryption of the callout messages with an xkey (they travel inside the TLS-protected NATS connection), immediate disconnection on revocation (it takes effect within `DELBERT_NATS_SESSION_SECS`).

## Enrollment

1. An administrator creates an enrollment key (`POST .../enrollment-keys`); the installer receives the key, the Core URL and the CA certificate.
2. `delbert-agent enroll` (or `run` with the same settings in the environment) generates an Ed25519 identity key and an age key on the host, sends the CSR and the age public key over HTTPS (trusting only the provided CA), and stores certificate, CA, signing keys and metadata under `identity/` (private keys 0600).
3. The Core chooses the certificate subject itself (`CN=<agent>`, URI `urn:delbert:agent:<tenant>:<agent>`), counts the use, and audits the enrollment. A used-up, expired, revoked or unknown key all answer 401. An agent that is already enrolled answers 409 until it is deleted.
4. **Revocation.** Deleting an agent refuses its requests, reports and downloads at once, and NATS stops authorizing it: its open connection ends when its session expires (at most `DELBERT_NATS_SESSION_SECS`), and it cannot reconnect.
5. **Renewal with key rotation.** When less than a third of its certificate's life is left (or `DELBERT_RENEW_BEFORE_SECS`), the agent generates a NEW key and a CSR and sends them on `delbert.req.<t>.<a>.renew`, proven with the current key. The Core certifies the new key, keeps the previous one valid only until a request signed with the new one is seen (a lost reply never locks an agent out), and audits `agent.renew`. The agent installs key and certificate atomically (interrupted installs are completed at start), then reconnects. Renewals are at least an hour apart.

## Secrets and artifacts

- A policy lists the secret names it needs (`spec.secrets`); values live only in the secret store, sealed with the Core key. When a policy is issued the Core decrypts them and encrypts each to the target agent's age key. The agent decrypts at apply time and exposes them to templates as `secrets.*`; they are never logged, reported or audited. A missing secret is reported in `conflicts`.
- `artifact://<name>` references are pinned: the signed policy carries the SHA-256 and size of the version in use, the agent downloads it over HTTPS by hash, verifies it, keeps it in a content-addressed cache and refuses any other content. A missing artifact leaves out the resource that needs it (and its dependents). Changing an artifact or a secret bumps the policy version.

## Database

Migrations run as the schema owner. The Core runs as a login role that is a member of `delbert_app`, which can read and write everything except `UPDATE`/`DELETE`/`TRUNCATE` on `audit_events` and `policy_versions`. Create the login role yourself (development: `deploy/dev/postgres-init.sql`).

## Behaviour worth knowing

- Policies are validated on upload (schema, resource rules, `metadata.tenant` must match the URL). `target.when` is rejected for now so that a conditional policy never applies everywhere by mistake.
- A policy targets an agent when `target.groups` is empty or intersects the agent's groups.
- `effective` ids are namespaced `<policy>/<resource id>`. The version of the signed policy increases only when the compiled content changes, so repeated pulls are idempotent and agents can apply their anti-rollback rule.
- Conflicts follow [ABSTRACT.md](ABSTRACT.md) §3: identical declarations merge; different ones are resolved by the strategy chain; unresolved ones are left out (together with their dependents) and reported in `conflicts`. Only `priority` and `error` are implemented.
- Every write, login (including failures) and every new issued version is appended to the hash-chained audit trail inside the same transaction.
