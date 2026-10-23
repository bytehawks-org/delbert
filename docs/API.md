# Delbert - Core API

JSON over HTTP, served by `delbert-core` (Axum). Interactive documentation: `/swagger-ui` and `/openapi.json` (generated with utoipa; disable with `DELBERT_API_DOCS=false`). Everything except `/healthz`, `POST /v1/auth/login` and the documentation requires `Authorization: Bearer <session token>` and the permission listed below. Agents do not use this API: they talk to the Core over NATS ([ABSTRACT.md](ABSTRACT.md) §2).

## Configuration (environment)

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
| `DATABASE_URL` | PostgreSQL connection of the runtime role (member of `delbert_app`, see Database) (required) |
| `DATABASE_MIGRATE_URL` | Schema owner connection used only to run migrations; defaults to `DATABASE_URL` |
| `DELBERT_BOOTSTRAP_ADMIN_PASSWORD` | Creates user `admin` (role `admin`) when the database has no users; at least 12 characters |
| `NATS_URL`, `NATS_USER`, `NATS_PASSWORD` | Message bus; without it there are no notifications and agents cannot pull |
| `DELBERT_BIND` | Listen address, default `0.0.0.0:8080` |
| `DELBERT_SIGNING_KEY_FILE`, `DELBERT_SIGNING_KID` | Policy Signing Key (base64 seed from `delbert-sign keygen`) and its key id; without them no policy can be issued |
| `DELBERT_POLICY_TTL_SECS` | Validity of issued policies, default 86400 |
| `DELBERT_CONFLICT_STRATEGY` | Comma-separated chain, `priority`, `error` (default `error`); `error` is always the implicit last resort |
| `DELBERT_API_DOCS` | `false` disables Swagger UI and `/openapi.json` |

## Authentication and RBAC

- `POST /v1/auth/login` with `{username, password}` returns a session token valid 8 hours (Argon2id passwords; only the SHA-256 of the token is stored). `POST /v1/auth/logout` revokes it; changing a password or deactivating a user revokes their sessions.
- A role is a list of permissions: `*`, `read`, `tenants:write`, `agents:write`, `policies:write`, `secrets:write`, `proxies:write`, `effective:issue`, `audit:read`, `users:admin`. Built-in roles: `admin` (`*`), `operator` (`read`, `agents:write`, `policies:write`, `effective:issue`), `auditor` (`read`, `audit:read`). Custom roles can be created, changed and deleted (not while assigned); built-ins are immutable.
- The last active holder of `*` cannot be deleted, deactivated or demoted.
- Not done yet: SSO (OIDC/SAML), LDAP/AD, MFA, login throttling, per-tenant role scoping ([ROADMAP.md](ROADMAP.md)).

## Endpoints

| Method and path | Permission | Purpose |
|-----------------|------------|---------|
| `GET /healthz` | public | Liveness and database reachability |
| `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/me` | public / any session | Session handling |
| `GET/POST /v1/users`, `PUT/DELETE /v1/users/{username}` | `users:admin` | Users (password, active, roles) |
| `GET/POST /v1/roles`, `PUT/DELETE /v1/roles/{name}` | `users:admin` | Roles |
| `POST /v1/tenants`, `GET /v1/tenants` | `tenants:write` / `read` | Tenants |
| `POST/GET /v1/tenants/{t}/agents` | `agents:write` / `read` | Create / list agents (`name`, `groups`; list includes the last report) |
| `PUT/DELETE /v1/tenants/{t}/agents/{a}` | `agents:write` | Change groups / delete |
| `POST/GET /v1/tenants/{t}/enrollment-keys`, `DELETE .../{id}` | `agents:write` / `read` | Enrollment keys: expiring, limited uses, revocable; the key is shown once |
| `POST/GET /v1/proxies`, `DELETE /v1/proxies/{name}` | `proxies:write` / `read` | Branch-office proxies ([PROXY.md](PROXY.md)): create (one-time key), list (agents, last seen), delete (refused while agents are assigned) |
| `POST /v1/proxies/enroll` | the proxy\'s one-time key | Proxy enrollment: CSR in, certificate (client and server) out |
| `POST /v1/proxy/enroll-agent`, `GET /v1/proxy/{site}/artifacts/{tenant}/{name}` | proxy proof | Used by a proxy for its agents: enrollment relay, artifact fetch |
| `POST /v1/enroll` | the enrollment key | Agent enrollment: CSR + age public key in, certificate + CA + signing keys out |
| `PUT/GET /v1/tenants/{t}/secrets[/{name}]`, `DELETE` | `secrets:write` / `read` | Tenant secrets: write-only, the list shows names only |
| `PUT /v1/tenants/{t}/artifacts/{name}`, `GET .../artifacts` | `policies:write` / `read` | Immutable artifact versions (16 MiB at most); same content is a no-op |
| `GET /v1/agent/{t}/{a}/artifacts/{name}?sha256=` | agent proof | Download by hash, authenticated with `Authorization: Delbert-Agent <base64 proof>` |
| `POST/GET /v1/tenants/{t}/policies` | `policies:write` / `read` | Upload a policy YAML (`{"yaml": "..."}`, new immutable version) / list |
| `GET/DELETE /v1/tenants/{t}/policies/{name}` | `read` / `policies:write` | Latest version / deactivate (soft delete, history kept) |
| `GET /v1/tenants/{t}/agents/{a}/effective` | `effective:issue` | Compile the policies targeting the agent, resolve conflicts, sign: `{token, version, conflicts}` |
| `GET /v1/audit/verify` | `audit:read` | Recompute the audit hash chain: `{events, first_bad}` |

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
