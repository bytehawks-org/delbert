# Delbert - Changelog

## 2026-10-24

### Roadmap cleanup
- `ROADMAP.md` checked against the code: rows that were done but still marked to-do (policy signing, signing-key distribution and rotation, cookie sessions/MFA/throttling, OIDC SSO, CA rotation, secrets-key rotation, proxy renewal, S3 artifact store, per-agent secret encryption) are now complete or split into done and remaining parts; duplicates removed. Newly recorded gaps: the CA is not behind a trait yet (rcgen only), tenant DELETE and general list pagination are missing.

### Frontend M3, fifth slice: content sources
- `web/`: **Content** (`/content`, menu entry for `content:read` globally or in a tenant): sources with owner, last sync and error, create/edit (git or directory, branch, sub-directory, owning tenant, poll interval, prune, enabled, write-only access token that is kept when left empty and can be removed), **Sync now** with the result (status, errors, changes with unified diffs) and delete by typing the name. `/content/{name}` shows the sync history and, per sync, the changes and diffs. A failed fetch is reported as an alert and the source row turns to "failing" (the Core records the last error). Tenant users see only their tenant's sources, read-only unless they hold `content:write` / `content:sync`.
- `compose.e2e.yaml` sets `DELBERT_CONTENT_ALLOW_TENANT_GIT=true` (development stack only) so the scenario for tenant-owned sources can create one; the Core keeps it off by default. Playwright: 19 scenarios in total pass. Successful git syncs with diffs are not covered by the web tests (no git server in the stack); they are covered by `tests/content.rs` and the Forgejo check.

### Frontend M3, fourth slice: single sign-on providers
- `web/`: **Single sign-on** (`/sso`, menu entry for `sso:read`): OIDC providers with issuer, client id, write-only client secret (kept when the field is left empty on edit, never rendered back), scopes, groups claim, "refuse sign-in without a mapped role", enabled flag, and the group to (role, tenant or global) mapping editor; the redirect URI to register is shown; a **Test** button runs the Core's discovery check; delete by typing the name. The pass-through gained the provider calls. Playwright: 17 scenarios in total pass (the issuer in the test is unreachable on purpose: the test button reports a failure instead of breaking the page).

### Frontend M3, third slice: tenant access and approval
- `web/`: the tenant page gained an **Access and approval** card: the four-eyes approval switch (`tenants:settings`) and the tenant's role assignments (assign, edit, remove; only roles that are not global-only are offered; the Core still limits a delegated administrator to what they hold). The pass-through gained `PUT .../settings` and `PUT .../assignments/{user}`. Playwright: 16 scenarios in total pass.

### Frontend M3, second slice: profile
- `web/`: **Profile** (`/profile`, linked from the signed-in name): TOTP set-up (secret and `otpauth://` URI shown, confirmation with a code, recovery codes shown once) and disabling (password plus code); the user's sessions with revocation of the others; API tokens (name, scope global or one tenant, lifetime, permissions limited to what the user holds in that scope, token shown once, revoke). No QR code is rendered: it would add a dependency, and the secret can be typed into any authenticator. The pass-through gained `/v1/me/mfa/*`, `/v1/me/tokens` and `/v1/me/sessions`. Playwright: `e2e/profile.spec.ts` (TOTP helper shared in `e2e/totp.ts`); 15 scenarios in total pass.

### Frontend M3, first slice: users and roles
- Core: `GET /v1/permissions` lists every permission and whether it is global-only (same gate as the role list); the UI builds the permission matrix from it instead of hard-coding it. `web/openapi.json` and the generated client regenerated.
- `web/`: **Users** (`/users`: create with an optional first assignment, edit role assignments per tenant or global, activate/deactivate, set password, reset MFA, revoke sessions, delete by typing the name) and **Roles** (`/roles`: built-in roles read-only; custom roles edited in a resource-by-action matrix with a per-resource "all" (`resource:*`); global-only permissions are disabled for tenant-scoped roles). The menu entries appear only for users holding `users:read` / `roles:read` globally; the Core enforces everything regardless. The allow-listed pass-through gained the user and role calls. Playwright: `e2e/governance.spec.ts` (13 scenarios in total pass against the live stack; the pass-through test now uses `/v1/proxies` as its example of a refused call).

### CI
- `.github/workflows/ci.yml`: jobs run in Alpine containers (`rust:1.99-alpine`, `node:22-alpine`, `postgres:17-alpine`; the hosted runner itself stays Ubuntu). The whole workspace test suite and the web build were verified on Alpine/musl locally. Rust job (PostgreSQL 17 service, `nats-server` from Alpine with JetStream, `cargo clippy --workspace --all-targets`, `cargo test --workspace`), web job (`npm ci`, typecheck, production build), image job (Containerfile targets `core`, `agent`, `proxy`, `tools`, `web`; build only, no push). Clippy warnings are reported but not fatal (about 50 existing, none of them errors); `cargo fmt --check` is not enforced because the tree was never formatted with rustfmt (a mass reformat is a separate decision). Not run on GitHub yet.

## 2026-10-23

### Design
- Added `RBAC.md` (tenant-scoped roles, `resource:action` permissions, built-in roles, optional per-tenant four-eyes approval with an active-version pointer, cookie sessions, MFA, throttling, API tokens, audit browsing), `FRONTEND.md` (Next.js + Tailwind with a backend-for-frontend, generated client, screens, milestones) and `STATUS.md` (state, how to run, decisions, limits, working agreements for the next session).

### Authentication hardening
- Migration `0013`. Cookie sessions with CSRF (double-submit token stored hashed), idle timeout, listable/revocable sessions; TOTP MFA with sealed secret, replay protection and recovery codes, optional or mandatory (`DELBERT_MFA_REQUIRED`); login throttling per (user, address), address and user; admin reset of MFA/sessions. Tests in `tests/auth.rs`. See [API.md](API.md).

### Frontend M2
- Policy editor (`/tenants/{t}/policies/new`, `.../{name}/edit`): validates as you type through the new `POST /v1/tenants/{tenant}/policies/validate` (same checks as a save, stores nothing, no audit event), shows the next version number, whether it will be a draft, and a line diff against the live version. Version steps from the policy page (submit, approve, reject, activate, rollback) appear only where role and state allow; the Core still decides. Enrollment keys (create, shown once, revoke), write-only secrets and artifact upload on the tenant page. `GET .../versions/{v}` now includes `approval_required`.
- Mutations from the browser go through `/api/core/...`, an allow-list of the calls the UI makes (everything else is a 404), same-origin only, session added server side. Browser uploads are limited by the Next.js proxy body limit (10 MB by default); use the API for larger artifacts.
- Fix: listing versions or opening one of a policy that was never activated (a draft under approval) failed with a 500.
- Playwright: editor, four-eyes flow with two users, keys/secrets/artifacts, pass-through restrictions (11 scenarios in total).

### Frontend M1
- Read-only views in `web/`: tenants (agents, policies, artifacts, secret names), fleet-wide agent list with state filter and agent detail, policy source with versions and approval history, proxies, audit browser (filters, keyset paging, hash-chain status). Sections a role does not cover show a notice instead of failing. Two more Playwright scenarios (administrator browse; tenant-scoped viewer). Core fix: the audit filters were documented as path parameters in the OpenAPI document; they are now query parameters (`web/openapi.json` regenerated).

### Frontend M0
- `web/`: Next.js 16.4.2 (App Router), React 19.3.1, Tailwind CSS 4.3.3, TypeScript 5.9; backend-for-frontend with the Core session in an encrypted HttpOnly SameSite=Strict cookie (`jose`), `Origin` check on mutations, per-request CSP nonce in `proxy.ts`, login with MFA and SSO callback/exchange, IT/EN (`next-intl`), light/dark/system theme, typed client generated from the Core's OpenAPI (`delbert-core --print-openapi`), dashboard skeleton. Containerfile target `web`, `web` service in `compose.e2e.yaml`, `deploy/kubernetes/web.yaml`. Playwright tests (security headers, login/logout, language/theme, cross-origin refusal, TOTP login) pass against the live stack. See [web/README.md](../web/README.md).

### Rotations (CA, secrets key, proxy certificate, NATS issuer)
- Internal CA rotation with overlap: CA bundles (`delbert-pki::bundle`), in-band announcement (`ca_add`, `ca_remove`, `renew_issued_before` in the signed trust update), agents report trusted CAs and their certificate's issuer, `GET /v1/pki/ca`; enrollment and renewal hand out the bundle. Verified live (announce, switch with forced renewal, retire).
- Secrets-key rotation: `SecretsKeys` (current + old), `GET /v1/secrets/key`, `POST /v1/secrets/reseal` over tenant secrets, TOTP, SSO and git tokens (migration-free).
- Proxy certificate renewal with a new key: `POST /v1/proxies/{site}/renew`, migration `0017` (previous key), callout and proofs accept the previous key; the proxy renews itself, installs atomically and restarts.
- NATS issuer switch procedure verified live. New permission `keys:write`. `compose.e2e.yaml` takes the CA, leaf certificates, NATS CA file and issuer from `E2E_*` variables.
- Agent and proxy enrollment accept a CA bundle from the Core as long as it contains every CA they were given.

### Guides and deployment files
- `docs/quickstart.md` (verified from scratch: keys, stack, tenant, artifact, policy, enrollment, convergence, change, drift, audit) and `docs/install.md` (components, keys, PostgreSQL, NATS, Core configuration, Kubernetes/K3s, Podman, agents with systemd, proxy, integrations, backup/restore, upgrades, troubleshooting, known limits).
- `deploy/kubernetes/` (kustomization: namespace, NATS StatefulSet, Core Deployment; not run on a cluster yet), `deploy/systemd/` (agent unit and environment example), `examples/quickstart.yaml`, Containerfile targets `tools` (delbert-pki, delbert-sign) and the existing images documented.

### Signing-key rotation
- Signed policies can carry a `trust` update (keys to add, key ids to remove) that agents apply to `trusted-keys.txt` after verifying the signature, with fail-closed rules; agents report their trusted key ids; `GET /v1/signing/keys` shows readiness; `DELBERT_SIGNING_PUBLISH_KEYS` / `DELBERT_SIGNING_RETIRE_KEYS`. Procedure and the state of every other rotation in [ROTATION.md](ROTATION.md). Verified live with a Core and an agent in containers; `compose.e2e.yaml` now takes the signing key from `${E2E_SIGNING_KID}` and mounts `./dev` at `/keys`.

### Content sources
- Migration `0016`; `content.rs`: directory and git sources (platform- or tenant-owned), whole-snapshot validation, diffs, apply through the normal paths, ownership (409 in the API), prune, history, background poller. Policy/artifact writes were factored into `store_policy_version` / `store_artifact`. Tests in `tests/content.rs`, and against Forgejo 11 with a private repo + token. The container image now carries `git`.
- Build cache: `[profile.dev] debug = "line-tables-only"` (the cargo volume had grown to 36 GB; now ~2 GB).

### Single sign-on (OIDC)
- Migration `0015`; providers, group mappings, authorization code + PKCE through `openidconnect` 4 (rustls, no OpenSSL), one-time code exchange, no account takeover by name, `DELBERT_LOCAL_LOGIN=admins` for break-glass. Tested with a mock provider (`tests/sso.rs`: PKCE, nonce, replay, mapping, local-name clash) and end to end against Keycloak 26.4 in Podman.

### Configuration file and content sources
- Core configuration file (TOML) layered under the environment, strict keys, `--check-config` (`config.rs`, example in `deploy/`). Proxy to follow.
- Design of repository-backed content (`CONTENT.md`): `directory` and `git` sources (local Forgejo/Gitea component or a public remote), snapshot validation, diffs, versions, ownership.

### API tokens
- Migration `0014`: scoped, expiring, revocable tokens that never exceed their owner (`tests/auth.rs`).

### Artifact storage
- Artifact content no longer lives in PostgreSQL (migration `0012` drops `artifacts.content`; development databases must re-upload). New `blobs` module on `object_store` 0.12 (Apache-2.0): local directory or S3-compatible, keys `artifacts/<tenant id>/<sha256>` (content-addressed, idempotent). Content is written before its metadata row; downloads are streamed and hashed on the way out, so a corrupted object aborts instead of being served; the limit rises to 64 MiB. Verified against Garage v2.1.0 in Podman (`tests/blobs.rs` runs against S3 when `S3_TEST_*` is set). See [API.md](API.md).

### Audit API
- `GET /v1/audit` (filters, keyset pagination, tenant scoping) and `GET /v1/audit/export` (NDJSON with hashes, self-audited). Tests in `tests/audit_api.rs`.
- New crate `delbert-fs`: the crash-safe write helper is now shared; proxy queue/allow-list/caches, agent identity files, artifact staging and the PKI CLI use it too. Private keys are no longer briefly readable (created 0600 instead of chmod after write).

### Hardening
- `unsafe_code = "forbid"` workspace-wide (there was no `unsafe` already; now enforced by the compiler).
- Crash-safe file replacement for `file`/`copy`/`template`/`line_in_file` and the agent state/cache: the temporary file used a fixed, predictable name, was created with default permissions (secret content readable before `chmod`) and was never fsynced. Now `fsutil::replace_file`: unique name created exclusively with mode 0600, `fchown` then `fchmod`, `fsync`, atomic `rename`, directory `fsync`, stale temporaries swept.
- Signed policy verification also rejects `expires_at <= issued_at`. Verified unchanged: the signed payload is the JCS-serialized effective policy (never raw YAML); signature, target, expiry/validity window and anti-rollback (version lower than the last applied) are checked before `Ok` is returned.

### RBAC v2 (part 1)
- Migration `0010`: role `scope`, `user_roles.tenant_id`, new `resource:action` permissions (custom v1 roles are mapped), built-in roles `platform-admin` (was `admin`), `tenant-admin`, `operator`, `approver`, `auditor`, `viewer`.
- Authorization is tenant-aware: `CurrentUser::tenant()` resolves the tenant and checks the permission in scope (404 when the caller has no role there); global-only permissions never come from a tenant-scoped assignment; `GET /v1/tenants` lists only reachable tenants.
- Users carry `assignments` (`role`, optional `tenant`) instead of `roles`; `/v1/me` shows assignments and per-tenant permissions; delegated `GET/PUT /v1/tenants/{t}/assignments`, limited to what the delegate holds. Breaking change of the API (unreleased project). Tests: scope matrix and delegation (`tests/rbac.rs`). See [API.md](API.md), [RBAC.md](RBAC.md).

### RBAC v2 (part 2): policy approval
- Migration `0011`: `tenants.approval_required`, `policies.active_version`, append-only `policy_version_events`. The compiler now uses the active version, not the latest.
- Per-tenant optional four-eyes: upload makes a draft, then `submit` → `approve`/`reject` (author and submitter excluded, no override) → `activate`; `rollback` to a previously approved version needs `policies:approve`. Without approval an upload goes live at once. Settings endpoint; switching the control off needs a global grant and no pending versions. Version list/detail with events. Tests in `tests/approval.rs`.

### Code
- Cargo workspace (Rust edition 2024) with `delbert-policy`, `delbert-core`, `delbert-agent`.
- `delbert-policy`: typed YAML model (`file`, `copy`, `line_in_file`, `package`, `service`), JSON Schema, validation (duplicate ids, single verb, dependencies, handlers, cycles, paths, modes) with 6 tests.
- `delbert-core`: Axum `/healthz`, SQLx migration `0001` (tenants, append-only `audit_events` enforced by triggers).
- `delbert-agent`: engine (`check`/`apply`, dependency ordering, handlers, verify-after-apply, skip on failed dependency) with `file`, `copy`, `line_in_file`; atomic writes preserving mode/owner; CLI `check`/`apply` with `--root` sandbox and exit codes 0/1/2; 8 tests; `examples/app-baseline.yaml`.
- `delbert-policy`: intra-policy conflict detection by resource key (path, package/service name; handlers exempt), `..` rejected in paths.
- **Proxy** (`delbert-proxy`, new; `delbert-natsauth`, new shared crate): branch-office relay as an application-level proxy, so the site network never connects to the Core. Core side: `proxies` table (migration `0009`), admin API and one-time enrollment (certificate usable as client and server), agents enrolled through a proxy are assigned to it, relay/agents/report subjects with acknowledgements, forwarded reports judged as of the proxy's reception time and never overwriting newer ones, artifact fetch for proxies, callout rules for proxy certificates, new permission `proxies:write`. Proxy side: local callout from a disk-persisted allow-list, request relay with proof checks and cached answers, report queue (latest per agent), enrollment relay, artifact cache verified by hash. Verified in containers on an isolated network, including a cut link ([docs/PROXY.md](docs/PROXY.md), [docs/TESTING.md](docs/TESTING.md)).
- NATS clients (proxy, agents) ping every 10 s: recovery after an outage dropped from 91 s to 9 s; an agent without a policy retries after 5 s.
- Disk: dev builds use `CARGO_INCREMENTAL=0` (the cache volume had grown to 29 GB).
- Fixed an intermittent failure of the test suite on a fresh PostgreSQL cluster: migration `0005` created the `delbert_app` role with a check-then-create that races when two databases of one cluster migrate together; it now creates and tolerates "already exists". (`0005` was edited in place because the project is unreleased: databases created before this change must be recreated.)
- NATS authorization callout (`bus_auth.rs`): identity from the client certificate, checked against the key on record, confined permissions per agent and for the Core, user JWT with an expiry (`DELBERT_NATS_SESSION_SECS`), verified against a real NATS server; `deploy/dev/nats-callout.conf`; `delbert-pki nats-issuer`.
- Certificate renewal with key rotation (`delbert.req.<t>.<a>.renew`, migration `0008` keeps the previous key until the new one is used), atomic key/certificate install with crash recovery, automatic reconnect, minimum one hour between renewals; revocation takes effect at NATS when the session expires. Agents use a per-agent inbox prefix; `probe` example to test the permissions; fixed the callout reading the certificate from `verified_chains`.
- `delbert-pki` (new): internal CA, CSR signing (subject and identity URI chosen by the Core, Ed25519 only, proof of possession verified), server/client certificates with Authority Key Identifier, agent request proofs (`authn`), `delbert-pki` CLI.
- Enrollment: `enrollment_keys` (hashed, expiring, limited uses, revocable), `POST /v1/enroll`, `delbert-agent enroll` and unattended enrollment from `run`; identity stored under `identity/` (keys 0600); agent deletion revokes.
- mTLS: NATS requires client certificates from the Delbert CA; Core and agents connect with them; Core API served over HTTPS. Requests and reports carry signed proofs checked against the certified public key (60 s window).
- Secrets: write-only store sealed with the Core's age key, per-agent re-encryption in the effective policy, decrypted on the agent and exposed to templates as `secrets.*`; never logged or audited. Artifacts: immutable versions, pinned by SHA-256 in the signed policy, downloaded by hash over HTTPS with an agent proof, verified and cached; missing artifacts/secrets are reported in `conflicts`.
- `docs/API.md`, `docs/TESTING.md`, `compose.e2e.yaml`, `deploy/dev/nats-tls.conf` updated; new permission `secrets:write`.
- `delbert-core`: users, roles and sessions (Argon2id, hashed session tokens, `*` safeguard, custom roles), static admin token removed; OpenAPI + Swagger UI (utoipa); typed API responses; least-privilege runtime DB role (`delbert_app`, migrations `0004`/`0005`) with separate migration connection; NATS bus (notifications, request/reply policy pull, reports into `agent_reports`); graceful shutdown. Tenant/agent names restricted to NATS-safe tokens.
- `delbert-agent`: `run` daemon (pull over NATS, verify, apply, report; periodic and notification-driven cycles; cached policy while the Core is down; graceful shutdown); `package` refreshes the index once and retries a failed install.
- `Containerfile` (core and agent images), `compose.e2e.yaml`, `docs/TESTING.md`: end-to-end run with Core + two agents in Podman; fixes found by it (apt index refresh, SIGTERM handling).
- `delbert-core`: library + binary; REST API with admin bearer token (constant-time compare, required at startup), migration `0002` (agents, policies, immutable `policy_versions`), policy compiler (id namespacing, merge of identical resources, conflict strategies `priority`/`error`, dependents of dropped resources blocked, variable conflicts), signing of effective policies, hash-chained audit with advisory-lock serialization and `verify`; 9 unit + 4 API integration tests against PostgreSQL; verified end to end (Core API → signed policy → agent apply, tampering and wrong-agent rejected).
- `docs/API.md` added; `compose.yaml` passes admin token, signing key and conflict strategy to the Core.
- `delbert-wire` (new): `EffectivePolicy`, JCS canonicalization (own implementation, tested incl. UTF-16 key order), compact JWS EdDSA signing/verification (rejects tampering, wrong key, `alg: none`, unknown kid, non-canonical payload, expiry, wrong agent, rollback, invalid resources); `delbert-sign` CLI.
- `delbert-agent`: `check-signed` / `apply-signed` with trusted keys file and anti-rollback state file; `template` (MiniJinja, strict undefined, rendered on the agent, `vars` + `facts`), `package` (apt/dnf/zypper/apk), `service` (systemd; `restarted`/`reloaded` only on handlers); `Runner` abstraction (argv only, no shell; refused in sandbox roots); verified with real `apt` in a throwaway container.
- `delbert-policy`: `template` verb, package/service name validation (no option injection), service rules.
- `compose.yaml` for Podman development (PostgreSQL 17, RabbitMQ 4, Core built in a `rust:1` container).

### Design changes
- NATS JetStream is now the only message bus (RabbitMQ and the `MessageBus` trait removed); `compose.yaml` runs NATS instead of RabbitMQ.
- YAML is authoring-only; agents receive per-endpoint effective policies as canonical JSON (JCS), Ed25519/JWS-signed, with sensitive fields encrypted per agent; CBOR/COSE kept as alternative.
- Conflict handling between policies: resource keys, strategy chain (`error`, `specificity`, `priority`, `merge`), per-resource/policy/global settings and resolution records, impact preview (see `ABSTRACT.md` §3, `POLICY.md`).

### Documentation
- Rewrote `ABSTRACT.md`: selectable RabbitMQ/NATS bus, internal PKI (rcgen with OpenSSL fallback), "stateless" agent definition, host agent + in-cluster Operator for Kubernetes, SQLx instead of SeaORM, utoipa for OpenAPI, new PKI and NIS2 audit sections.
- Aligned `CLAUDE.md`: new stack, RBAC/multi-tenant/audit features, control plane production limited to Kubernetes/K3s, agent packaged natively; fixed typos.
- Added execution principle (server never executes commands, only agents do) and YAML policy format to `ABSTRACT.md`, `CLAUDE.md`, `SCOPE.md`, `ROADMAP.md`.
- Defined policy signing (Ed25519, `core`/`external` modes, versioned, expiring) and the restricted `command` resource; chose `serde_yaml_ng`, `schemars`, `ed25519-dalek`.
- Added `POLICY.md`: draft v0.1 YAML policy format with an Ansible-inspired verb subset (Linux + containers), MiniJinja templating, handlers, check/apply contract; phased plan with Windows deferred to phase 2 and its study items.
- Populated `SCOPE.md`, `DESIDERATA.md`, `ROADMAP.md`.
