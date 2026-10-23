# Delbert - Changelog

## 2026-10-23

### Design
- Added `RBAC.md` (tenant-scoped roles, `resource:action` permissions, built-in roles, optional per-tenant four-eyes approval with an active-version pointer, cookie sessions, MFA, throttling, API tokens, audit browsing), `FRONTEND.md` (Next.js + Tailwind with a backend-for-frontend, generated client, screens, milestones) and `STATUS.md` (state, how to run, decisions, limits, working agreements for the next session).

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
