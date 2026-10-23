# Delbert - Roadmap

Status per functional area, from [SCOPE.md](SCOPE.md) and [DESIDERATA.md](DESIDERATA.md).

| Item | Status | Date |
|------|--------|------|
| Architecture abstract | complete | 2026-10-23 |
| Scope and desiderata documents | complete | 2026-10-23 |
| NATS scale and failure-mode test (JetStream persistence, leaf nodes, per-agent permissions) | to-do | 2026-10-23 |
| Wire format: effective policy JSON + JCS + JWS(EdDSA), signing and verification | complete | 2026-10-23 |
| Wire format: per-agent field encryption of `sensitive` values (HPKE/age) | to-do | 2026-10-23 |
| Core: compile policies per endpoint and sign them (`core` mode) | complete | 2026-10-23 |
| Core: REST API for tenants, agents, policies, effective policy ([API.md](API.md)) | partial | 2026-10-23 |
| Core: audit hash chain writer and verification | complete | 2026-10-23 |
| Core: OpenAPI/Swagger (utoipa) | complete | 2026-10-23 |
| Core: DELETE for tenants, pagination | to-do | 2026-10-23 |
| Core: local users, customizable RBAC, sessions | complete | 2026-10-23 |
| Core: SSO (OIDC/SAML), LDAP/AD, MFA, login throttling/captcha, per-tenant role scoping | to-do | 2026-10-23 |
| Core: least-privilege DB role (no UPDATE/DELETE on audit and policy versions) | complete | 2026-10-23 |
| Core: signed anchors for the audit chain, SIEM export, retention | to-do | 2026-10-23 |
| Conflicts: `specificity` strategy, per-policy/resource overrides, resolution records, impact preview | to-do | 2026-10-23 |
| Core: evaluate `target.when` (restricted expression language) | to-do | 2026-10-23 |
| Agent: daemon with NATS pull, notifications, reports, cached policy | complete | 2026-10-23 |
| Proxy / relay: local callout, request relay with cache, report store-and-forward, enrollment relay, artifact cache ([PROXY.md](PROXY.md)) | complete | 2026-10-23 |
| Proxy: certificate renewal, high availability (shared queue), rate limits, leaf-node transport option | to-do | 2026-10-23 |
| Per-action audit events from agents (the report queue is a state view, not an event log) | to-do | 2026-10-23 |
| Core API over HTTPS (axum-server/rustls) | complete | 2026-10-23 |
| Onboarding: PSK + CSR enrollment, internal CA, mTLS to NATS, signed request/report proofs | complete | 2026-10-23 |
| NATS per-agent subject permissions (auth callout) | complete | 2026-10-23 |
| Auth callout hardening: xkey encryption of the callout messages, immediate disconnect on revocation | to-do | 2026-10-23 |
| Certificate renewal with key rotation, revocation effective at NATS (session expiry) | complete | 2026-10-23 |
| CRL/OCSP for the HTTPS endpoints, CA rotation and intermediate CAs for Proxies | to-do | 2026-10-23 |
| Secrets: per-agent age encryption, write-only store, sealed at rest | complete | 2026-10-23 |
| Secrets: rotation of the Core secrets key, external KMS/Vault | to-do | 2026-10-23 |
| Artifacts: Core store, SHA-256 pinning, verified download by agents | complete | 2026-10-23 |
| Artifacts: S3-compatible store (Garage) for large files, retention | to-do | 2026-10-23 |
| Service verb: test on a systemd host (container run covers everything else) | to-do | 2026-10-23 |
| Containers: end-to-end run in Podman (Core + 2 agents) | complete | 2026-10-23 |
| Agent: trusted-key distribution at onboarding, key rotation | to-do | 2026-10-23 |
| Conflict handling: design (strategies, resource keys, resolution records) | complete | 2026-10-23 |
| Conflict handling: implementation and impact preview | to-do | 2026-10-23 |
| Decide PKI backend (rcgen vs OpenSSL wrapper) after effort estimate | to-do | 2026-10-23 |
| Policy format: declarative YAML | complete | 2026-10-23 |
| YAML resource schema: verb vocabulary and structure draft ([POLICY.md](POLICY.md)) | partial | 2026-10-23 |
| YAML resource schema: JSON Schema generation and typed validation (5 of ~14 verbs) | partial | 2026-10-23 |
| Phase 1 delivery: Linux + container agent | to-do | 2026-10-23 |
| Phase 2: Windows study (ACL, SCM, registry, packages, reboots) | to-do | 2026-10-23 |
| Policy signing design (Ed25519, `core`/`external` modes, anti-rollback) | complete | 2026-10-23 |
| Policy signing implementation | to-do | 2026-10-23 |
| `command` resource design (local allowlist, no shell, idempotency guard) | complete | 2026-10-23 |
| `command` resource implementation | to-do | 2026-10-23 |
| Windows agent approach (service, registry, DSC) | to-do | 2026-10-23 |
| Workspace skeleton: policy, Core, Agent crates | complete | 2026-10-23 |
| Workspace skeleton: Proxy crate | complete | 2026-10-23 |
| Workspace skeleton: Operator crate (Kubernetes, kube-rs) | to-do | 2026-10-23 |
| Agent: check/apply for `file`, `copy`, `line_in_file` (local YAML mode) | complete | 2026-10-23 |
| Agent: `template`, `package` (apt/dnf/zypper/apk), `service` (systemd) | complete | 2026-10-23 |
| Agent: package `state: latest`, artifact SHA-256 pinning, `get_url`, `user`/`group`, `sysctl`, `cron`, `block_in_file`, `command`, containers | to-do | 2026-10-23 |
| Agent: accept only signed effective policies (replace local YAML mode in production) | to-do | 2026-10-23 |
| Core: audit hash chain writer, policy CRUD API, OpenAPI (utoipa) | to-do | 2026-10-23 |
| RBAC v2 design: tenant-scoped roles, `resource:action` permissions, optional per-tenant four-eyes approval ([RBAC.md](RBAC.md)) | complete | 2026-10-23 |
| RBAC v2: tenant-scoped assignments, `resource:action` permissions, built-in roles, delegated tenant administration (migration `0010`) | complete | 2026-10-23 |
| RBAC v2: approval workflow (`approval_required`, `active_version`, `policy_version_events`, migration `0011`) | complete | 2026-10-23 |
| Approval: version diff, impact preview before approving, emergency path | to-do | 2026-10-23 |
| Auth hardening: cookie sessions + CSRF, TOTP MFA, login throttling/Turnstile, scoped API tokens | to-do | 2026-10-23 |
| Core API for the UI: audit search/export, pagination and filters, policy versions/diff/schema, tenant delete, SSE status | to-do | 2026-10-23 |
| Frontend design ([FRONTEND.md](FRONTEND.md)) | complete | 2026-10-23 |
| Frontend M0 skeleton (Next.js BFF, generated client, login, i18n, Playwright smoke) | to-do | 2026-10-23 |
| Frontend M1-M4 (read-only, operations, governance, hardening) | to-do | 2026-10-23 |
| `git init`, CI pipeline (tests, clippy, image build) | to-do | 2026-10-23 |
| Audit browse and export API (`GET /v1/audit`, `/v1/audit/export`) | complete | 2026-10-23 |
| Artifact storage outside PostgreSQL: local directory and S3-compatible (Garage verified) | complete | 2026-10-23 |
| Artifacts: streaming upload (multipart/range) beyond 64 MiB, garbage collection of unreferenced objects, retention | to-do | 2026-10-23 |
| Artifacts: lifecycle with Garage in compose and Kubernetes manifests | to-do | 2026-10-23 |
| Auth hardening: cookie sessions + CSRF, TOTP MFA, login throttling (migration `0013`) | complete | 2026-10-23 |
| Auth: scoped API tokens / service accounts | to-do | 2026-10-23 |
| Auth: SSO via OIDC (Keycloak, Microsoft Entra ID, ...): authorization code + PKCE, group/claim to (role, scope) mapping, break-glass local account; LDAP/AD later | to-do | 2026-10-23 |
| Auth: captcha (Turnstile) after repeated failures, WebAuthn, password breach check | to-do | 2026-10-23 |
| Configuration file for Core and Proxy (TOML/YAML + env override, validated, `--check`), replacing the growing list of environment variables | to-do | 2026-10-23 |
| Content repository on the Core's server (files, policies, configs): the Core reads a local repo, detects changes, records diffs and versions the content; managed from the web UI | to-do (design first) | 2026-10-23 |
| Key rotation beyond agent certificates (which renew with key rotation): policy signing key (trusted-keys overlap), internal CA, NATS issuer key, secrets age key, proxy certificate | to-do | 2026-10-23 |
