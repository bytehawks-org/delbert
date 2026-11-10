# Delbert - Roadmap

Status per functional area, from [SCOPE.md](SCOPE.md) and [DESIDERATA.md](DESIDERATA.md).

| Item | Status | Date |
|------|--------|------|
| Architecture abstract | complete | 2026-10-23 |
| Scope and desiderata documents | complete | 2026-10-23 |
| NATS scale and failure-mode test (JetStream persistence, leaf nodes, per-agent permissions) | to-do | 2026-10-23 |
| Wire format: effective policy JSON + JCS + JWS(EdDSA), signing and verification | complete | 2026-10-23 |
| Wire format: per-agent encryption of secrets (age; secrets never appear in policies) | complete | 2026-10-24 |
| Core: compile policies per endpoint and sign them (`core` mode) | complete | 2026-10-23 |
| Core: REST API for tenants, agents, policies, effective policy ([API.md](API.md)) | partial | 2026-10-23 |
| Core: audit hash chain writer and verification | complete | 2026-10-23 |
| Core: OpenAPI/Swagger (utoipa) | complete | 2026-10-23 |
| Core: tenant archive (`DELETE /v1/tenants/{t}`, migration `0018`) | complete | 2026-10-24 |
| Core: pagination of list endpoints (audit already keyset-paged) | to-do | 2026-10-24 |
| Core: local users, customizable RBAC, sessions | complete | 2026-10-23 |
| Core: least-privilege DB role (no UPDATE/DELETE on audit and policy versions) | complete | 2026-10-23 |
| Audit: NDJSON export done; signed anchors for the chain, SIEM connector, retention to-do | partial | 2026-10-24 |
| Conflicts: `priority` and `error` strategies implemented; `specificity`, per-policy/resource overrides, resolution records, impact preview to-do | partial | 2026-10-24 |
| Core: evaluate `target.when` (restricted expression language) | to-do | 2026-10-23 |
| Agent: daemon with NATS pull, notifications, reports, cached policy | complete | 2026-10-23 |
| Proxy / relay: local callout, request relay with cache, report store-and-forward, enrollment relay, artifact cache ([PROXY.md](PROXY.md)) | complete | 2026-10-23 |
| Proxy: certificate renewal (migration `0017`) | complete | 2026-10-24 |
| Proxy: high availability (shared queue), rate limits, leaf-node transport option | to-do | 2026-10-23 |
| Per-action audit events from agents (changed/failed resources, applied/rejected policies; spool, proxy queue, idempotent, hash-chained) | complete | 2026-10-24 |
| Audit events carry the subject, the drift found and the duration (drift correction readable in the trail) | complete | 2026-10-24 |
| Global (platform-owned) artifacts inherited by tenants (tenant first, then platform; `globals:*`; agents move when a shared file changes) | complete | 2026-10-24 |
| Four-eyes approval for changes to shared artifacts and to variables (today authenticated, authorized and audited, but live at once) | to-do | 2026-10-24 |
| Template variables and constants: layers shared, tenant, group, agent; locked constants; resolved by the Core into the signed policy; "render for agent" preview | complete | 2026-10-24 |
| Variables: undefined `vars.x` is caught by the preview, not yet at policy save; inline `copy.content` is not templated | partial | 2026-10-24 |
| "ByteHawks" theme applied to this console (tokens, fonts, logo, sidebar layout) | complete | 2026-10-24 |
| Shared "ByteHawks" theme for all admin dashboards: extract the tokens, fonts and base components (`ui/`, shell, nav) into a package other dashboards import | to-do | 2026-10-24 |
| Agent events: per-agent rate limit is a fixed 1000/hour; configurable limits, event for command output (when `command` exists), UI view of an agent's events | to-do | 2026-10-24 |
| Core API over HTTPS (axum-server/rustls) | complete | 2026-10-23 |
| Onboarding: PSK + CSR enrollment, internal CA, mTLS to NATS, signed request/report proofs | complete | 2026-10-23 |
| NATS per-agent subject permissions (auth callout) | complete | 2026-10-23 |
| Auth callout hardening: xkey encryption of the callout messages, immediate disconnect on revocation | to-do | 2026-10-23 |
| Certificate renewal with key rotation, revocation effective at NATS (session expiry) | complete | 2026-10-23 |
| Internal CA rotation with overlap | complete | 2026-10-24 |
| CRL/OCSP for the HTTPS endpoints, intermediate CAs for Proxies | to-do | 2026-10-23 |
| Secrets: per-agent age encryption, write-only store, sealed at rest | complete | 2026-10-23 |
| Secrets: rotation of the Core secrets key (reseal) | complete | 2026-10-24 |
| Secrets: external KMS/Vault (superseded by the external key and secret providers rows below) | to-do | 2026-10-23 |
| Artifacts: Core store, SHA-256 pinning, verified download by agents | complete | 2026-10-23 |
| Artifacts: retention and garbage collection (S3 store itself is done, see below) | to-do | 2026-10-23 |
| Service verb: test on a systemd host (container run covers everything else) | to-do | 2026-10-23 |
| Containers: end-to-end run in Podman (Core + 2 agents) | complete | 2026-10-23 |
| Conflict handling: design (strategies, resource keys, resolution records) | complete | 2026-10-23 |
| PKI backend: rcgen in use; CA behind the `CertificateAuthority` trait with a conformance suite and `DELBERT_CA_BACKEND` | complete | 2026-10-24 |
| PKI: an OpenSSL backend (only if a deployment needs it; implement the trait, pass `ca::conformance::check`) | to-do | 2026-10-24 |
| Policy format: declarative YAML | complete | 2026-10-23 |
| YAML resource schema: verb vocabulary and structure draft ([POLICY.md](POLICY.md)) | partial | 2026-10-23 |
| YAML resource schema: JSON Schema generation and typed validation (15 verbs: `file`, `copy`, `template`, `line_in_file`, `block_in_file`, `get_url`, `package`, `service`, `container`, `user`, `group`, `cron`, `sysctl`, `mount`, `command`) | partial | 2026-10-24 |
| Phase 1 delivery: Linux + container agent (installers ready; first release tag to do) | partial | 2026-11-10 |
| Phase 2: Windows study (ACL, SCM, registry, packages, reboots): paths, SCM and facts decided and implemented ([WINDOWS.md](WINDOWS.md)); ACL model, registry verb, packages, reboots open | partial | 2026-11-10 |
| Policy signing design (Ed25519, `core`/`external` modes, anti-rollback) | complete | 2026-10-23 |
| `command` resource design (local allowlist, no shell, idempotency guard) | complete | 2026-10-23 |
| `command` resource implementation | complete | 2026-11-10 |
| Windows agent (preview, [WINDOWS.md](WINDOWS.md)): `file`/`copy`/`template`/`line_in_file` with drive paths, `service` on the SCM, registry facts, Windows Service (`service install/uninstall`), private data directory; cross-compiled, not yet run on Windows | partial | 2026-11-10 |
| Windows agent: green `windows` CI job (smoke test, MSI) and a hand-run enrollment on Windows Server and Windows 11 | to-do | 2026-11-10 |
| Windows agent: ACL parameters (`owner`/`group`/`mode` are refused today), `package` backend (MSI with pinned hash), remediation for Windows services, Event Log, `registry` verb, reboots, arm64, code signing | to-do | 2026-11-10 |
| Workspace skeleton: policy, Core, Agent crates | complete | 2026-10-23 |
| Workspace skeleton: Proxy crate | complete | 2026-10-23 |
| Workspace skeleton: Operator crate (Kubernetes, kube-rs) | complete | 2026-11-01 |
| Container config delivery design: per-namespace/environment, no per-pod identity ([ABSTRACT.md](ABSTRACT.md) §5) | complete | 2026-11-01 |
| Operator: `DelbertBinding` CRD, ConfigMap/Secret rendering with content hash (pure logic, tests) | complete | 2026-11-01 |
| Core deliveries: migration `0021`, CRUD (`/v1/tenants/{t}/deliveries`), bundle endpoint for the Operator (variables, files, sensitive values sealed to it), integration test | complete | 2026-11-01 |
| Deliveries in the web console (CRUD, bundle preview with masked values) and a dedicated `deliveries:*` permission (today `policies:*`) | to-do | 2026-11-01 |
| Deliveries: audit event when the Operator reports an applied version | complete | 2026-11-01 |
| Deliveries: bundle version is informational (removals not reflected) | to-do | 2026-11-01 |
| Operator: minimum Kubernetes 1.31 (k8s-openapi 0.28 offers `v1_32` as earliest; verified working on K3s 1.31.14) | complete | 2026-11-01 |
| Operator: identity (enrollment, kept in a Secret), bundle fetch with agent proof, reconcile loop (server-side apply, owner reference, rollout hash on workloads, status), `run` command | partial | 2026-11-01 |
| Operator: loop verified by hand on K3s 1.31.14 against a real Core ([TESTING.md](TESTING.md)) | complete | 2026-11-01 |
| Operator: repeatable end-to-end test in CI (K3s + Core), a current Kubernetes version, StatefulSet/DaemonSet rollouts | to-do | 2026-11-01 |
| Operator: manifests (`deploy/kubernetes/operator`: CRD, RBAC, Deployment) and `operator` image target | complete | 2026-11-01 |
| Operator: leader election (today one replica, Recreate strategy) | to-do | 2026-11-01 |
| Operator: push notification instead of polling; several tenants per Operator | to-do | 2026-11-01 |
| Operator: Deployment/RBAC manifests, etcd encryption at rest documented as prerequisite, optional External Secrets backend | to-do | 2026-11-01 |
| Containers (Podman/Docker): `container` verb with `env_from` / `secret_from`, recreation on change, secrets as files; real Podman test | complete | 2026-11-01 |
| Containers: run against Docker; `container_volume` / `container_network`; registry credentials; healthchecks; Windows | to-do | 2026-11-01 |
| Facts: read-only collectors, shared subset reported to the Core every 15 min or on change, local facts and `facts.d` on the host; not a CMDB (decision 2026-11-01) | complete | 2026-11-01 |
| Facts: console page/filter on the reported facts (the API returns them; `web/` schema not regenerated); Windows collectors; more collectors (init system, package manager, container engine) | to-do | 2026-11-01 |
| Per-resource `when` evaluated on the agent over facts and variables (`target.when` for a whole policy stays refused: groups cover it) | complete | 2026-11-01 |
| Preview of which resources apply to a host (the editor cannot know local facts; offer fake facts for a dry run) | to-do | 2026-11-01 |
| Orphaned files removed when a version drops them, `keep_if_absent_in_policy`, after a clean cycle ([REMEDIATION.md](REMEDIATION.md)) | complete | 2026-11-01 |
| Orphans: console preview of the paths a save would remove; offline CLI; `line_in_file` lines | to-do | 2026-11-01 |
| Remediation: `verify` / `on_failure` / `stop` / `start` per service, atomic whole-policy rollback to the last known good, quarantine, inconsistent state in the Core, forced release (`agents:remediate`), audit events ([REMEDIATION.md](REMEDIATION.md)) | complete | 2026-11-01 |
| Remediation: run on a real systemd host; Windows services and Podman containers; HTTP probe; console page to see and force an inconsistent agent | to-do | 2026-11-01 |
| Repository layout: policies/files/templates/variables per tenant, group and host; folder-implied target; `target.agents`; variables from a repository; template repository ([REPOSITORY.md](REPOSITORY.md)) | complete | 2026-11-01 |
| Online editor: Monaco in the console, validation as you type, commit to a new branch, `writable` sources, `content:edit` | complete | 2026-11-01 |
| Repository: files and templates per group and host (layering by name, host > group > tenant > shared, with a preview) | to-do | 2026-11-01 |
| Repository: shared (global) variables, files and templates from a repository; global policies | to-do | 2026-11-01 |
| Editor: policy-schema completion (needs a YAML language service and `worker-src`), diff view, merge request opened from the console (Forgejo/GitHub/GitLab), create a repository from the template, e2e in the stack (needs a git server in compose) | to-do | 2026-11-01 |
| Operator counterpart of remediation: rollout that misses its deadline re-applies the previous bundle | to-do | 2026-11-01 |
| Deferred: sidecar agent with environment PSK; per-pod identity; workload auth via projected ServiceAccount token | to-do | 2026-11-01 |
| Agent: check/apply for `file`, `copy`, `line_in_file` (local YAML mode) | complete | 2026-10-23 |
| Agent: `template`, `package` (apt/dnf/zypper/apk), `service` (systemd) | complete | 2026-10-23 |
| Agent: `block_in_file`, `user`, `group`, `sysctl`, `cron` (`/etc/cron.d`, argv, local allow-list `DELBERT_CRON_ALLOW`); verified on a real Debian root (shadow tools) | complete | 2026-11-10 |
| Agent: `get_url` (mandatory SHA-256, no request when the file is already right), `mount` (fstab line + mount/umount/remount), `command` (local allow-list with optional hash pin, argv, mandatory guard and timeout, declared user); run for real: HTTPS download, tmpfs mount, a command as `nobody` and a timeout | complete | 2026-11-10 |
| `command`: output and exit code of a successful run in the audit trail (needs masking of secrets), kill of the whole process group at timeout, supplementary groups of the user, policy-side hash of the executable | to-do | 2026-11-10 |
| Agent: `authorized_key`, user passwords from secrets, authoritative group membership, per-user crontab spool, streaming download above 256 MiB, Windows counterparts (local users, Scheduled Tasks, commands) | to-do | 2026-11-10 |
| MVP exit criteria ([STATUS.md](STATUS.md) "MVP assessment"): CI green on the new jobs, chart installed on K3s, agent service on a real systemd host, backup/restore drill, first tag `v0.1.0` | to-do | 2026-11-10 |
| New verbs in the console: form/snippets and schema completion in the policy editor (the YAML editor and the validation already accept them) | to-do | 2026-11-10 |
| Orphans for the new verbs: a cron job, sysctl file or block that leaves the policy stays (needs `state: absent`) | to-do | 2026-11-10 |
| Agent: accept only signed effective policies (replace local YAML mode in production) | to-do | 2026-10-23 |
| RBAC v2 design: tenant-scoped roles, `resource:action` permissions, optional per-tenant four-eyes approval ([RBAC.md](RBAC.md)) | complete | 2026-10-23 |
| RBAC v2: tenant-scoped assignments, `resource:action` permissions, built-in roles, delegated tenant administration (migration `0010`) | complete | 2026-10-23 |
| RBAC v2: approval workflow (`approval_required`, `active_version`, `policy_version_events`, migration `0011`) | complete | 2026-10-23 |
| Approval: version diff, impact preview before approving, emergency path | to-do | 2026-10-23 |
| Core API for the UI: audit search/export, policy versions/validate, SSE stream, fleet overview done; general pagination/filters to-do | partial | 2026-10-24 |
| Frontend design ([FRONTEND.md](FRONTEND.md)) | complete | 2026-10-23 |
| Frontend M0 (Next.js BFF, generated client, login with MFA/SSO, i18n, theme, Playwright) | complete | 2026-10-23 |
| Frontend M1 (read-only: dashboard, tenants, agents, policies and versions, proxies, audit) | complete | 2026-10-23 |
| Frontend M2 (policy editor with dry-run validation and diff, version steps, enrollment keys, secrets, artifacts) | complete | 2026-10-23 |
| Frontend M2 leftovers: tenant create/archive, agent and proxy management | complete | 2026-10-24 |
| Frontend: syntax highlighting in the policy editor (deferred: cosmetic, CSP and test cost; validation and diff already live) | to-do | 2026-10-24 |
| CI: web end-to-end job (compose stack with PKI, Playwright) | to-do | 2026-10-24 |
| Frontend: manual accessibility review with a screen reader (axe covers only part of WCAG) | to-do | 2026-10-24 |
| Frontend M4: live status (SSE), dashboard with overview endpoint, axe accessibility audit, performance budget, visual regression | complete | 2026-10-24 |
| `git init` | complete | 2026-10-24 |
| CI pipeline (tests, clippy, fmt, image build); `windows` job (portable crates, agent smoke test, MSI) and `packaging` job (static build, deb/rpm in Debian and Fedora containers, chart, container installer) added 2026-11-10, results not seen yet | partial | 2026-11-10 |
| Audit browse and export API (`GET /v1/audit`, `/v1/audit/export`) | complete | 2026-10-23 |
| Artifact storage outside PostgreSQL: local directory and S3-compatible (Garage verified) | complete | 2026-10-23 |
| Artifacts: streaming upload (multipart/range) beyond 64 MiB, garbage collection of unreferenced objects, retention | to-do | 2026-10-23 |
| Artifacts: lifecycle with Garage in compose and Kubernetes manifests | to-do | 2026-10-23 |
| Auth hardening: cookie sessions + CSRF, TOTP MFA, login throttling (migration `0013`) | complete | 2026-10-23 |
| Auth: scoped API tokens (migration `0014`) | complete | 2026-10-23 |
| Auth: service accounts (users of kind `service` without password) | to-do | 2026-10-23 |
| Auth: SSO via OIDC (authorization code + PKCE, group to (role, scope) mapping, break-glass; verified with Keycloak) | complete | 2026-10-23 |
| Auth: SSO with Entra ID verified against a real tenant; groups overage; SAML; LDAP/AD | to-do | 2026-10-23 |
| SSO: assignments show their source (manual / sso:<provider>) in the API and the UI | to-do | 2026-10-23 |
| Auth: captcha (Turnstile) after repeated failures, WebAuthn, password breach check | to-do | 2026-10-23 |
| Configuration file for the Core (TOML, env override, strict keys, `--check-config`) | complete | 2026-10-23 |
| Configuration file for the Proxy (clap reads only the environment; needs a shared loader) | to-do | 2026-10-23 |
| Content sources design: directory or git (local Forgejo component or public remote), diff/version/apply ([CONTENT.md](CONTENT.md)) | complete | 2026-10-23 |
| Content sources implementation (directory + https git, sync API, ownership, diffs, poller) | complete | 2026-10-23 |
| Content sources: SSH remotes / deploy keys with pinned host keys, required signed commits or tags, webhook secret | to-do | 2026-10-23 |
| Content sources in the web UI (sources, snapshots, diffs, sync now) | complete | 2026-10-24 |
| Key rotation: policy signing key with overlap (in-band trust update, readiness API) | complete | 2026-10-23 |
| Key rotation: internal CA, NATS issuer, secrets age key, proxy certificate ([ROTATION.md](ROTATION.md)) | complete | 2026-10-23 |
| Quickstart and installation guides ([quickstart.md](quickstart.md), [install.md](install.md)) | complete | 2026-10-23 |
| Helm chart (`deploy/helm/delbert`: Core, NATS, web UI, optional PostgreSQL, generated passwords, NetworkPolicy for the database); `helm lint`/`template` in CI | complete | 2026-11-10 |
| Helm chart installed on a real K3s cluster; PodDisruptionBudget; drop the plain manifests of the control plane once the chart is proven | to-do | 2026-11-10 |
| Static (musl) builds of every binary; deb/rpm packages (nfpm) for agent, Core, proxy and tools with systemd units and service accounts; `install-agent.sh` | complete | 2026-11-10 |
| Windows installer: MSI (WiX 5) and `install-agent.ps1`, built and installed by CI | partial | 2026-11-10 |
| Release workflow on a tag: images on ghcr.io (cosign, SBOM, provenance), chart as OCI artifact, packages, MSI, install scripts, container bundle, `SHA256SUMS` (written, never run) | partial | 2026-11-10 |
| Releases: first tag; arm64 images; signed packages and an apt/dnf repository; signed MSI | to-do | 2026-11-10 |
| Single-host container install (`deploy/container`: compose for Podman/Docker, `install.sh`, keys created by a one-shot container); verified with Docker | complete | 2026-11-10 |
| `delbert-pki bootstrap`: every key and certificate of a new installation in one idempotent step | complete | 2026-11-10 |
| Agents: fingerprint-pinned download of the CA certificate from the Core (today `ca.pem` travels out of band) | to-do | 2026-11-10 |
| Quadlet units for single-host Podman (the compose install covers the case today); HA of NATS and the Core | to-do | 2026-11-10 |
| Rotation: proxy renewal verified in a live branch scenario; automatic reload (no restart) of the proxy and its site NATS; CA rotation reaching proxies without waiting for their renewal | to-do | 2026-10-23 |
| Frontend M3, slice 1: users, roles and the permission matrix (`GET /v1/permissions`) | complete | 2026-10-24 |
| Frontend M3, slice 2: profile (TOTP set-up, sessions, API tokens) | complete | 2026-10-24 |
| Frontend M3, slice 3: tenant approval switch and per-tenant role assignments | complete | 2026-10-24 |
| Frontend M3, slice 4: SSO providers (list, create/edit with group mappings, test, delete) | complete | 2026-10-24 |
| Frontend M3, slice 5: content sources (sources, history, diffs, sync now) | complete | 2026-10-24 |
| Frontend M3: complete | complete | 2026-10-24 |
| Decision (2026-10-24): local management of secrets, keys and certificates stays complete and the default (age-sealed store, key files, internal CA); external providers are an optional extra layer of protection behind the same seams, never a requirement. Nothing in the product may need a provider to work | complete | 2026-10-24 |
| External providers, design: seams `KeyWrapper` (secrets at rest), remote `Signer` (policy-signing key, CA key), `SecretSource` (values kept in an external store); each backend optional (cargo feature, one crate per family) | to-do | 2026-10-24 |
| External providers, first backend (optional): OpenBao/Vault (Transit wrap and Ed25519 signing, PKI sign-CSR, KV references). Check Ed25519 support per provider before choosing; HSM via PKCS#11 needs an isolated FFI crate (`unsafe_code` exception) | to-do | 2026-10-24 |
| External providers: PKCS#11 (Thales Luna, Utimaco, CloudHSM, SoftHSM2 for tests) | to-do | 2026-10-24 |
| External providers: AWS KMS/Secrets Manager, Azure Key Vault/Managed HSM, Google Cloud KMS/Secret Manager | to-do | 2026-10-24 |
