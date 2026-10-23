# Delbert - Scope

Derived from [ABSTRACT.md](ABSTRACT.md). Section numbers refer to it.

## In scope

| Area | Content | Abstract |
|------|---------|----------|
| Core Server | API (Axum, OpenAPI planned), policy/desired-state management, inventory, tenants, RBAC | §2, §7 |
| Proxy/Relay | Local authorization, request relay with cache, store-and-forward of reports, enrollment relay, artifact cache ([PROXY.md](PROXY.md)); optional sub-CA still to do | §2, §4 |
| Agent | Phase 1: Linux; phase 2: Windows. Outbound-only, idempotent enforcement, cached policy | §3, §5 |
| Policy format | YAML, Ansible-inspired verb subset ([POLICY.md](POLICY.md)) | §3 |
| Container engines | Docker and Podman containers, volumes, networks | §5 |
| Kubernetes | Host agent on nodes + in-cluster Operator (CRDs, kube-rs) | §5 |
| Message bus | NATS JetStream only (mTLS, per-tenant accounts, leaf nodes for Proxies) | §2 |
| PKI | Internal CA (rcgen, Ed25519, leaf-only); PSK + CSR onboarding, mTLS; renewal and revocation still to do | §3, §4 |
| Audit | Append-only hash-chained trail, retention, SIEM export, NIS2 reports | §6 |
| Web UI | Next.js + Tailwind admin dashboard, EN + IT | §7 |
| Auth | Local users, OIDC/SAML SSO, AD/LDAP, MFA | CLAUDE.md |
| Ops | Backup/restore, Podman (local), K8s/K3s (production) | CLAUDE.md |

## Design constraints

- Core and Proxy never execute commands on managed systems; only agents/Operator execute, locally.
- YAML is the authoring format only; agents receive per-endpoint effective policies as canonical JSON (JCS), Ed25519-signed, sensitive fields encrypted per agent.
- Policy conflicts are resolved only by the Core (configurable strategies), never by agents.
- The `command` resource is agent-side only, off by default, with local allowlist.

## Out of scope (for now)

- macOS agents
- Inbound connections to endpoints (SSH/rsync push)
- Legal NIS2 compliance certification (Delbert supports it, the operator remains responsible)
