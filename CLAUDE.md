# Global

This file extends and integrates the user-scoped CLAUDE.md file.

# Desired Stack

- Rust, edition 2024 (Axum)
- SQLx + native SQL migrations (`sqlx migrate`), no ORM
- NATS JetStream as the only message bus (`async-nats`)
- PostgreSQL 17.x
- Next.js + Tailwind CSS (administration frontend)
- utoipa + Swagger UI (API documentation)
- kube-rs (Kubernetes Operator)
- rcgen + rustls for the internal PKI (OpenSSL as fallback backend)

# Desired Add-ons and Features

- Local users and multiple SSO providers (OIDC/SAML) + Active Directory/LDAP login
- RBAC with separation of duties, MFA for administrators
- Multi-tenant (tenant/group scoping for policies, PSK and certificates)
- NIS2-supporting audit trail: append-only, hash-chained, SIEM export (see docs/ABSTRACT.md §6)

# Requirements

- Keep It Simple (KISS) code philosophy
- Simple Backup and Restore procedure
- Comprehensive inline documentation
- Every element must have an administrative control with CRUD operations and all needed to administer it
- API documentation in Swagger
- API security: limit public API access only to necessary
- Multilanguage support: English + Italian but extensible to other languages
- Certificate authority behind a trait, so the backend (rcgen / OpenSSL) is swappable
- Agent: outbound-only, idempotent, no non-reconstructible local state
- Core and Proxy never execute commands on managed systems: only agents (and the in-cluster Operator) act, on their own host
- YAML is the authoring format only (`serde_yaml_ng`), validated by schema and typed deserialization
- Agents receive per-endpoint effective policies: canonical JSON (JCS, RFC 8785), Ed25519-signed (JWS); agents verify before applying
- Sensitive fields are encrypted per target agent; everything travels over TLS 1.3 + mTLS
- Policy conflicts are resolved only by the Core (configurable strategy chain, per-resource/policy overrides, auditable resolution records); default is fail-closed per conflicting key
- `command` resource: disabled by default, enabled only in local agent config, no shell, local allowlist, mandatory idempotency guard and timeout

# Deployment

## Server/Control Plane

- Local: Podman
- Production: Kubernetes/K3s

## Client/Agent

- Local: Podman (test environments)
- Production: native packages (systemd service on Linux, Windows Service on Windows)
- Kubernetes: Operator deployed in-cluster; standard agent on the nodes' hosts

# Project Details and Documentation

- docs/ABSTRACT.md
- docs/POLICY.md (policy YAML format)
- docs/API.md (Core API), docs/PROXY.md (branch-office proxy), docs/TESTING.md
- docs/RBAC.md (access control v2), docs/FRONTEND.md (web UI design)
- docs/STATUS.md (current state and handoff: read it first in a new session)
- docs/DESIDERATA.md
- docs/SCOPE.md
- docs/CHANGELOG.md
- docs/ROADMAP.md
