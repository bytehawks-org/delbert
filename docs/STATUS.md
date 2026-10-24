# Delbert - Status and handoff

Snapshot for whoever continues the work (updated 2026-10-24). Design lives in [ABSTRACT.md](ABSTRACT.md); this file says what exists, how to run it and what to watch out for.

## What exists

| Crate | Role | Notes |
|-------|------|-------|
| `delbert-policy` | YAML policy model, JSON Schema, validation | verbs: `file`, `copy`, `template`, `line_in_file`, `package`, `service` |
| `delbert-wire` | effective policy, JCS (RFC 8785), Ed25519 JWS sign/verify, signing-key rotation (`trust` updates) | `delbert-sign` CLI |
| `delbert-pki` | internal CA behind a trait (rcgen backend), Ed25519 CSR signing, agent request proofs | `delbert-pki` CLI |
| `delbert-natsauth` | NATS authorization-callout building blocks | shared by Core and Proxy |
| `delbert-fs` | crash-safe file replacement | used by agent, proxy, PKI CLI |
| `delbert-core` | REST API, PostgreSQL via SQLx (migrations 0001-0019), NATS bus + callout | RBAC v2 (tenant-scoped), approval workflow, sessions/CSRF/MFA/throttling, API tokens, OIDC SSO, content sources (directory/git), artifacts in local dir or S3, audit browse/export, config file |
| `delbert-agent` | engine + daemon + CLI | enrollment, renewal with key rotation, trust updates |
| `delbert-proxy` | branch-office relay | see [PROXY.md](PROXY.md) |
| `web/` (Next.js) | administration UI, milestones M0-M3 | backend-for-frontend, see [web/README.md](../web/README.md) |

About 130 automated tests (unit, PostgreSQL, NATS; optional S3/git/Keycloak-backed checks run with environment variables). Container end-to-end scenarios and the real-system checks (Garage, Keycloak, Forgejo, key rotation) are in [TESTING.md](TESTING.md). Start with [quickstart.md](quickstart.md); deployment in [install.md](install.md). Repository: `bytehawks-org/delbert` on GitHub (`main`). Nothing is deployed anywhere.

## Run it

Everything runs in Podman; Rust is not needed on the host.

```sh
podman compose up -d postgres nats
podman run --rm -e CARGO_INCREMENTAL=0 --network delbert_default \
  -e DATABASE_URL=postgres://delbert:delbert-dev@postgres:5432/delbert -e NATS_URL=nats://nats:4222 \
  -v "$PWD":/work:Z -v delbert_cargo_registry:/usr/local/cargo/registry -v delbert_cargo_target:/work/target \
  -w /work docker.io/library/rust:1 cargo test --workspace
podman compose down
```

Optional environment for the real-system tests: `S3_TEST_*` (Garage), `GIT_TEST_*` (git server with a token). Images come from the `Containerfile` (targets `core`, `agent`, `proxy`, `tools`).

## Decisions worth remembering

- Core and Proxy never execute commands on managed systems; only agents act. YAML is the authoring format; agents receive per-endpoint effective policies as canonical JSON signed with Ed25519 (JWS). `unsafe` is forbidden workspace-wide.
- NATS is the only broker, mTLS with the Delbert CA, authorization callout, per-agent subjects, signed proofs.
- Secrets never appear in policies: write-only store sealed with the Core's age key, re-encrypted to each agent.
- Content (artifacts) lives in an object store, never in PostgreSQL. Policies/artifacts can also come from a repository source, which then owns them (API edits refused).
- Tenant-scoped RBAC; optional per-tenant four-eyes approval; SSO users are keyed by the provider's `sub` and never linked to a local account by name.
- Configuration: TOML file under the environment; strict keys; `--check-config`.
- Migrations are plain SQL run as the schema owner; the Core runs as a least-privilege role. The project is unreleased: migrations were edited/dropped columns in place before (0005, 0012).

## Known limits

See [ROADMAP.md](ROADMAP.md). The ones that matter most: web UI at milestone M3 (M4: SSE, accessibility audit, performance budget; [FRONTEND.md](FRONTEND.md)); no Kubernetes Operator; no Windows agent; `service` only tested with a fake runner; no CRL/OCSP; proxy renewal not run live in a branch scenario ([ROTATION.md](ROTATION.md)); the Kubernetes manifests were never run on a cluster; no published images/packages; the proxy has no configuration file and its certificate does not renew.

## Next steps

1. Frontend M4 ([FRONTEND.md](FRONTEND.md)): SSE for live status, accessibility audit, performance budget, visual regression. M0-M3 are in `web/` (governance and management screens included); a tenant "delete" is an archive.
2. Kubernetes Operator; Windows agent study. (The CA is behind a trait, rcgen backend only: [API.md](API.md) `DELBERT_CA_BACKEND`.) (Per-action audit events from agents are done, also through the proxy: [API.md](API.md) "Agent audit events".)
3. Proxy config file and live branch check of proxy renewal; SSH remotes and signed commits for content sources; Entra ID check against a real tenant.

## Working agreements

- Replies in Italian; code, comments, commit messages and documentation in English; keep `README.md`, `CHANGELOG.md` and `ROADMAP.md` updated after meaningful changes (`CLAUDE.md` in the repository root has the rest).
- No scripts are committed unless asked for; commands live in the docs.
- Do not use `podman volume prune` or `podman system prune`: the same Podman storage holds other projects (`notturni_*`, `event-horizon_*`). Remove only what Delbert created. Build with `CARGO_INCREMENTAL=0` and a named target volume; an incremental cache once grew to 29 GB and filled the disk.
- Check findings against the real thing: the live NATS server and the container runs found more problems (certificate lookup in the callout, renewal loop, slow outage recovery, a migration race) than the unit tests did.
