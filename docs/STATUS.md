# Delbert - Status and handoff

Snapshot for whoever continues the work (written 2026-10-23). Design lives in [ABSTRACT.md](ABSTRACT.md); this file says what exists, how to run it and what to watch out for.

## What exists

| Crate | Role | Notes |
|-------|------|-------|
| `delbert-policy` | YAML policy model, JSON Schema, validation | verbs: `file`, `copy`, `template`, `line_in_file`, `package`, `service` |
| `delbert-wire` | effective policy, JCS (RFC 8785), Ed25519 JWS sign/verify | `delbert-sign` CLI (keygen, sign) |
| `delbert-pki` | internal CA (Ed25519), CSR signing, agent request proofs | `delbert-pki` CLI (init, issue-server, issue-client, secrets-key, nats-issuer) |
| `delbert-natsauth` | NATS authorization-callout building blocks | shared by Core and Proxy |
| `delbert-core` | REST API (Axum, OpenAPI/Swagger), PostgreSQL via SQLx, NATS bus, callout | users/RBAC v1, tenants, agents, policies, compiler + conflicts, signing, secrets, artifacts, enrollment, proxies, audit hash chain |
| `delbert-agent` | engine + daemon + CLI | local `check/apply`, signed `check-signed/apply-signed`, `enroll`, `run` |
| `delbert-proxy` | branch-office relay | see [PROXY.md](PROXY.md) |

81 automated tests (unit, PostgreSQL integration, NATS). End-to-end scenarios in containers are recorded in [TESTING.md](TESTING.md). Nothing is deployed anywhere; there is no git repository yet (`git init` is the first thing to do).

## Run it

Everything runs in Podman; Rust is not needed on the host.

```sh
# automated tests (the Core tests need PostgreSQL and NATS)
podman compose up -d postgres nats
podman run --rm -e CARGO_INCREMENTAL=0 --network delbert_default \
  -e DATABASE_URL=postgres://delbert:delbert-dev@postgres:5432/delbert -e NATS_URL=nats://nats:4222 \
  -v "$PWD":/work:Z -v delbert_cargo_registry:/usr/local/cargo/registry -v delbert_cargo_target:/work/target \
  -w /work docker.io/library/rust:1 cargo test --workspace
podman compose down
```

End-to-end with mutual TLS (Core + agents) and with a branch office behind a proxy: [TESTING.md](TESTING.md). Images are built from the `Containerfile` (targets `core`, `agent`, `proxy`). The dev PKI, keys and identities live in `./dev` (git-ignored, development only).

## Decisions worth remembering

- Core and Proxy never execute commands on managed systems; only agents act. YAML is the authoring format; agents receive per-endpoint effective policies as canonical JSON signed with Ed25519 (JWS).
- NATS is the only broker. Every client uses mTLS with certificates of the Delbert CA; the Core (and each proxy, for its site) authorizes connections through the NATS authorization callout, with per-agent subject permissions; requests and reports also carry the agent's signed proof.
- Secrets never appear in policies: write-only store sealed with the Core's age key, re-encrypted to each agent at issue time.
- Proxy is an application-level relay (no leaf nodes), so the branch network never connects to the Core.
- Conflicts between policies are resolved only by the Core, fail-closed (`error` strategy by default, `priority` available).
- Migrations are plain SQL run as the schema owner; the Core runs as a least-privilege role that cannot rewrite the audit trail or policy versions. The project is unreleased: migration `0005` was edited in place once, so databases created before that were to be recreated.

## Known limits

See [ROADMAP.md](ROADMAP.md) for the full list. The ones that matter most: no per-action audit events from agents; `service` is only tested with a fake runner (no systemd in the containers); no Kubernetes Operator yet; the proxy's own certificate does not renew; no CRL/OCSP; no SSO/MFA; RBAC is global (see [RBAC.md](RBAC.md)); Windows agent not started.

## Next steps (agreed)

1. RBAC v2 and authentication hardening in the Core ([RBAC.md](RBAC.md)): tenant-scoped roles, finer permissions, optional per-tenant four-eyes approval, cookie sessions, MFA, login throttling, audit browsing API, pagination.
2. Frontend ([FRONTEND.md](FRONTEND.md)): milestone M0 onward.
3. Then: per-action audit events from agents (also through the proxy), Kubernetes Operator, Windows agent study.

## Working agreements

- Replies in Italian; code, comments, commit messages and documentation in English; keep `README.md`, `CHANGELOG.md` and `ROADMAP.md` updated after meaningful changes (`CLAUDE.md` in the repository root has the rest).
- No scripts are committed unless asked for; commands live in the docs.
- Do not use `podman volume prune` or `podman system prune`: the same Podman storage holds other projects (`notturni_*`, `event-horizon_*`). Remove only what Delbert created. Build with `CARGO_INCREMENTAL=0` and a named target volume; an incremental cache once grew to 29 GB and filled the disk.
- Check findings against the real thing: the live NATS server and the container runs found more problems (certificate lookup in the callout, renewal loop, slow outage recovery, a migration race) than the unit tests did.
