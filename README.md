# Delbert

Open-source configuration management and state enforcement for hybrid infrastructure (Linux and Windows hosts, containers, Kubernetes). Agents pull signed, declarative YAML policies and converge the local system idempotently; the server never executes commands.

Web UI: [web/README.md](web/README.md) · Start here: [Quickstart](docs/quickstart.md) · [Installation](docs/install.md) (containers, Helm, deb/rpm, MSI) · [Windows agent](docs/WINDOWS.md)

Status and handoff: [docs/STATUS.md](docs/STATUS.md) · Operator: [docs/OPERATOR.md](docs/OPERATOR.md) · RBAC v2: [docs/RBAC.md](docs/RBAC.md) · Frontend: [docs/FRONTEND.md](docs/FRONTEND.md) · Repository layout and editor: [docs/REPOSITORY.md](docs/REPOSITORY.md) · Remediation and orphans: [docs/REMEDIATION.md](docs/REMEDIATION.md)

Design: [docs/ABSTRACT.md](docs/ABSTRACT.md) · Scope: [docs/SCOPE.md](docs/SCOPE.md) · Policy format: [docs/POLICY.md](docs/POLICY.md) · Roadmap: [docs/ROADMAP.md](docs/ROADMAP.md) · Changes: [docs/CHANGELOG.md](docs/CHANGELOG.md)

## Status

MVP candidate (v0.1.0, unreleased): feature-complete for Linux, proof steps still open ([docs/STATUS.md](docs/STATUS.md) "MVP assessment").

- `delbert-policy`: policy YAML model, JSON Schema, semantic validation (tests included).
- `delbert-core`: Axum REST API with Swagger UI ([docs/API.md](docs/API.md)): local users and customizable RBAC with sessions, tenants, agents, versioned policies, policy compiler with conflict resolution (`priority`/`error`), signing of effective policies (`core` mode), hash-chained audit trail, NATS notifications/pull/reports, least-privilege DB role, agent enrollment (pre-shared keys, CSR, mTLS), NATS authorization callout (per-agent subject permissions), certificate renewal with key rotation, per-agent encrypted secrets, content-pinned artifacts (own or shared with every tenant), layered template variables with constants and a render preview. SQLx migrations. Content sources read a repository with policies, files, templates and variables per tenant, group and host, and a writable source can be edited from the console ([docs/REPOSITORY.md](docs/REPOSITORY.md)); an inconsistent agent is released by a signed, audited decision.
- `delbert-operator` (in progress, [docs/OPERATOR.md](docs/OPERATOR.md)): Kubernetes Operator that delivers per-namespace configuration (ConfigMap + Secret) from the Core's configuration deliveries; the `DelbertBinding` CRD, rendering rules, identity and reconcile loop are written (unit-tested and verified by hand on K3s 1.31.14; manifests in `deploy/kubernetes/operator`); the Core bundle endpoint is done and tested.
- `delbert-proxy`: branch-office relay ([docs/PROXY.md](docs/PROXY.md)): local NATS authorization callout from a synchronized allow-list, request relay with cache, store-and-forward of reports (latest per agent), enrollment relay, artifact cache; `delbert-natsauth` holds the callout building blocks shared with the Core.
- `delbert-pki`: internal CA (Ed25519, leaf-only), CSR signing with Core-chosen subjects, agent request proofs; `delbert-pki` CLI (`bootstrap` for a new installation; `init`, `issue-server`, `issue-client`, `secrets-key`, `nats-issuer`).
- `delbert-wire`: effective policy (JSON), JCS canonicalization (RFC 8785), Ed25519 JWS signing and strict verification (key id, expiry, target, anti-rollback); `delbert-sign` CLI (`keygen`, `sign`) for the `external` signing mode.
- `delbert-agent`: daemon (`enroll`, `run`: mTLS to NATS, signed proofs, pull over NATS, verify, apply every cycle or on notification, report, cached policy when the Core is down) and engine with `check`/`apply` for `file`, `copy`, `template` (MiniJinja), `line_in_file`, `block_in_file`, `package` (apt, dnf, zypper, apk), `service` (systemd), `user`, `group`, `sysctl`, `mount`, `get_url` (pinned SHA-256), `cron` and `command` (both off unless allowed in the local agent configuration); dependencies, handlers, idempotent, verified after apply. CLI: `validate`, `schema`, `check`, `apply` (local YAML, development) and `check-signed`, `apply-signed` (signed policies only; exit 3 = rejected). Also: host facts (a small subset reported to the Core, the rest local) and per-resource `when`; the `container` verb for Podman/Docker with `env_from` and secrets as files; orphaned files removed when a version drops them; remediation of a failed update with rollback to the last known good ([docs/REMEDIATION.md](docs/REMEDIATION.md)).

- Windows (preview, [docs/WINDOWS.md](docs/WINDOWS.md)): the agent builds for Windows with `file`, `copy`, `template`, `line_in_file` on drive paths, `service` on the Service Control Manager, registry facts and a Windows Service mode; compiled, not yet run on a Windows host.

## Install

| Environment | How | Details |
|-------------|-----|---------|
| One host, Podman or Docker | `./install.sh --host delbert.example.com` in [`deploy/container`](deploy/container) | compose stack; keys and passwords generated |
| Kubernetes / K3s | `delbert-pki bootstrap`, one Secret, `helm install` of [`deploy/helm/delbert`](deploy/helm/delbert) | Core, NATS, web UI, optional PostgreSQL |
| Linux without containers | `.deb` / `.rpm` of `delbert-core`, `delbert-agent`, `delbert-proxy`, `delbert-tools` ([`packaging/`](packaging)) | static binaries, systemd units |
| Linux agent | `install-agent.sh --core-url ... --ca-file ca.pem --agent-id ... --psk ...` | package + enrollment |
| Windows agent | `install-agent.ps1`, or `msiexec /i delbert-agent-<v>-x64.msi /qn CORE_URL=... ENROLL_PSK=...` | Windows Service |

No release is published yet: [docs/install.md](docs/install.md) says how to build the artifacts and what was actually verified.

## Development (Podman, no Rust needed on the host)

```sh
# dependencies + Core (builds inside a rust:1 container)
podman compose up -d postgres nats core
curl localhost:8080/healthz

# build with CARGO_INCREMENTAL=0 and a named target volume (see docs/TESTING.md: disk usage)
# tests (the Core tests need PostgreSQL: start it first, run on the compose network)
podman compose up -d postgres
podman run --rm --network delbert_default \
  -e DATABASE_URL=postgres://delbert:delbert-dev@postgres:5432/delbert \
  -v "$PWD":/work:Z -w /work docker.io/library/rust:1 cargo test --workspace

# Core with signing: generate a dev key (kept in ./dev, git-ignored), then start
podman run --rm -v "$PWD":/work:Z -w /work docker.io/library/rust:1 \
  cargo run -q -p delbert-wire --bin delbert-sign -- keygen k1 --dir dev > dev/trusted-keys.txt
DELBERT_SIGNING_KEY_FILE=/work/dev/k1.key DELBERT_SIGNING_KID=k1 podman compose up -d postgres core

# try a policy in a sandbox directory (exit 0 compliant, 2 drift, 1 failure)
podman run --rm -v "$PWD":/work:Z -w /work docker.io/library/rust:1 sh -c \
  "mkdir -p /tmp/sb/etc && cargo run -q -p delbert-agent -- check examples/app-baseline.yaml --root /tmp/sb"
```

Signed flow (keys and policy in a scratch directory, sandbox root; `package`/`service` are refused in a sandbox):

```sh
delbert-sign keygen k1 --dir . > trusted-keys.txt
delbert-sign sign examples/app-baseline.yaml --key k1.key --kid k1 --agent agent-1 --version 1 > policy.jws
delbert-agent apply-signed policy.jws --trusted-keys trusted-keys.txt --agent-id agent-1 --tenant example --root /tmp/sb
```

End to end in containers (Core + two agents; and a branch office behind a proxy on an isolated network): see [docs/TESTING.md](docs/TESTING.md) and [compose.e2e.yaml](compose.e2e.yaml). Images are built from the [Containerfile](Containerfile).

Default dev credentials are in [compose.yaml](compose.yaml) and are for local use only.
