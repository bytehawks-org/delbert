# Delbert

Open-source configuration management and state enforcement for hybrid infrastructure (Linux hosts, containers, Kubernetes). Agents pull signed, declarative YAML policies and converge the local system idempotently; the server never executes commands.

Start here: [Quickstart](docs/quickstart.md) · [Installation](docs/install.md)

Status and handoff: [docs/STATUS.md](docs/STATUS.md) · RBAC v2: [docs/RBAC.md](docs/RBAC.md) · Frontend: [docs/FRONTEND.md](docs/FRONTEND.md)

Design: [docs/ABSTRACT.md](docs/ABSTRACT.md) · Scope: [docs/SCOPE.md](docs/SCOPE.md) · Policy format: [docs/POLICY.md](docs/POLICY.md) · Roadmap: [docs/ROADMAP.md](docs/ROADMAP.md) · Changes: [docs/CHANGELOG.md](docs/CHANGELOG.md)

## Status

Early skeleton (v0.1.0):

- `delbert-policy`: policy YAML model, JSON Schema, semantic validation (tests included).
- `delbert-core`: Axum REST API with Swagger UI ([docs/API.md](docs/API.md)): local users and customizable RBAC with sessions, tenants, agents, versioned policies, policy compiler with conflict resolution (`priority`/`error`), signing of effective policies (`core` mode), hash-chained audit trail, NATS notifications/pull/reports, least-privilege DB role, agent enrollment (pre-shared keys, CSR, mTLS), NATS authorization callout (per-agent subject permissions), certificate renewal with key rotation, per-agent encrypted secrets, content-pinned artifacts. SQLx migrations.
- `delbert-proxy`: branch-office relay ([docs/PROXY.md](docs/PROXY.md)): local NATS authorization callout from a synchronized allow-list, request relay with cache, store-and-forward of reports (latest per agent), enrollment relay, artifact cache; `delbert-natsauth` holds the callout building blocks shared with the Core.
- `delbert-pki`: internal CA (Ed25519, leaf-only), CSR signing with Core-chosen subjects, agent request proofs; `delbert-pki` CLI (`init`, `issue-server`, `issue-client`, `secrets-key`).
- `delbert-wire`: effective policy (JSON), JCS canonicalization (RFC 8785), Ed25519 JWS signing and strict verification (key id, expiry, target, anti-rollback); `delbert-sign` CLI (`keygen`, `sign`) for the `external` signing mode.
- `delbert-agent`: daemon (`enroll`, `run`: mTLS to NATS, signed proofs, pull over NATS, verify, apply every cycle or on notification, report, cached policy when the Core is down) and engine with `check`/`apply` for `file`, `copy`, `template` (MiniJinja), `line_in_file`, `package` (apt, dnf, zypper, apk), `service` (systemd); dependencies, handlers, idempotent, verified after apply. CLI: `validate`, `schema`, `check`, `apply` (local YAML, development) and `check-signed`, `apply-signed` (signed policies only; exit 3 = rejected).

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
