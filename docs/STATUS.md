# Delbert - Status and handoff

Snapshot for whoever continues the work (updated 2026-11-10). Design lives in [ABSTRACT.md](ABSTRACT.md); this file says what exists, how to run it and what to watch out for.

## What exists

| Crate | Role | Notes |
|-------|------|-------|
| `delbert-policy` | YAML policy model, JSON Schema, validation | verbs: `file`, `copy`, `template`, `line_in_file`, `block_in_file`, `package`, `service`, `container`, `user`, `group`, `cron`, `sysctl`, `get_url`, `mount`, `command` |
| `delbert-wire` | effective policy, JCS (RFC 8785), Ed25519 JWS sign/verify, signing-key rotation (`trust` updates) | `delbert-sign` CLI |
| `delbert-pki` | internal CA behind a trait (rcgen backend), Ed25519 CSR signing, agent request proofs | `delbert-pki` CLI; `bootstrap` creates every key of a new installation |
| `delbert-natsauth` | NATS authorization-callout building blocks | shared by Core and Proxy |
| `delbert-fs` | crash-safe file replacement, private directories (Unix and Windows) | used by agent, proxy, PKI CLI |
| `delbert-core` | REST API, PostgreSQL via SQLx (migrations 0001-0021), NATS bus + callout | RBAC v2 (tenant-scoped), shared artifacts and layered variables, configuration deliveries for the Operator, approval workflow, sessions/CSRF/MFA/throttling, API tokens, OIDC SSO, content sources (directory/git), artifacts in local dir or S3, audit browse/export, config file |
| `delbert-agent` | engine + daemon + CLI | enrollment, renewal with key rotation, trust updates; Windows preview (`winsvc.rs`, [WINDOWS.md](WINDOWS.md)) |
| `deploy/container`, `deploy/helm/delbert`, `packaging/` | installers: compose + `install.sh`, Helm chart, deb/rpm (nfpm), MSI (WiX), install scripts | what was really run: [install.md](install.md) "How far the installers are verified" |
| `delbert-proxy` | branch-office relay | see [PROXY.md](PROXY.md) |
| `delbert-operator` | Kubernetes Operator | `DelbertBinding` CRD, rendering, identity, bundle fetch and reconcile loop ([OPERATOR.md](OPERATOR.md)); verified by hand on K3s 1.31.14 (manifests in `deploy/kubernetes/operator`, image target `operator`); no CI test, no leader election. Target Kubernetes >= 1.31. Design: [ABSTRACT.md](ABSTRACT.md) §5 |
| `web/` (Next.js) | administration UI, milestones M0-M4 (complete) | backend-for-frontend, see [web/README.md](../web/README.md) |

About 215 automated tests (unit, PostgreSQL, NATS; optional S3/git/Keycloak-backed checks run with environment variables). Container end-to-end scenarios and the real-system checks (Garage, Keycloak, Forgejo, key rotation) are in [TESTING.md](TESTING.md). Start with [quickstart.md](quickstart.md); deployment in [install.md](install.md). Repository: `bytehawks-org/delbert` on GitHub (`main`). Nothing is deployed anywhere.

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

Optional environment for the real-system tests: `S3_TEST_*` (Garage), `GIT_TEST_*` (git server with a token). Images come from the `Containerfile` (targets `core`, `agent`, `proxy`, `operator`, `tools`, `web`).

Cross-builds without a container (what the packaging uses): `pip install cargo-zigbuild ziglang`, `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu`, then `cargo zigbuild --target <target> ...`. The Windows target only proves that it compiles and links; nothing runs it here.

## Decisions worth remembering

- Core and Proxy never execute commands on managed systems; only agents act. YAML is the authoring format; agents receive per-endpoint effective policies as canonical JSON signed with Ed25519 (JWS). `unsafe` is forbidden workspace-wide.
- NATS is the only broker, mTLS with the Delbert CA, authorization callout, per-agent subjects, signed proofs.
- Secrets never appear in policies: write-only store sealed with the Core's age key, re-encrypted to each agent.
- Content (artifacts) lives in an object store, never in PostgreSQL. Policies/artifacts can also come from a repository source, which then owns them (API edits refused).
- Tenant-scoped RBAC; optional per-tenant four-eyes approval; SSO users are keyed by the provider's `sub` and never linked to a local account by name.
- Configuration: TOML file under the environment; strict keys; `--check-config`.
- Migrations are plain SQL run as the schema owner; the Core runs as a least-privilege role. The project is unreleased: migrations were edited/dropped columns in place before (0005, 0012).

## Known limits

See [ROADMAP.md](ROADMAP.md). The ones that matter most: web UI complete through M4 ([FRONTEND.md](FRONTEND.md)); Kubernetes Operator verified by hand on K3s 1.31.14 but with no automated end-to-end test; remediation (rollback to the last known good, [REMEDIATION.md](REMEDIATION.md)) and `service` tested with a scripted `systemctl` only, not on a real systemd host; the Windows agent is compiled but was never run on Windows ([WINDOWS.md](WINDOWS.md)); `service` only tested with a fake runner; no CRL/OCSP; proxy renewal not run live in a branch scenario ([ROTATION.md](ROTATION.md)); the Helm chart and the Kubernetes manifests were never run on a cluster (the chart not even rendered locally); no release published yet (the workflow exists, no tag); the deb/rpm files and the MSI are first built by CI, whose new jobs have not been seen green; the proxy has no configuration file.

## MVP assessment (2026-11-10)

**Verdict: feature-complete MVP candidate for Linux; not yet a released MVP.** What is missing is proof and a release, not features.

| Area | MVP needs | State |
|------|-----------|-------|
| Control plane | API with Swagger, tenants, RBAC with separation of duties, MFA, OIDC SSO, signed policies, internal PKI with rotation, sealed secrets, artifacts, hash-chained audit with export, web console (EN/IT) | done, covered by about 215 tests and the container end-to-end runs |
| Linux agent | enrollment, renewal, signed policies only, drift correction, reports and audit events, facts, remediation | done; 15 verbs (files, lines and blocks, downloads, packages, services, containers, accounts, cron, sysctl, mounts, commands) |
| Branch office, Kubernetes workloads | proxy; Operator | done; Operator verified by hand on K3s only |
| Install | containers, Kubernetes, packages | container install run for real; packages checked by content; chart and release pipeline written, **never run** |
| Windows | optional for an MVP | preview, compiled only |

Exit criteria, in order (each is a run, not a feature):

1. The `windows` and `packaging` CI jobs green (they went to `main` without anybody seeing a run).
2. The Helm chart installed on a real K3s cluster, an agent enrolled against it.
3. The agent as a systemd service on a real host (package install, `service` and remediation against a real systemd: today a scripted `systemctl` only).
4. A backup and restore drill following [install.md](install.md), ending with `GET /v1/audit/verify`.
5. Tag `v0.1.0` and check every artifact of the release (images, chart, packages, MSI, checksums).

Known and acceptable for an MVP, to say in the release notes: wire compatibility between versions is not guaranteed (agents reject verbs they do not know: upgrade agents first); no HA of the Core and NATS; packages unsigned; `specificity` conflict strategy, resolution records, SAML and LDAP/AD login, SIEM connector (NDJSON export exists), pagination of lists are post-MVP ([ROADMAP.md](ROADMAP.md)).

## Next steps

0. Repository layout and the online editor are done ([REPOSITORY.md](REPOSITORY.md)); next there: files and templates per group and host, shared content from a repository, schema completion and merge requests from the editor.

1. Work through the five exit criteria of the MVP assessment above, in that order; then enroll a real Windows host. Then web e2e in CI and the optional integrations (external key and secret providers). The UI is complete through M4 ([FRONTEND.md](FRONTEND.md)); a tenant "delete" is an archive.
2. Kubernetes Operator; Windows: ACL model and `package` backend ([WINDOWS.md](WINDOWS.md) "Next steps"). (The CA is behind a trait, rcgen backend only: [API.md](API.md) `DELBERT_CA_BACKEND`.) (Per-action audit events from agents are done, also through the proxy: [API.md](API.md) "Agent audit events".)
3. Proxy config file and live branch check of proxy renewal; SSH remotes and signed commits for content sources; Entra ID check against a real tenant.

## Working agreements

- Replies in Italian; code, comments, commit messages and documentation in English; keep `README.md`, `CHANGELOG.md` and `ROADMAP.md` updated after meaningful changes (`CLAUDE.md` in the repository root has the rest).
- No scripts are committed unless asked for; commands live in the docs. Asked for and committed: the installers and their build/test scripts in `packaging/` and `deploy/container/`.
- Write files with an editor, not with shell here-documents that contain another here-document: a nested terminator once ended the outer one and the rest ran as commands.
- Do not use `podman volume prune` or `podman system prune`: the same Podman storage holds other projects (`notturni_*`, `event-horizon_*`). Remove only what Delbert created. Build with `CARGO_INCREMENTAL=0` and a named target volume; an incremental cache once grew to 29 GB and filled the disk.
- Check findings against the real thing: the live NATS server and the container runs found more problems (certificate lookup in the callout, renewal loop, slow outage recovery, a migration race) than the unit tests did.
