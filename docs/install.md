# Delbert - Installation

How to run Delbert for real: the control plane (Core, PostgreSQL, NATS, web UI), agents on Linux and Windows hosts, and optionally a proxy at a branch office. For a ten-minute trial on one machine see [quickstart.md](quickstart.md).

**State of the project:** unreleased (v0.x). The installers below exist in this repository and a release workflow publishes them when a tag `vX.Y.Z` is pushed ([Releases](#releases)); **no release has been published yet**, so until the first tag you build the artifacts yourself ([Building](#building-the-artifacts-yourself)). What was run for real and what was only written is listed in [How far the installers are verified](#how-far-the-installers-are-verified). Read the "Known limits" at the end before relying on it.

## Pick your path

| You have | Control plane | Agents |
|----------|---------------|--------|
| One host with Podman or Docker | [Containers](#a-containers-one-host-with-podman-or-docker): `./install.sh --host <name>` | [Linux](#linux-host-with-systemd) / [Windows](#windows) |
| Kubernetes / K3s | [Helm chart](#b-kubernetes--k3s-helm): `helm install` | on the nodes' hosts, plus the [Operator](OPERATOR.md) for workloads |
| Linux servers without containers | [deb/rpm packages](#c-linux-packages-no-containers) and systemd | [Linux](#linux-host-with-systemd) / [Windows](#windows) |

## What you are installing

```text
 operators ──HTTPS──▶ ┌──────────────┐      ┌────────────┐
                      │  Delbert Core │─────▶│ PostgreSQL │   state: tenants, policies, users, audit
 agents ──HTTPS─────▶ │  (REST API)   │─────▶│ object store│  artifacts: local dir or S3 (Garage)
   │                  └──────┬───────┘      └────────────┘
   └──mTLS──▶ NATS ◀────────┘  (the Core authorizes every connection)
 branch office: agents ──▶ proxy ──▶ Core
```

| Component | Required | Notes |
|-----------|----------|-------|
| `delbert-core` | yes | Rust, stateless apart from its database and artifact store. One replica unless artifacts are in S3 and no local content sources are used |
| PostgreSQL 17 | yes | Plain SQL migrations run by the Core at start. Bundled (single instance) by the container and Helm installs; use a managed service or an operator (e.g. CloudNativePG) in production |
| NATS 2.10+ with JetStream | yes | Stock `nats-server`; Delbert supplies the configuration. Agents connect to it, the Core authorizes them (authorization callout) |
| Artifact storage | yes | Local directory (default) or any S3-compatible service (Garage is verified) |
| `delbert-web` | recommended | The administration UI (Next.js), container image only. Talks to the Core server-side |
| `delbert-agent` | on every managed host | Linux (static binary, deb/rpm) and Windows (MSI, preview: [WINDOWS.md](WINDOWS.md)). Outbound connections only |
| `delbert-proxy` + a NATS | optional | One per branch office whose hosts must not reach the Core ([PROXY.md](PROXY.md)) |
| `delbert-operator` | optional | In a workload cluster: delivers configuration to namespaces ([OPERATOR.md](OPERATOR.md)) |
| `git` | optional | Only next to the Core, for git content sources ([CONTENT.md](CONTENT.md)) |
| OIDC provider | optional | Keycloak, Microsoft Entra ID, ... for single sign-on |

The Core and the proxy never run commands on managed systems; only agents act, on their own host.

Network: agents and users must reach the **Core** (HTTPS, default port 8443) and agents must reach **NATS** (TLS, port 4222), both by the DNS names put in the certificates. Agents verify the Core's certificate against the Delbert CA, so **no TLS-terminating proxy or ingress goes in front of the Core API**. Nothing ever connects to an agent.

## Keys

One command creates everything an installation needs (the CA, the server certificates of the Core and of NATS, the Core's NATS client certificate, the secrets key, the NATS callout issuer and the policy signing key `k1`). It keeps the files that already exist, so it can be run again.

```sh
delbert-pki --dir keys bootstrap --core-dns delbert.example.com --nats-dns nats.example.com
```

The `--core-dns` / `--nats-dns` names (repeat the flag) must be the ones agents, users and the Core itself really use: add the in-cluster or in-compose names too (`delbert-core`, `delbert-nats`, ...; each install path below says which). The container install runs this for you; for Kubernetes and for packages you run it once on an administration machine, from the `delbert-tools` package or image:

```sh
podman run --rm -v "$PWD/keys":/keys:Z ghcr.io/bytehawks-org/delbert-tools:<version> \
  delbert-pki --dir /keys bootstrap --core-dns delbert.example.com --nats-dns nats.example.com
```

| File | Purpose | If lost |
|------|---------|---------|
| `ca.key` | issues every certificate | enrollment and renewals stop; a new CA means re-enrolling everything |
| `secrets.key` | seals tenant secrets at rest | stored secrets are unreadable and must be entered again |
| `k1.key` | signs policies | agents refuse everything until rotated ([ROTATION.md](ROTATION.md)) |
| `nats-issuer.seed` | NATS authorization callout | NATS must be reconfigured with a new issuer |
| `ca.pem` | the CA certificate (public) | given to every agent, out of band |

**Back them up offline** (see [Backup](#backup-and-restore)). Never put `ca.key`, `secrets.key` or `k1.key` in an image, a config repository or a ConfigMap. The single steps (`init`, `issue-server`, ...) still exist for rotations: [ROTATION.md](ROTATION.md).

## The control plane

### A. Containers (one host with Podman or Docker)

For staging, small sites and trials that should last. Download `delbert-container-<version>.tar.gz` from the release (or copy [`deploy/container/`](../deploy/container)) to the host, then:

```sh
tar -xzf delbert-container-<version>.tar.gz && cd delbert
./install.sh --host delbert.example.com
```

`--host` is the DNS name agents and users will use for this machine. The script needs `podman compose` or `docker compose`; it writes `.env` (random passwords, mode 0600), pulls the images and starts PostgreSQL, NATS, the Core and the web UI. The keys are created on the first start by a one-shot container and live in the `delbert_keys` volume. At the end it prints the addresses, the first password of `admin` and writes `ca.pem` (the CA certificate agents need) next to the script.

| Published | Port | Notes |
|-----------|------|-------|
| Core API (HTTPS, Delbert CA) | 8443 | `DELBERT_CORE_PORT` in `.env` |
| NATS (mutual TLS) | 4222 | `DELBERT_NATS_PORT` |
| Web UI (plain HTTP) | 127.0.0.1:3000 | put a TLS reverse proxy in front of it and set `DELBERT_WEB_URL` to its public address; for a trial without TLS set `WEB_INSECURE_COOKIES=true` and `DELBERT_WEB_BIND=0.0.0.0` |

After the first login change the password of `admin`, enable MFA (administrators need it by default: `DELBERT_MFA_REQUIRED` in `.env`), then empty `DELBERT_BOOTSTRAP_ADMIN_PASSWORD`. Upgrade: `./install.sh --version <new>` (keeps `.env` and the keys). Every other Core setting can be added to the `core` service's environment in `compose.yaml` ([API.md](API.md)). To start the stack at boot with Podman enable the `podman-restart` unit (the services have `restart: unless-stopped`); Quadlet units are not provided yet.

### B. Kubernetes / K3s (Helm)

Recommended for production. The chart ([`deploy/helm/delbert`](../deploy/helm/delbert)) installs the Core, NATS, the web UI and, unless disabled, a single PostgreSQL instance. Target Kubernetes >= 1.31.

```sh
# 1. keys, on an administration machine (release name "delbert": the in-cluster names are delbert-core and delbert-nats)
delbert-pki --dir keys bootstrap --core-dns delbert.example.com --core-dns delbert-core \
                                 --nats-dns nats.example.com --nats-dns delbert-nats
# 2. the keys as a Secret
kubectl create namespace delbert
kubectl -n delbert create secret generic delbert-pki --from-file=keys/
# 3. the release
helm install delbert oci://ghcr.io/bytehawks-org/charts/delbert --version <version> -n delbert \
  --set core.publicUrl=https://delbert.example.com:8443 \
  --set nats.publicUrl=tls://nats.example.com:4222
```

The notes printed by Helm say how to read the first `admin` password and the addresses of the two `LoadBalancer` Services (on K3s they are the node addresses); point the DNS names at them. Passwords (database, NATS callout, UI session secret) are generated once and kept in the Secret `delbert-env`, which survives upgrades and `helm uninstall`.

Values you are likely to set ([`values.yaml`](../deploy/helm/delbert/values.yaml) documents all of them):

| Value | Meaning |
|-------|---------|
| `core.publicUrl`, `nats.publicUrl` | required: how agents and users reach the Core and NATS from outside |
| `postgresql.enabled=false` + `externalDatabase.url` / `.migrateUrl` (or `.existingSecret`) | use your own PostgreSQL (create the roles first, [below](#postgresql-when-you-bring-your-own)) |
| `web.ingress.enabled`, `web.ingress.host`, `web.ingress.tlsSecret`, `web.publicUrl` | publish the UI through an ingress (the browser's TLS ends there) |
| `core.service.type`, `nats.service.type` | `LoadBalancer` (default) or `NodePort` |
| `core.extraEnv` | any other Core setting, e.g. S3 artifacts ([API.md](API.md)) |
| `image.registry`, `image.tag`, `imagePullSecrets` | a private mirror |
| `networkPolicy.enabled` | only the Core may reach the bundled PostgreSQL (default on) |

Upgrade: `helm upgrade delbert oci://... --version <new> -n delbert --reuse-values`. etcd holds the `delbert-pki` Secret: enable encryption at rest. The plain manifests in [`deploy/kubernetes/`](../deploy/kubernetes) (kustomize) are the chart's ancestor and are kept for those who do not use Helm; the Operator has its own manifests ([OPERATOR.md](OPERATOR.md)).

### C. Linux packages (no containers)

`delbert-core`, `delbert-tools`, `delbert-agent` and `delbert-proxy` are published as `.deb` and `.rpm` for amd64 and arm64. The binaries are static (musl), so the same package installs on any distribution of that architecture; systemd is expected. PostgreSQL 17 and `nats-server` (2.10+) come from your distribution or their vendors. The web UI is a container image only.

```sh
# Debian / Ubuntu                                        # RHEL / Fedora / SUSE
sudo dpkg -i delbert-tools_*.deb delbert-core_*.deb      # sudo rpm -i delbert-tools-*.rpm delbert-core-*.rpm

# 1. keys (readable by the service account only)
sudo delbert-pki --dir /etc/delbert/keys bootstrap --core-dns delbert.example.com --nats-dns delbert.example.com
sudo chgrp delbert /etc/delbert/keys/*.key /etc/delbert/keys/nats-issuer.seed
sudo chmod 0640 /etc/delbert/keys/*.key /etc/delbert/keys/nats-issuer.seed

# 2. PostgreSQL roles (see below), then NATS from /usr/share/doc/delbert-core/nats.conf.example
# 3. settings: addresses in core.toml, secrets in core.env (0640 root:delbert)
sudoedit /etc/delbert/core.toml /etc/delbert/core.env
sudo -u delbert sh -c 'set -a; . /etc/delbert/core.env; delbert-core --config /etc/delbert/core.toml --check-config'
sudo systemctl enable --now delbert-core
```

The package creates the system user `delbert`, `/etc/delbert/keys` (0750 root:delbert), `/var/lib/delbert-core` and a hardened unit (`delbert-core.service`: no privileges, read-only system). The NATS server's user must be able to read `nats.pem`, `nats.key` and `ca.pem` (copy them to its own directory or add it to a group that can). Upgrades (`dpkg -i` / `rpm -U`) restart a running service and never replace `core.toml` / `core.env`. Removing the package stops and disables the service and keeps keys and data.

### PostgreSQL, when you bring your own

Create the database, the schema owner (runs the migrations) and the runtime login (cannot rewrite the audit trail or policy versions). The roles must exist **before** the Core starts:

```sql
CREATE ROLE delbert LOGIN PASSWORD '<owner password>';
CREATE DATABASE delbert OWNER delbert;
CREATE ROLE delbert_app NOLOGIN;
CREATE ROLE delbert_rt LOGIN PASSWORD '<runtime password>' IN ROLE delbert_app;
```

The Core takes `DATABASE_URL` (the runtime role) and `DATABASE_MIGRATE_URL` (the owner, used only at start). Use TLS to the database (`?sslmode=verify-full`) outside a trusted network. Schema changes only ever come from the migrations in the Core.

### The Core's settings and first start

All settings are in a TOML file (`delbert-core --config <file>`, or `DELBERT_CONFIG`) and/or environment variables; the environment wins. `delbert-core --check-config` prints the effective values (secrets masked) and what is wrong. Reference: [`deploy/delbert-core.example.toml`](../deploy/delbert-core.example.toml) and [API.md](API.md).

First start: the Core runs the migrations, creates the user `admin` with the bootstrap password, and serves the API. Log in, **change that password, enable MFA**, then remove the bootstrap variable. Hardening checklist:

- `server.api_docs = false` once you no longer need Swagger UI; keep the API behind your network controls.
- `auth.mfa_required = "admins"` (or `"all"`); with single sign-on, `auth.local_login = "admins"` keeps a local break-glass account.
- Behind a reverse proxy that you trust, `server.trust_forwarded = true` so the throttling and the session list see client addresses; otherwise leave it off.
- Artifacts: `artifacts.store = "s3"` for more than one replica or large files; otherwise a persistent volume at `artifacts.dir`.
- Give the Core only what it needs: it does not need access to the managed hosts, and it never connects to them.

## Agents

An agent needs: the Core URL (or the site's proxy), the CA certificate (`ca.pem`), the name it will have, and a one-time **enrollment key** created by an administrator (web UI, or `POST /v1/tenants/<tenant>/enrollment-keys` with the groups the host belongs to, a use limit and an expiry; the key is shown once). On first start it generates its own key, obtains a certificate from the Core, and from then on renews it by itself.

### Linux host with systemd

```sh
# one step: downloads the package of the latest release (checksum verified), installs, enrolls, starts
sudo sh install-agent.sh --core-url https://delbert.example.com:8443 --ca-file ca.pem \
                         --agent-id web-01 --psk <enrollment key>
```

[`install-agent.sh`](../packaging/install-agent.sh) is published with each release; `--package <file>` installs a package you already have (air-gapped hosts), `--version` pins a release. It removes the enrollment key from `/etc/delbert/agent.env` once the agent is enrolled. The same by hand:

```sh
sudo dpkg -i delbert-agent_*.deb                 # or: sudo rpm -i delbert-agent-*.rpm
sudo install -m 0644 ca.pem /etc/delbert/ca.pem
sudoedit /etc/delbert/agent.env                  # URL, agent name, enrollment key (file is 0600)
sudo systemctl enable --now delbert-agent
journalctl -u delbert-agent -f
```

Hosts without dpkg or rpm (Alpine, Arch, ...): unpack `delbert-<version>-linux-<arch>.tar.gz`, copy `delbert-agent` to `/usr/bin` and install [`deploy/systemd/delbert-agent.service`](../deploy/systemd/delbert-agent.service) and [`agent.env.example`](../deploy/systemd/agent.env.example) yourself (or the init system's equivalent of `delbert-agent run` with that environment).

The package also installs `delbert` and `dg` (commands that change) and `overlook` (commands that only look) as aliases of `delbert-agent` ([POLICY.md](POLICY.md) "The command line"); `overlook check policy.yaml` is the quick way to see whether a host has drifted. The identity is kept in `/var/lib/delbert/identity`; to re-enroll, delete that directory and give a new key. The agent runs as root because it changes the host; it opens no port. `DELBERT_INTERVAL_SECS` is how often it re-checks without a notification (default 300). The `package` verb supports apt, dnf, zypper and apk; `service` drives systemd.

### Windows

Preview: read [WINDOWS.md](WINDOWS.md) for what works and how far it is tested.

```powershell
.\install-agent.ps1 -CoreUrl https://delbert.example.com:8443 -CaFile .\ca.pem -AgentId web-01 -EnrollKey <key>
# or, unattended (GPO, Intune, SCCM):
msiexec /i delbert-agent-<version>-x64.msi /qn CORE_URL=https://delbert.example.com:8443 CA_FILE=C:\Temp\ca.pem AGENT_ID=web-01 ENROLL_PSK=<key>
```

### Container

`ghcr.io/bytehawks-org/delbert-agent` with the same variables manages **its own container**: use it for test environments, not to manage a host.

### Kubernetes

Install the agent on the nodes' hosts as above (it manages the OS of the node). Configuration for workloads is delivered by the in-cluster Operator: [OPERATOR.md](OPERATOR.md).

## A branch-office proxy (optional)

For sites whose hosts must not reach the Core. The proxy has its own NATS at the site and is the only component that talks to the Core. Full description: [PROXY.md](PROXY.md). With the `delbert-proxy` package (or the `delbert-proxy` image):

```sh
sudo dpkg -i delbert-proxy_*.deb                                   # creates the user delbert-proxy and /var/lib/delbert-proxy
# one-time key from the Core: POST /v1/proxies (site name, DNS names of the proxy)
sudo -u delbert-proxy delbert-proxy enroll --core-url https://delbert.example.com:8443 --ca-file ca.pem --psk <key> --site <site>
# the site's NATS from deploy/dev/nats-site.conf, then:
sudoedit /etc/delbert/proxy.env
sudo systemctl enable --now delbert-proxy
```

Agents of the site then enroll against the proxy's URL (`https://<proxy>:8443`).

## Optional integrations

- **Single sign-on:** register the Core's callback `<public_url>/v1/auth/sso/<provider>/callback` at Keycloak/Entra ID, then create the provider in the web UI or with `POST /v1/sso/providers` ([API.md](API.md), verified with Keycloak). Set the Core's `server.ui_url` to `<UI URL>/auth/callback`.
- **Policies from git or a directory:** content sources ([CONTENT.md](CONTENT.md), [REPOSITORY.md](REPOSITORY.md)); a local Forgejo/Gitea inside your stack works as the remote.
- **S3 artifacts:** a Garage (or other S3) bucket and the `artifacts.s3_*` settings.

## Backup and restore

| Item | How | Changes |
|------|-----|---------|
| PostgreSQL | `pg_dump -Fc delbert` (or your platform's backups / PITR) | constantly |
| Artifact store | the directory or bucket (object versioning on S3) | with uploads |
| Content directories | `DELBERT_CONTENT_DIR`; git mirrors can be re-fetched, `directory` sources are the only copy | with edits |
| Keys (`ca.key`, `secrets.key`, `k1.key`, `nats-issuer.seed`, certificates) | offline, encrypted | rarely |
| Configuration (`.env`, Helm values, `core.toml`) | your configuration management | rarely |

Per install path:

```sh
# containers: database, keys, Core data (artifacts and content)
podman compose exec -T postgres pg_dump -U delbert -Fc delbert > delbert.dump
podman run --rm -v delbert_keys:/keys:ro -v "$PWD":/out:Z docker.io/library/alpine tar -C /keys -czf /out/keys.tar.gz .
podman run --rm -v delbert_core:/data:ro -v "$PWD":/out:Z docker.io/library/alpine tar -C /data -czf /out/core-data.tar.gz .

# Kubernetes: the keys are the directory you created the Secret from; database and the Core's volume
kubectl -n delbert exec delbert-postgresql-0 -- pg_dump -U delbert -Fc delbert > delbert.dump
kubectl -n delbert exec deploy/delbert-core -- tar -C /var/lib/delbert-core -czf - . > core-data.tar.gz

# packages: /etc/delbert (keys and settings), /var/lib/delbert-core, and pg_dump
```

NATS (JetStream) and the agents' local state need no backup: agents rebuild from the Core, and they keep their identity on disk.

Restore: 1) recreate PostgreSQL and restore the dump (`pg_restore`; create the roles first), 2) restore the key files and the artifact store/content directories, 3) start the Core with the same configuration (migrations are idempotent), 4) start NATS with the same issuer key. Agents reconnect on their own. The audit trail's hash chain is restored with the database; verify it with `GET /v1/audit/verify` afterwards. Test a restore before you need one.

## Upgrades

Back up first. Start the new Core (image tag, chart version or package): it applies the pending migrations on start (forward only; there is no automatic downgrade). While the project is below 1.0 read [CHANGELOG.md](CHANGELOG.md) before each upgrade: some changes are breaking. Upgrade the Core first, then proxies and agents (wire compatibility between versions is not guaranteed yet: the CHANGELOG says when it breaks). Agents are upgraded with their package (`dpkg -i` / `rpm -U` restart the service; a newer MSI replaces the old one); the identity is kept.

## Releases

Pushing a tag `vX.Y.Z` (equal to the workspace version in `Cargo.toml`) runs [`.github/workflows/release.yml`](../.github/workflows/release.yml):

| Artifact | Where |
|----------|-------|
| Images `delbert-core`, `-agent`, `-proxy`, `-operator`, `-tools`, `-web` (amd64), signed with cosign (keyless), with SBOM and provenance attestations | `ghcr.io/<owner>/delbert-<name>:<version>` |
| Helm chart | `oci://ghcr.io/<owner>/charts/delbert` |
| `delbert-{agent,core,proxy,tools}` as `.deb` / `.rpm`, and `delbert-<version>-linux-<arch>.tar.gz` (static binaries), amd64 and arm64 | GitHub release |
| `delbert-agent-<version>-x64.msi`, `delbert-agent-<version>-windows-x64.zip` | GitHub release |
| `install-agent.sh`, `install-agent.ps1`, `delbert-container-<version>.tar.gz`, `SHA256SUMS` | GitHub release |

Verify an image: `cosign verify ghcr.io/<owner>/delbert-core:<version> --certificate-identity-regexp 'https://github.com/<owner>/delbert/.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com`. Set the repository variable `PACKAGE_MAINTAINER` (`Name <address>`) for the package metadata. The packages are not signed and there is no apt/dnf repository yet; the installers verify the SHA-256 from `SHA256SUMS`.

## Building the artifacts yourself

```sh
git clone https://github.com/bytehawks-org/delbert.git && cd delbert
# images (targets: core, agent, proxy, operator, tools, web)
podman build --target core -t <registry>/delbert-core:<tag> .
# static binaries and deb/rpm (needs cargo-zigbuild with zig, the Rust target and nfpm)
packaging/build-packages.sh 0.1.0 x86_64-unknown-linux-musl dist
packaging/test-packages.sh dist podman          # installs them in clean Debian and Fedora containers
# Windows (on Windows, WiX 5): cargo build --release -p delbert-agent, then
wix build packaging\windows\delbert-agent.wxs -arch x64 -d Version=0.1.0 -d BinDir=target\release -o delbert-agent.msi
```

For the container install with your own images: `./install.sh --host <name> --registry <registry> --version <tag>`; for the chart: `--set image.registry=<registry> --set image.tag=<tag>` with `helm install delbert deploy/helm/delbert`.

## How far the installers are verified

| Piece | Verified how (2026-11-10) |
|-------|---------------------------|
| `delbert-pki bootstrap` | run; idempotent second run |
| Container install (`install.sh`, compose) without the web UI | run with Docker 29: keys created by the one-shot container, NATS callout, Core healthy; a tenant, a policy and an enrollment key created; a static agent enrolled through the published name and ports and applied the policy |
| Web UI in the container install | not run (the service definition mirrors the e2e stack) |
| Static (musl) binaries of every crate | built; Core and agent run as above |
| Package content: maintainer scripts, users, modes, `core.toml` accepted by `--check-config`, agent apply/check | run in Debian 13 and Fedora containers on a hand-laid layout |
| The `.deb` / `.rpm` files themselves (nfpm), `install-agent.sh` download path | **not built here**: first exercised by the `packaging` CI job (`test-packages.sh`) |
| Helm chart | **not rendered here** (no Helm in the development sandbox): `helm lint` and `helm template` run in the `packaging` CI job; never installed on a cluster |
| Windows agent, service, MSI, `install-agent.ps1` | compiled for Windows only: see [WINDOWS.md](WINDOWS.md); first run is the `windows` CI job |
| Release workflow | never run (no tag pushed) |

## Troubleshooting

- `delbert-core --check-config` first; the Core logs the reason it refuses to start.
- An agent that cannot enroll: wrong CA file, the Core name is not in the certificate's `--core-dns` list, key expired or used up (the audit trail has `agent.enroll` outcomes).
- Policies do not arrive: the agents list shows `effective_version` against `reported_version`; check the agent's journal (Windows: `C:\ProgramData\Delbert\logs\agent.log`) and that NATS is reachable at `nats.public_url`.
- Every login or agent is refused after a NATS change: the callout issuer public key in NATS must match `nats-issuer.seed` of the Core.
- "multi-factor authentication is required": administrators must enroll MFA before using the API (`POST /v1/me/mfa/enroll`, or the profile page of the UI).
- Disk usage while building: use `CARGO_INCREMENTAL=0` and a named target volume ([TESTING.md](TESTING.md)).

## Known limits

- No release published yet; packages are unsigned and there is no apt/dnf repository; images are amd64 only.
- Helm chart never installed on a cluster; no PodDisruptionBudget or HA of NATS and the Core; the bundled PostgreSQL is a single instance without backups of its own.
- No Quadlet units for Podman; the web UI has no package (container image only) and needs a TLS reverse proxy in the single-host install.
- Windows agent is a preview ([WINDOWS.md](WINDOWS.md)): no `package`, ACLs, remediation or containers there.
- The CA certificate reaches agents out of band (there is no fingerprint-pinned download from the Core).
- See [ROADMAP.md](ROADMAP.md) for everything else.
