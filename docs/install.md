# Delbert - Installation

How to run Delbert for real: the control plane (Core, PostgreSQL, NATS), agents on hosts, and optionally a proxy at a branch office. For a ten-minute trial on one machine see [quickstart.md](quickstart.md).

**State of the project:** unreleased (v0.x). There are no published images, packages or Helm chart yet; you build the images from this repository. The web UI is not built yet (administration is through the API and Swagger UI). The Kubernetes manifests in `deploy/kubernetes/` follow the settings exercised in the container tests but **have not been run on a cluster yet**. Read the "Known limits" at the end before relying on it.

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
| PostgreSQL 17 | yes | Plain SQL migrations run by the Core at start. Use a managed service or an operator (e.g. CloudNativePG) in production |
| NATS 2.10+ with JetStream | yes | Stock `nats-server`; Delbert supplies the configuration. Agents connect to it, the Core authorizes them (authorization callout) |
| Artifact storage | yes | Local directory (default) or any S3-compatible service (Garage is verified) |
| `delbert-agent` | on every managed host | Outbound connections only |
| `delbert-proxy` + a NATS | optional | One per branch office whose hosts must not reach the Core ([PROXY.md](PROXY.md)) |
| `git` | optional | Only in the Core image/host, for git content sources ([CONTENT.md](CONTENT.md)) |
| OIDC provider | optional | Keycloak, Microsoft Entra ID, ... for single sign-on |

The Core and the proxy never run commands on managed systems; only agents act, on their own host.

## 1. Build the images

```sh
git clone https://github.com/bytehawks-org/delbert.git && cd delbert
podman build --target core  -t <registry>/delbert-core:<tag>  .
podman build --target agent -t <registry>/delbert-agent:<tag> .
podman build --target proxy -t <registry>/delbert-proxy:<tag> .
podman build --target tools -t <registry>/delbert-tools:<tag> .     # delbert-pki, delbert-sign
podman push <registry>/delbert-core:<tag>                             # ...and the others you need
```

## 2. Create the keys (once, and keep them safe)

Do this on an administration machine, not on the cluster. The directory holds the most sensitive material of the installation.

```sh
mkdir keys
tools() { podman run --rm -v "$PWD/keys":/keys:Z <registry>/delbert-tools:<tag> "$@"; }
tools delbert-pki --dir /keys init                                           # CA: ca.pem, ca.key
tools delbert-pki --dir /keys issue-server nats --dns nats.example.com --dns delbert-nats
tools delbert-pki --dir /keys issue-server core --dns delbert.example.com --dns delbert-core
tools delbert-pki --dir /keys issue-client core-nats                         # the Core's client certificate for NATS
tools delbert-pki --dir /keys secrets-key                                    # age key sealing stored secrets
tools delbert-pki --dir /keys nats-issuer                                    # NATS callout issuer: seed + public key
tools delbert-sign keygen k1 --dir /keys                                     # policy signing key k1
```

The `--dns` names must be the ones agents and the Core really use to reach NATS and the Core API: agents verify the server certificate against the CA and the name. Agents get the CA certificate (`ca.pem`) out of band; it is public.

What each file is, and what losing it means:

| File | Purpose | If lost |
|------|---------|---------|
| `ca.key` | issues every certificate | enrollment and renewals stop; a new CA means re-enrolling everything |
| `secrets.key` | seals tenant secrets at rest | stored secrets are unreadable and must be entered again |
| `k1.key` | signs policies | agents refuse everything until rotated ([ROTATION.md](ROTATION.md)) |
| `nats-issuer.seed` | NATS authorization callout | NATS must be reconfigured with a new issuer |

**Back them up offline** (see Backup). Never put `ca.key`, `secrets.key` or `k1.key` in an image, a config repository or a ConfigMap.

## 3. PostgreSQL

Create the database, the schema owner (runs the migrations) and the runtime login (cannot rewrite the audit trail or policy versions). The roles must exist **before** the Core starts:

```sql
CREATE ROLE delbert LOGIN PASSWORD '<owner password>';
CREATE DATABASE delbert OWNER delbert;
CREATE ROLE delbert_app NOLOGIN;
CREATE ROLE delbert_rt LOGIN PASSWORD '<runtime password>' IN ROLE delbert_app;
```

The Core takes `DATABASE_URL` (the runtime role) and `DATABASE_MIGRATE_URL` (the owner, used only at start). Use TLS to the database (`?sslmode=verify-full`) outside a trusted network. Schema changes only ever come from the migrations in the Core.

## 4. NATS

Use the stock `nats:2` image with [`deploy/dev/nats-callout.conf`](../deploy/dev/nats-callout.conf) as the base (mutual TLS with the Delbert CA, the callout account, JetStream). It needs, from the environment, `NATS_AUTH_PASSWORD` (the static password of the Core's callout service) and `NATS_ISSUER_PUBLIC` (contents of `nats-issuer.pub`), and the files `nats.pem`, `nats.key`, `ca.pem`. Give JetStream a persistent volume. NATS holds nothing that cannot be rebuilt, but losing it interrupts notifications until it is back.

## 5. The Core

All settings are in a TOML file (`delbert-core --config <file>`, or `DELBERT_CONFIG`) and/or environment variables; the environment wins. Start from [`deploy/delbert-core.example.toml`](../deploy/delbert-core.example.toml) and check it **before** starting:

```sh
delbert-core --config delbert-core.toml --check-config      # effective values (secrets masked), missing files, bad values
```

Settings you almost certainly need: `server.tls_*` (HTTPS is mandatory in production), `server.public_url`, `database.*`, `nats.*` (including `nats.public_url`, the NATS address handed to agents), `pki.*`, `policy.signing_*`, `bootstrap.admin_password` (only for the first start). Everything else is explained in [API.md](API.md).

First start: the Core runs the migrations, creates the user `admin` with the bootstrap password, and serves the API. Log in, **change that password, enable MFA** (`/v1/me/mfa/enroll`), then remove the bootstrap variable. Hardening checklist:

- `server.api_docs = false` once you no longer need Swagger UI; keep the API behind your network controls.
- `auth.mfa_required = "admins"` (or `"all"`); with single sign-on, `auth.local_login = "admins"` keeps a local break-glass account.
- Behind a reverse proxy that you trust, `server.trust_forwarded = true` so the throttling and the session list see client addresses; otherwise leave it off.
- Artifacts: `artifacts.store = "s3"` for more than one replica or large files; otherwise a persistent volume at `artifacts.dir`.
- Give the Core only what it needs: it does not need access to the managed hosts, and it never connects to them.

## 6. Where to run the control plane

### Kubernetes / K3s (recommended for production)

Manifests: [`deploy/kubernetes/`](../deploy/kubernetes) (a kustomization with the namespace, NATS and the Core). Not run on a cluster yet; review them like any third-party manifest.

```sh
kubectl create namespace delbert
kubectl -n delbert create secret generic delbert-pki \
  --from-file=ca.pem=keys/ca.pem --from-file=ca.key=keys/ca.key \
  --from-file=core.pem=keys/core.pem --from-file=core.key=keys/core.key \
  --from-file=core-nats.pem=keys/core-nats.pem --from-file=core-nats.key=keys/core-nats.key \
  --from-file=secrets.key=keys/secrets.key --from-file=nats-issuer.seed=keys/nats-issuer.seed \
  --from-file=k1.key=keys/k1.key
kubectl -n delbert create secret generic delbert-nats-tls \
  --from-file=nats.pem=keys/nats.pem --from-file=nats.key=keys/nats.key --from-file=ca.pem=keys/ca.pem
kubectl -n delbert create secret generic delbert-nats-env \
  --from-literal=NATS_AUTH_PASSWORD='<random>' --from-literal=NATS_ISSUER_PUBLIC="$(cat keys/nats-issuer.pub)"
kubectl -n delbert create secret generic delbert-core-env \
  --from-literal=DATABASE_URL='postgres://delbert_rt:<pw>@<db host>:5432/delbert' \
  --from-literal=DATABASE_MIGRATE_URL='postgres://delbert:<pw>@<db host>:5432/delbert' \
  --from-literal=DELBERT_BOOTSTRAP_ADMIN_PASSWORD='<first password, 12+ chars>' \
  --from-literal=NATS_AUTH_USER=auth --from-literal=NATS_AUTH_PASSWORD='<same as above>'
```

Edit `deploy/kubernetes/core.yaml` (the two `CHANGE` addresses in the ConfigMap), set the image in `kustomization.yaml`, then `kubectl apply -k deploy/kubernetes`. The Core and NATS are exposed with `LoadBalancer` Services (K3s serves them on the node addresses): agents must reach the Core at `public_url` (HTTPS with the Delbert CA's certificate, so **no TLS-terminating ingress in front of it**) and NATS at `nats.public_url`. PostgreSQL is not part of the manifests: use a managed instance or an operator.

### One VM or server with Podman (staging, small sites)

The container images run unchanged under Podman. For a trial use `compose.e2e.yaml` as in the [quickstart](quickstart.md); for a lasting single-host setup write Quadlet units (`.container` files) for the Core and NATS from the same settings as the Kubernetes manifests, with PostgreSQL on the host or a managed one. There is no ready-made Quadlet set yet. `docker-compose` is not a production tool and the repository's compose files use development passwords.

## 7. Agents

An agent needs: the Core URL, the CA certificate, the name it will have, and a one-time **enrollment key** created by an administrator (`POST /v1/tenants/<tenant>/enrollment-keys`, with the groups the host belongs to, a use limit and an expiry; the key is shown once). On first start it generates its own key, obtains a certificate from the Core, and from then on renews it by itself.

### Linux host with systemd

```sh
# binary (built in the agent image; it links against that image's glibc, see Known limits)
podman create --name dl-agent <registry>/delbert-agent:<tag> && podman cp dl-agent:/usr/local/bin/delbert-agent . && podman rm dl-agent
sudo install -m 0755 delbert-agent /usr/local/bin/delbert-agent

sudo install -d -m 0700 /etc/delbert
sudo install -m 0644 ca.pem /etc/delbert/ca.pem
sudo install -m 0600 deploy/systemd/agent.env.example /etc/delbert/agent.env     # then edit: URL, agent name, enrollment key
sudo install -m 0644 deploy/systemd/delbert-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now delbert-agent
journalctl -u delbert-agent -f
```

After the first successful start remove `DELBERT_ENROLL_PSK` from `agent.env` (the identity is kept in `/var/lib/delbert/identity`; to re-enroll, delete that directory and give a new key). The agent runs as root because it changes the host; it opens no port. `DELBERT_INTERVAL_SECS` is how often it re-checks without a notification (default 300).

The `package` verb supports apt, dnf, zypper and apk; `service` drives systemd. A `command` resource is designed but not implemented.

### Container

`<registry>/delbert-agent` with the same variables manages **its own container**: use it for test environments, not to manage a host.

### Kubernetes nodes

Install the agent on the nodes' hosts as above. The in-cluster Operator for cluster objects is planned, not available. Windows hosts are not supported yet.

## 8. A branch-office proxy (optional)

For sites whose hosts must not reach the Core. The proxy has its own NATS at the site and is the only component that talks to the Core. Full description and steps: [PROXY.md](PROXY.md) (`POST /v1/proxies` for a one-time key, `delbert-proxy enroll`, the site NATS from [`deploy/dev/nats-site.conf`](../deploy/dev/nats-site.conf), `delbert-proxy run`; agents then enroll against the proxy's URL).

## 9. Optional integrations

- **Single sign-on:** register the Core's callback `<public_url>/v1/auth/sso/<provider>/callback` at Keycloak/Entra ID, then `POST /v1/sso/providers` with the issuer, client and group mappings ([API.md](API.md), verified with Keycloak).
- **Policies from git or a directory:** `POST /v1/content/sources` ([CONTENT.md](CONTENT.md)); a local Forgejo/Gitea inside your stack works as the remote.
- **S3 artifacts:** a Garage (or other S3) bucket and the `artifacts.s3_*` settings.

## Backup and restore

What to back up, and how often it matters:

| Item | How | Changes |
|------|-----|---------|
| PostgreSQL | `pg_dump -Fc delbert` (or your platform's backups / PITR) | constantly |
| Artifact store | the directory or bucket (object versioning on S3) | with uploads |
| Content directories | `DELBERT_CONTENT_DIR`; git mirrors can be re-fetched, `directory` sources are the only copy | with edits |
| `ca.key`, `secrets.key`, `k1.key`, `nats-issuer.seed`, certificates | offline, encrypted | rarely |
| Config file and environment (without secrets) | your configuration management | rarely |

NATS (JetStream) and the agents' local state need no backup: agents rebuild from the Core, and they keep their identity on disk.

Restore: 1) recreate PostgreSQL and restore the dump, 2) restore the key files and the artifact store/content directories, 3) start the Core with the same configuration (migrations are idempotent), 4) start NATS with the same issuer key. Agents reconnect on their own. The audit trail's hash chain is restored with the database; verify it with `GET /v1/audit/verify` afterwards. Test a restore before you need one.

## Upgrades

Back up first. Start the new Core image: it applies the pending migrations on start (forward only; there is no automatic downgrade). While the project is below 1.0 read [CHANGELOG.md](CHANGELOG.md) before each upgrade: some changes are breaking (for example migration `0012` moved artifact content out of the database). Upgrade the Core before the proxies and agents; agents are tolerant of newer Cores, and a new agent binary can be rolled out through your usual package or configuration tooling.

## Troubleshooting

- `delbert-core --check-config` first; the Core logs the reason it refuses to start.
- An agent that cannot enroll: wrong CA file, the Core name is not in the certificate's `--dns` list, key expired or used up (the audit trail has `agent.enroll` outcomes).
- Policies do not arrive: `GET /v1/tenants/<t>/agents` shows `effective_version` against `reported_version`; check the agent's journal and that NATS is reachable at `nats.public_url`.
- Every login or agent is refused after a NATS change: the callout issuer public key in NATS must match `nats-issuer.seed` of the Core.
- Disk usage while building: use `CARGO_INCREMENTAL=0` and a named target volume ([TESTING.md](TESTING.md)).

## Known limits

- No published images, packages or Helm chart; the agent binary is dynamically linked against the glibc of the build image (Debian 13), so older hosts may need a build on an older base.
- Kubernetes manifests not yet run on a cluster; no PodDisruptionBudget, NetworkPolicy or HA of NATS and the Core (see [ROADMAP.md](ROADMAP.md)).
- The web UI, the Kubernetes Operator, the Windows agent, per-action audit events from agents and the `command` resource are planned.
