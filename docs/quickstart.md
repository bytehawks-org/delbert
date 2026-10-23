# Delbert - Quickstart

Ten minutes on one machine: a Core with PostgreSQL and NATS, one agent, one policy, and the agent converging to it. Everything runs in Podman containers; nothing is installed on the host. This is an **evaluation** stack (throw-away CA, development passwords): for a real deployment read [install.md](install.md).

You need Podman 4+ with `podman compose`, `git`, `curl` and `jq`, and about 3 GB of disk for the first build.

## 1. Get the code and build the images

```sh
git clone https://github.com/bytehawks-org/delbert.git && cd delbert
podman build --target core  -t localhost/delbert-core  .
podman build --target agent -t localhost/delbert-agent .
podman build --target tools -t localhost/delbert-tools .
podman build --target web   -t localhost/delbert-web   .
```

The first build compiles the Rust workspace and takes several minutes.

## 2. Create the keys

Delbert runs its own small certificate authority: every component proves its identity with a certificate, and policies are signed. Generate a throw-away set in `./dev` (git-ignored):

```sh
mkdir -p dev/pki
tools() { podman run --rm -v "$PWD/dev":/dev-data:Z localhost/delbert-tools "$@"; }
tools delbert-pki --dir /dev-data/pki init                                   # the CA
tools delbert-pki --dir /dev-data/pki issue-server nats --dns nats --dns localhost
tools delbert-pki --dir /dev-data/pki issue-server core --dns core --dns localhost
tools delbert-pki --dir /dev-data/pki issue-client core-nats                 # the Core's identity towards NATS
tools delbert-pki --dir /dev-data/pki secrets-key                            # seals stored secrets
tools delbert-pki --dir /dev-data/pki nats-issuer                            # key of the NATS authorization callout
tools delbert-sign keygen k1 --dir /dev-data                                 # policy signing key
chmod a+r dev/pki/* dev/k1.key                                               # development only: the containers run as other users
```

## 3. Start the Core

```sh
export E2E_NATS_ISSUER_PUBLIC=$(cat dev/pki/nats-issuer.pub)
podman compose -f compose.e2e.yaml up -d --no-build postgres nats core web
curl --cacert dev/pki/ca.pem https://localhost:8080/healthz        # {"status":"ok"}
```

The Core created its database schema, the first administrator (`admin`, password `e2e-admin-password`) and listens on HTTPS. The web UI is at <http://localhost:3000> (sign in as `admin`; browse tenants, agents, policies with their versions, proxies and the audit trail; editing arrives in later milestones). The API documentation is at <https://localhost:8080/swagger-ui/> (your browser will not trust the throw-away CA; the `curl` commands below do, through `--cacert`).

## 4. Log in and create a tenant, an artifact and a policy

```sh
API=https://localhost:8080; C="curl -s --cacert dev/pki/ca.pem"
TOKEN=$($C -X POST $API/v1/auth/login -H 'content-type: application/json' \
  -d '{"username":"admin","password":"e2e-admin-password"}' | jq -r .token)
auth() { $C -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"; }

auth -X POST $API/v1/tenants -d '{"name":"acme"}'

# a template the policy will render on the host
printf 'greeting={{ vars.greeting }}\nhost={{ facts.hostname }}\n' > settings.conf.j2
auth -X PUT $API/v1/tenants/acme/artifacts/settings.conf.j2 \
  -H 'content-type: application/octet-stream' --data-binary @settings.conf.j2

# the policy (examples/quickstart.yaml): a directory, a file and a rendered template, for hosts in group "web"
auth -X POST $API/v1/tenants/acme/policies -d "$(jq -n --rawfile y examples/quickstart.yaml '{yaml:$y}')"
```

A **tenant** is an isolated customer or environment. A **policy** is YAML describing the desired state ([POLICY.md](POLICY.md)); the Core validates it, compiles it for each agent and signs the result. The agent never sees your YAML, only the signed, per-host version.

## 5. Enroll an agent

An agent joins with a one-time enrollment key. Create one for the group `web` and start the agent container with it:

```sh
KEY=$(auth -X POST $API/v1/tenants/acme/enrollment-keys -d '{"groups":["web"],"max_uses":1}' | jq -r .key)
E2E_PSK_1=$KEY podman compose -f compose.e2e.yaml up -d --no-build --no-deps agent-1
sleep 20
auth $API/v1/tenants/acme/agents | jq -c '.[] | {name, groups, reported_version, compliant}'
# {"name":"agent-1","groups":["web"],"reported_version":1,"compliant":true}
podman exec delbert_agent-1_1 sh -c 'cat /etc/quickstart/motd /etc/quickstart/settings.conf'
# Managed by Delbert
# greeting=hello
# host=agent-1
```

What happened: the agent generated its own key, got a certificate from the Core's CA, connected to NATS with it, pulled its signed policy, verified signature, expiry and version, applied it, and reported back. It only ever connects **outwards**.

## 6. Change the policy, then break the host

```sh
sed 's/Managed by Delbert/Managed by Delbert (v2)/' examples/quickstart.yaml > q2.yaml
auth -X POST $API/v1/tenants/acme/policies -d "$(jq -n --rawfile y q2.yaml '{yaml:$y}')"   # version 2, live at once
sleep 4; podman exec delbert_agent-1_1 cat /etc/quickstart/motd                              # Managed by Delbert (v2)

podman exec delbert_agent-1_1 sh -c 'echo tampered > /etc/quickstart/motd'                   # drift
sleep 25;  podman exec delbert_agent-1_1 cat /etc/quickstart/motd                            # restored by the next cycle
```

Policies are immutable versions; the new one reached the agent in seconds through a notification, and drift is corrected at every cycle (20 s here, 5 minutes by default).

## 7. Look at the audit trail

```sh
auth "$API/v1/audit?limit=5" | jq -r '.events[] | "\(.seq) \(.action) \(.actor) \(.outcome)"'
auth $API/v1/audit/verify | jq -c .      # {"events":11,"first_bad":null}: the hash chain is intact
```

Every change is an append-only, hash-chained event; `GET /v1/audit/export` produces NDJSON for a SIEM.

## 8. Clean up

```sh
export E2E_NATS_ISSUER_PUBLIC=x
podman compose -f compose.e2e.yaml down -v
rm -rf dev settings.conf.j2 q2.yaml
```

(`down -v` removes only the volumes of this compose file. Do not use `podman volume prune` or `podman system prune` on a machine shared with other projects.)

## Where next

- Real deployment on Kubernetes/K3s, hosts with systemd, a branch-office proxy, backups: [install.md](install.md).
- Policy format and verbs: [POLICY.md](POLICY.md). API: [API.md](API.md).
- Users, roles per tenant, four-eyes approval, MFA, single sign-on: [RBAC.md](RBAC.md), [API.md](API.md).
- Policies from a git repository: [CONTENT.md](CONTENT.md). Key rotation: [ROTATION.md](ROTATION.md).
