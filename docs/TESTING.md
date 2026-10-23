# Delbert - Testing

## Automated tests

```sh
podman compose up -d postgres nats
podman run --rm --network delbert_default \
  -e DATABASE_URL=postgres://delbert:delbert-dev@postgres:5432/delbert \
  -e NATS_URL=nats://nats:4222 \
  -v "$PWD":/work:Z -w /work docker.io/library/rust:1 cargo test --workspace
```

- Unit tests: policy model, JCS, JWS, engine and verbs (file, copy, template, line_in_file, package and service with a fake command runner), compiler and conflicts.
- Integration tests (need PostgreSQL; `sqlx::test` creates a database per test): API, authentication, RBAC, audit chain, least-privilege DB role.
- NATS test (needs `NATS_URL`, skipped otherwise): notification, signed policy pull, reports.

## Server + agents in containers (end to end, mutual TLS)

`compose.e2e.yaml` runs a Core "server" (PostgreSQL 17, NATS with mTLS and authorization callout, `delbert-core` image) and two agent containers that act as managed hosts (an agent changes its own container). Everything is encrypted and authenticated with a throw-away CA.

```sh
# 1. PKI and keys (kept in ./dev, git-ignored; development only, keys are chmod 644 for the containers)
delbert-pki --dir dev/pki init
delbert-pki --dir dev/pki issue-server nats --dns nats --dns localhost
delbert-pki --dir dev/pki issue-server core --dns core --dns localhost
delbert-pki --dir dev/pki issue-client core-nats
delbert-pki --dir dev/pki secrets-key
delbert-pki --dir dev/pki nats-issuer         # key of the NATS authorization callout
export E2E_NATS_ISSUER_PUBLIC=$(cat dev/pki/nats-issuer.pub)
delbert-sign keygen k1 --dir dev            # policy signing key (dev/k1.key)

# 2. images and server side
podman build --target core  -t localhost/delbert-core  .
podman build --target agent -t localhost/delbert-agent .
podman compose -f compose.e2e.yaml up -d --no-build postgres nats core

# 3. over the HTTPS API (https://core:8080, trust dev/pki/ca.pem): log in as admin
#    (password e2e-admin-password), create tenant "acme", a secret, an artifact, the policy
#    examples/e2e-baseline.yaml, and one enrollment key per agent; then
E2E_PSK_1=... E2E_PSK_2=... podman compose -f compose.e2e.yaml up -d --no-build --no-deps agent-1 agent-2
```

Scenarios run on 2026-10-23 (all passed):

| Scenario | Result |
|----------|--------|
| Core starts: migrations as owner, runtime role `delbert_rt`, bootstrap admin, NATS over mTLS, API over HTTPS | ok |
| Agents enroll unattended (key + CA), pull the signed policy over NATS and converge: package, files, a template rendered with a **secret** and an **artifact** (downloaded over HTTPS, hash verified) | agent-1/2 `compliant: true`; `db.conf` mode 0600 with the decrypted secret |
| Enrollment with a wrong key | refused (401), nothing created |
| Enrollment against a Core whose certificate is from another CA | refused (`BadSignature`), the key is not consumed |
| Client without a certificate against NATS | TLS handshake ends with `certificate required` |
| Secret in the database / in the signed policy / in the audit trail | only age ciphertext; no plaintext anywhere |
| Secret rotated through the API | agent updates the file in about 0.5 s (notification) |
| Delete agent-2 | its requests and reports are rejected and logged; its cached policy keeps being enforced locally |
| Audit chain after all of it | verifies |
| NATS authorization callout (the real server asks the Core about every connection) | Core, agent-1, agent-2 authorized; sessions limited to 60 s in this setup |
| `probe` example with agent-1's real identity: publish/request/subscribe on another agent's subjects, `delbert.notify.*.*`, `>`, `_INBOX.>` | all six denied by the NATS server; its own subjects work |
| Delete agent-2, push a new policy after the session lifetime | agent-1 receives it; agent-2 is refused at reconnect ("authorization violation") and keeps its last state |
| Agent-4 with a renewal threshold above its certificate life | exactly one renewal, key rotated, previous key retired after the first proof with the new one, policy updates still arrive |
| Earlier scenarios (drift, notification, conflicts, Core down, RBAC, DB least privilege, graceful stop) | re-verified in the previous run, unchanged |

Findings from these runs, fixed: the real NATS server puts the client certificate in `client_tls.verified_chains`, not in `certs` (found by the first live callout); an agent whose renewal threshold exceeds the certificate life renewed on every cycle (2,198 renewals in a minute) - renewals are now at least an hour apart; `package` failed on hosts with empty apt indexes (now refreshes once and retries); Core and agent ignored SIGTERM as PID 1 (graceful shutdown); issued certificates lacked the Authority Key Identifier, which strict TLS clients (Python 3.13) reject.

Signing-key rotation, run on 2026-10-23 with the same stack (`E2E_SIGNING_KID`, `E2E_PUBLISH_KEYS`, `E2E_RETIRE_KEYS` select the stage; key files in `dev/` must be readable by the Core's user, `chmod 644`): announce `k2` while signing with `k1` -> the agent's `trusted-keys.txt` gains `k2` and `GET /v1/signing/keys` shows both keys known; sign with `k2` -> the next policy applies; retire `k1` -> the agent drops it; retiring the active key stops the Core at startup. See [ROTATION.md](ROTATION.md).

CA rotation and NATS issuer switch, run on 2026-10-23 with the same stack (`E2E_CA`, `E2E_CA_EXTRA`, `E2E_CA_RETIRE`, `E2E_RENEW_BEFORE`, `E2E_LEAF`, `E2E_NATS_CA`, `E2E_ISSUER` select the stage; a second CA and its server certificates were created with `delbert-pki` in another directory and copied next to the first one with a `2` suffix): announce CA2 -> the agent's `ca.pem` holds two certificates and the status shows both trusted; switch to CA2 with `E2E_RENEW_BEFORE=now` -> the agent renewed (new key, issued by CA2), reconnected, applied the next policy; retire CA1 -> bundle back to one certificate, next policy applied; a Core that retires its active CA refuses to start; new NATS issuer (NATS and Core restarted together) -> the agent reconnected in 4 s. See [ROTATION.md](ROTATION.md).

Probe: `cargo run -p delbert-agent --example probe -- <identity dir> tls://nats:4222 <other agent>` (copy an agent's `identity/` directory out of its container first).

Not covered: `service` on a real systemd host (unit tests with a fake runner only), Windows, Kubernetes, the `external` signing mode in a deployed flow.

## A branch office behind a proxy (end to end)

`compose.e2e-branch.yaml` adds a site on an **internal** network (no route to the Core or the internet): the site's NATS, `delbert-proxy`, and an agent. Only the proxy is also attached to the Core's network. See [PROXY.md](PROXY.md) for the design.

```sh
podman build --target proxy -t localhost/delbert-proxy .
# Core side up as above, then, as admin: create the proxy ("dns_names": ["proxy", "nats-site"]) and a policy for group "branch"
podman run --rm --network delbert_default -v $PWD/dev/pki/ca.pem:/ca.pem:ro,Z -v $PWD/dev/proxy-identity:/identity:Z \
  --entrypoint delbert-proxy localhost/delbert-proxy enroll --core-url https://core:8080 --ca-file /ca.pem --psk <proxy key> --site branch-a --identity-dir /identity
chmod 644 dev/proxy-identity/key.pem dev/proxy-identity/local-issuer.seed      # development only
export E2E_BRANCH_NATS_ISSUER=$(cat dev/proxy-identity/local-issuer.pub)
E2E_PSK_B1=<agent enrollment key, group branch> podman compose -f compose.e2e-branch.yaml up -d --no-build
```

Scenarios run on 2026-10-23 (all passed):

| Scenario | Result |
|----------|--------|
| Proxy created through the API, enrolled with its one-time key (second use refused) | certificate with the proxy identity and both DNS names; the Core's callout authorizes `proxy:branch-a` |
| Agent in the isolated network enrolls against the proxy's HTTPS, connects to the site's NATS (authorized by the proxy's callout) | assigned to the proxy (`proxy: branch-a`), converges: files, template with a **secret** and an **artifact** fetched through the proxy |
| Reachability from the agent | only `proxy` and `nats-site` resolve; `core`, `nats`, public DNS and the internet do not |
| Policy published at the Core | reaches the agent in about 0.5 s (Core, proxy, site NATS, agent) |
| **Link between proxy and Core cut** | drift still corrected; policy served from the proxy's cache; reports queue (one file per agent); the artifact is served from the proxy's cache to an agent that wiped its own |
| Policy published during the outage, link restored | applied 9 s after the link returns; queue flushed; the Core shows the agent compliant with a fresh report |
| Agent deleted at the Core | the proxy is told, its allow-list drops the agent, the site's NATS refuses its reconnection (`authorization violation`) |

Findings from this run, fixed: the NATS clients took 91 s to notice a dead link (default ping settings) - proxy and agent now ping every 10 s, recovery takes about 9 s; an agent that started before the proxy was ready waited a whole interval - without a policy it now retries after 5 s (a fresh branch converges in 7 s instead of 40 s).

Not covered: proxy certificate renewal, several proxies sharing agents, a proxy restart under load.

## SSO against Keycloak

`tests/sso.rs` uses a mock OIDC provider. The real thing was checked with Keycloak 26.4 (`start-dev`) next to a Core on the compose network: realm `delbert`, confidential client `delbert` with redirect URI `http://core:8080/v1/auth/sso/keycloak/callback`, a protocol mapper `oidc-group-membership-mapper` (claim `groups`, full path off), group `ops`, user `alice` in it (all with `kcadm.sh`). In Delbert: `POST /v1/sso/providers` with issuer `http://keycloak:8080/realms/delbert` and the mapping `ops → operator@acme` (needs `DELBERT_COOKIE_INSECURE=true` for the plain-HTTP issuer), then a scripted browser: `GET .../login`, follow to the Keycloak form, post the credentials, follow the callback and `POST /v1/auth/sso/exchange`. Remove the containers you started with `podman rm -f`, never `prune`.

## Artifact store against Garage (S3)

The S3 backend is exercised with a single-node Garage (v2.1.0) on the compose network. Throwaway setup; remove only what you created (`podman rm -f`, `podman volume rm`, never `prune`):

```sh
podman volume create delbert_garage_test
podman run -d --name delbert_garage_test --network delbert_default \
  -v ./garage.toml:/etc/garage.toml:Z -v delbert_garage_test:/var/lib/garage:Z docker.io/dxflrs/garage:v2.1.0
G="podman exec delbert_garage_test /garage"
$G status                                   # note the node id
$G layout assign -z dc1 -c 1G <node id> && $G layout apply --version 1
$G bucket create delbert-artifacts
$G key create delbert                       # prints the key id and secret
$G bucket allow --read --write --owner delbert-artifacts --key delbert
```

`garage.toml`: `db_engine = "sqlite"`, `replication_factor = 1`, `rpc_secret` (64 hex), `[s3_api] s3_region = "garage"`, `api_bind_addr = "[::]:3900"`. Then run `cargo test -p delbert-core --test blobs` with `S3_TEST_ENDPOINT=http://delbert_garage_test:3900`, `S3_TEST_BUCKET`, `S3_TEST_ACCESS_KEY` and `S3_TEST_SECRET_KEY`. In production the Core uses `DELBERT_ARTIFACT_STORE=s3` with the same settings (`DELBERT_S3_*`).
