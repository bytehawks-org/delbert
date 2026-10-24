# Delbert - Proxy

The proxy is the only component of a branch office that talks to the Core ([ABSTRACT.md](ABSTRACT.md) §2). The agents of the site never reach the Core: their network can be completely isolated, with a single outbound path from the proxy.

```text
 branch office                                        headquarters
 ─────────────                                        ────────────
  agent ──mTLS──▶ NATS (site) ◀──▶ delbert-proxy ──mTLS──▶ NATS ◀──▶ delbert-core ─▶ PostgreSQL
  agent ──HTTPS──────────────────▶ delbert-proxy ──HTTPS──▶ delbert-core
```

## What runs at the site

| Component | Role |
|-----------|------|
| NATS server of the site | Stock `nats-server`: mutual TLS with certificates of the Delbert CA and an authorization callout. Server certificate: the proxy's. See `deploy/dev/nats-site.conf`. |
| `delbert-proxy` | Serves the callout of the site's NATS, relays, queues and caches (below), and exposes HTTPS to the agents. |

## What the proxy does

- **Local authorization.** The site's NATS asks the proxy who may connect (same model as the Core's callout, own issuer key). The proxy decides from an **allow-list** of its agents and their public keys, synchronized from the Core and stored on disk, so the site keeps authorizing its agents while the Core is unreachable. Agents get exactly their own subjects, as with a direct connection.
- **Relay of requests.** Policy requests and certificate renewals are checked locally (the agent's proof) and relayed to the Core on `delbert.proxy.<site>.relay` with the proxy's proof. The agent's proof travels inside, so the Core verifies the agent as if it were connected directly. The Core only accepts relays for agents enrolled through that proxy.
- **Notifications** published by the Core for the agents of the site are republished on the site's NATS. Changes to the list of agents (enrollment, deletion, renewal) reach the proxy as a hint on `delbert.proxy.<site>.notify`; it also polls.
- **Cached policies.** The last answer for each agent is kept; if the Core cannot be reached the proxy serves it. It is signed by the Core, and the agent verifies signature, expiry and version itself, so a stale or tampered cache can never make an agent apply something wrong.
- **Store-and-forward of reports.** Reports are snapshots of an agent's state, so the queue keeps the **latest per agent** (one small file each): nothing that matters is lost and an outage cannot grow it. The queue is forwarded in batches and removed only when the Core acknowledges; a report that arrives out of order never replaces a newer one. This is a state view, not an event log. Audit events are different and are kept in full: `delbert.event.*.*` batches are verified (the agent's proof covers them), written to a separate queue (`events/`, up to 5000 batches) **before** the agent is told they are safe, and forwarded in order with `delbert.proxy.<s>.event` until the Core acknowledges. When the queue is full the proxy refuses and the agent keeps the events in its own spool. Verified with the link cut: the batch stayed on the proxy and reached the audit trail when the link returned.
- **Enrollment relay.** Agents enroll against the proxy's HTTPS endpoint; the proxy forwards the request with its proof and the Core assigns the agent to it. The response tells the agent to use the site's NATS and the proxy's URL.
- **Artifact cache.** Agents download artifacts from the proxy by hash; on a miss the proxy fetches the file from the Core once, verifies the SHA-256 and caches it. The agent verifies it again against the signed policy.

## Trust model

- The proxy has its own identity (Ed25519 key, certificate with URI `urn:delbert:component:proxy:<site>` and the DNS names of its endpoints) issued at enrollment with a one-time key. The certificate is used both as a client certificate towards the Core and as the server certificate of the site.
- Towards the Core the proxy's NATS connection is confined to its own subjects (`delbert.proxy.<site>.*`) plus the notifications; every request carries its proof. A deleted proxy is refused by the callout.
- **A compromised proxy** can: deny service to its site, read the non-secret policies of its agents, hold back or drop reports. It **cannot**: make an agent apply an unsigned or altered policy (agents verify the Core's signature), read the secrets (encrypted to each agent's key), act for an agent of another site, or forge an agent's report (reports carry the agent's own proof; the Core accepts a proxy's forwarded reports only for its own agents and only with valid agent proofs).
- The proxy trusts the Core's CA only; it receives no secret apart from the data of its own agents.

## Operation

1. `POST /v1/proxies` with the site name and the DNS names agents use for the proxy (HTTPS and NATS); it returns a one-time key valid 24 hours.
2. At the site: `delbert-proxy enroll --core-url ... --ca-file ... --psk ... --site ...` creates the identity (and the issuer key of the site's NATS callout, whose public part is printed).
3. Start the site's NATS server (certificate files and issuer public key from the identity) and `delbert-proxy run`.
4. Create an enrollment key for the tenant and enroll agents against `https://<proxy>:8443` instead of the Core.
5. `GET /v1/proxies` shows each proxy, its agents and when it was last seen; `GET .../agents` shows which proxy serves each agent. A proxy with agents cannot be deleted.

Configuration (environment or flags): `DELBERT_IDENTITY_DIR`, `DELBERT_STATE_DIR`, `DELBERT_LOCAL_NATS_URL`, `DELBERT_LOCAL_AUTH_PASSWORD`, `DELBERT_PUBLIC_NATS_URL`, `DELBERT_LISTEN`, `DELBERT_SYNC_SECS`, `DELBERT_FLUSH_SECS`, `DELBERT_LOCAL_SESSION_SECS`.

## Not done yet

- Certificate renewal for the proxy itself (agents renew; the proxy re-enrolls with a new key).
- High availability of a proxy (several instances sharing the queue).
- Policy caching beyond the last answer per agent, and rate limits on the local endpoints.
- A leaf-node transport as an alternative for sites that may reach the Core's network.
