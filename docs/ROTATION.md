# Delbert - Key and certificate rotation

What rotates, how, and what is still manual. Every procedure below was run end to end on 2026-10-23 with a Core, NATS and an agent in containers ([TESTING.md](TESTING.md)), except where marked.

| Secret | Rotation | State |
|--------|----------|-------|
| Agent certificate and key | automatic: agents renew before expiry with a **new key**; the previous key stays valid until the new one is seen; at least 1 h between renewals | done |
| **Policy signing key** (Ed25519) | in-band, with overlap, no touching of agents ([below](#rotating-the-policy-signing-key)) | done |
| **Internal CA** | in-band bundle with overlap, forced renewal of certificates, readiness API ([below](#rotating-the-internal-ca)) | done |
| **Proxy certificate** | automatic renewal with a new key, like agents; the proxy restarts to use it ([below](#proxy-certificate)) | done (Core side and unit tests; not run in a live branch scenario) |
| **Secrets key** (age) of the Core | old keys stay readable, one call re-seals everything ([below](#secrets-key)) | done |
| **NATS authorization-callout issuer** | switch NATS and the Core together ([below](#nats-callout-issuer)) | done (short interruption) |
| Enrollment keys, API tokens, sessions | expiring by design; revoke any time | done |
| Database password | external (PostgreSQL role); restart the Core | manual |

## Rotating the policy signing key

Agents trust a list of public keys (`trusted-keys.txt`, learned at enrollment). A policy signed by a trusted key may carry a **trust update** inside the signed payload (`trust.add`, `trust.remove`), so a rotation is authenticated by the key it replaces and needs no access to the hosts. Safety rules, enforced by the agent: a key id already known is never replaced by a different key; the key that signed a policy cannot remove itself in that same policy; the last key is never removed; malformed updates are ignored and logged.

Configuration of the Core (environment or `[policy]` in the config file):

| Setting | Meaning |
|---------|---------|
| `DELBERT_SIGNING_KEY_FILE`, `DELBERT_SIGNING_KID` | the key policies are signed with |
| `DELBERT_SIGNING_PUBLISH_KEYS` | `kid=publickey,...` announced to agents in every policy (and given to new agents at enrollment) |
| `DELBERT_SIGNING_RETIRE_KEYS` | `kid,...` agents are told to forget. The Core refuses to start if this lists its active key |

Agents report the key ids they trust; `GET /v1/signing/keys` (global `keys:read`) shows the active, published and retiring keys and, for each key, how many agents (reporting within 7 days) know it and which do not.

Procedure:

1. **Generate** the new key: `delbert-sign keygen k2 --dir <dir>` (prints the public key).
2. **Announce.** Keep signing with `k1`, add `DELBERT_SIGNING_PUBLISH_KEYS=k2=<public key>`, restart the Core. Agents learn `k2` at their next pull.
3. **Wait** until `GET /v1/signing/keys` shows `k2` known by every agent that matters (`missing` empty). Agents that are off for longer than their policy lifetime may not learn it: do not skip this step.
4. **Switch.** `DELBERT_SIGNING_KEY_FILE`/`KID` to `k2`; keep `k2` published (and `k1` if you want slow agents to still learn it), restart. Policies are now signed with `k2`; agents still accept `k1`.
5. **Retire** after one policy lifetime (`DELBERT_POLICY_TTL_SECS`, default 24 h): set `DELBERT_SIGNING_RETIRE_KEYS=k1`. Agents drop `k1` when they pull a policy signed by `k2`.
6. **Clean up** the settings after every agent reported only `k2` (or leave them: applying an update twice is a no-op).

An agent that was offline through the whole sequence knows only `k1` and cannot verify policies signed with `k2`: it must be enrolled again. That is why step 3 exists.

Verified on 2026-10-23 with a Core and an agent in containers: announce `k2` (the agent logged `trusted signing keys are now: k1, k2`), switch signing to `k2` (the next policy applied), retire `k1` (`now: k2`), and a Core configured to retire its active key refused to start. The unit test `signing_key_rotation_end_to_end` replays the same sequence with real signatures, including that a retired key no longer verifies and that a forged update fails on the signature.

## Compromise of the signing key

Rotation does not help against an attacker who already holds the private key and can reach your agents' network path: they can sign policies for any agent until it forgets the key. Treat it as an incident: switch and retire as above (the retirement is itself signed by the new key), shorten `DELBERT_POLICY_TTL_SECS` while it runs, and review the audit trail. An `external` signing mode (the key outside the Core, e.g. in an HSM) is on the roadmap.

## Rotating the internal CA

Agents, proxies and NATS trust a **bundle** of CA certificates; the Core issues from one of them. A signed policy can announce CAs to add, CA fingerprints (SHA-256, hex) to forget, and a moment before which certificates must be replaced, so no host is touched by hand. The agent only adds certificates that are valid self-signed CA certificates and never ends with an empty bundle.

Settings of the Core (environment or `[pki]`): `DELBERT_CA_CERT_FILE`/`DELBERT_CA_KEY_FILE` (the CA that issues), `DELBERT_CA_EXTRA_FILES` (other CA certificates to announce and hand to new components), `DELBERT_CA_RETIRE` (fingerprints to forget; the Core refuses to start if this lists its active CA), `DELBERT_CERT_RENEW_ISSUED_BEFORE` (Unix seconds). Agents report the CAs they trust and the one that issued their certificate; `GET /v1/pki/ca` (global `keys:read`) shows, per CA, how many agents trust it, how many certificates it issued and who is missing.

1. **Create CA2** (`delbert-pki --dir <new dir> init`) and issue new server certificates from it for NATS and the Core, and the Core's NATS client certificate (`issue-server`, `issue-client`).
2. **Announce.** Add `ca2.pem` to `DELBERT_CA_EXTRA_FILES`, give NATS a `ca_file` that contains **both** CAs and the Core a NATS CA file with both, restart. Agents learn CA2 at their next pull. Wait until `/v1/pki/ca` shows every agent trusting CA2.
3. **Switch.** Point `DELBERT_CA_CERT_FILE`/`KEY_FILE` to CA2, move CA1 to `DELBERT_CA_EXTRA_FILES`, install the CA2-issued server certificates (Core API, NATS, the Core's NATS client), set `DELBERT_CERT_RENEW_ISSUED_BEFORE` to now, restart. Agents renew their certificates (new key, from CA2) and reconnect; the status shows `issued_certificates` moving to CA2. Proxies renew on their own schedule or when restarted after `renew` is due (below); renew them before step 4.
4. **Retire.** When no certificate issued by CA1 is in use: `DELBERT_CA_RETIRE=<fingerprint of CA1>`, empty `DELBERT_CA_EXTRA_FILES`, NATS `ca_file` with CA2 only, restart. Agents drop CA1.

Do not retire a CA while server certificates (Core, NATS) are still issued by it, or while agents still hold certificates from it: they would lock themselves out. An agent that stays offline through steps 2-4 must be enrolled again. Verified live: announce (agent bundle 1 → 2 CAs), switch (agent certificate renewed from CA2 and reconnected, next policy applied), retire (bundle 2 → 1, next policy applied), and the refusal to retire the active CA.

## Proxy certificate

The proxy renews its certificate before it expires (less than a third of the lifetime left, or `--renew-before-secs`, never within an hour of issuing; checked every `DELBERT_RENEW_CHECK_SECS`, default 3600) by sending a CSR with a **new key**, signed with the current key, to `POST /v1/proxies/{site}/renew`. The Core keeps the previous key valid until the new one is used (for the NATS callout and the signed requests). Because the proxy's NATS clients, HTTPS listener and the site's NATS server all use the certificate files, the proxy writes them atomically and then **stops cleanly**; run it under a supervisor that restarts it (systemd `Restart=always`, a container restart policy, a Kubernetes pod) and restart or reload the site's NATS server with it. The renewal response carries the Core's current CA bundle, so a CA rotation reaches proxies at their next renewal.

## Secrets key

Tenant secrets, TOTP secrets, SSO client secrets and git tokens are sealed with the Core's age key. To rotate: create a new key (`delbert-pki secrets-key` in a new directory), set `DELBERT_SECRETS_KEY_FILE` to it and `DELBERT_SECRETS_OLD_KEY_FILES` to the previous one(s), restart (everything stays readable; new data uses the new key), then `POST /v1/secrets/reseal` (global `keys:write`) re-seals every value, and `GET /v1/secrets/key` reports how many still need an old key. When that is zero for every kind, remove the old key from the configuration and destroy it. Keep the old key in your backups until the next backup cycle has captured the re-sealed data.

## NATS callout issuer

NATS accepts one authorization-callout issuer, so the switch is a short interruption (seconds): generate a new issuer (`delbert-pki nats-issuer` in a new directory), then restart NATS with the new public key (`NATS_ISSUER_PUBLIC`) and the Core with the new seed (`DELBERT_NATS_ISSUER_SEED_FILE`) together. Connected agents drop and reconnect, and are authorized again by the Core with the new issuer. Verified live: the agent reconnected within 4 seconds and the next policy arrived. A proxy's site NATS has its own issuer, rotated the same way with `delbert-proxy` (re-enroll the issuer by regenerating `local-issuer.*` and reloading the site NATS).
