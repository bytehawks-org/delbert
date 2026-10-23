# Delbert - Key and certificate rotation

What rotates, how, and what is still manual. Verified end to end for the policy signing key (below); the other items are listed with their state.

| Secret | Rotation | State |
|--------|----------|-------|
| Agent certificate and key | automatic: agents renew before expiry with a **new key**; the previous key stays valid until the new one is seen; at least 1 h between renewals | done ([TESTING.md](TESTING.md)) |
| **Policy signing key** (Ed25519) | in-band, with overlap, no touching of agents (this page) | done |
| Proxy certificate | re-enroll with a new one-time key | manual; renewal like agents is on the [ROADMAP](ROADMAP.md) |
| Internal CA | issue a new CA, distribute both CAs, re-issue certificates, retire the old CA | not implemented |
| NATS authorization-callout issuer | two issuers accepted during a switch | not implemented |
| Secrets key (age) of the Core | re-seal all secrets with the new key, then retire the old | not implemented |
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
