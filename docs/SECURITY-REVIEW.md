# Delbert - Security review (2026-11-02)

A first, partial review of the security-critical paths, done by reading the code and writing adversarial tests against a real PostgreSQL. It is **not** an independent audit: a human reviewer should repeat it, especially on the areas listed under "Not reviewed". Severity is the author's estimate for a deployment as documented.

## Findings

| Id | Severity | Finding | Status |
|----|----------|---------|--------|
| F-01 | High | The audit hash chain verified cleanly after the newest events were deleted, or after the whole history was erased and rewritten through the normal append path (every hash valid). A database administrator, or a compromised Core with a privileged connection, could remove evidence undetected. | **Fixed**: signed anchors (migration `0026`), see [API.md](API.md) "Audit anchors". Tests: `tests/audit_adversarial.rs` |
| F-02 | Medium | `POST /v1/enroll` and `POST /v1/proxies/enroll` answered a bad, expired, revoked or exhausted key with 401 but recorded **nothing**: no audit event, no throttling. Guessing a 256-bit key is infeasible, but failed attempts are exactly what NIS2 incident detection needs; auditing them naively would let an anonymous caller grow the append-only trail. | **Fixed** (2026-11-02, migration `0027`): 10 failures per address (or per proxy) in 10 minutes, then 429 before the key is looked at; failures are audited (`enroll.denied`, the key itself never) up to that ceiling per address and 200 overall per window, a throttled address once (`enroll.throttled`). Tests: `tests/enroll_throttle.rs` |
| F-03 | Medium | The anchors are stored in the same database they protect. They detect truncation and rewriting of anchored history, but whoever can delete the newest anchors *and* the newest events is only detectable against a copy kept elsewhere. | **Mitigated** (2026-11-02): every anchor is logged as a structured line (`audit.anchor`) and appended to `DELBERT_AUDIT_ANCHOR_FILE` when set; `delbert-sign verify-anchors` checks such a copy without the database, also against an audit export. It still depends on the operator putting the file/log on storage the database administrators cannot write. A console view of the anchors is not done |
| F-04 | Low | Anchors are signed with the policy-signing key (separate signature domain `delbert-audit-anchor-v1`, so no cross-use). A dedicated audit key would limit the damage of one key leaking and allow a different custody (HSM, another operator). | Open (design choice) |
| F-05 | Low | Signed requests and reports (`delbert-pki::authn`) carry a timestamp and a nonce, but the Core keeps no nonce cache: a captured proof can be replayed within the 60 s window. Impact is small (reports are ordered by their own `at`; a replayed `renew` yields a certificate for the original CSR, useless without the private key) and capture needs the TLS-protected bus. | Open |
| F-06 | Low | An enrollment key is tenant-wide, not bound to an agent name: its holder can claim any pre-created, not yet enrolled agent name of that tenant (and its group set). Keys are short-lived and single-use by default. | Open (consider binding a key to a name) |
| F-07 | Info | The authorization callout does not verify the signature of the request JWT it receives on `$SYS.REQ.USER.AUTH`; it relies on NATS permissions keeping every client away from that subject. `xkey` encryption/verification of callout messages is already on the roadmap. | Open (hardening) |
| F-09 | Medium | With `DELBERT_TRUST_FORWARDED=true` the client address was the **first** entry of `X-Forwarded-For`, which the client controls when the reverse proxy appends instead of overwriting the header: the login and enrollment throttles could be sidestepped by rotating the header, and free-form text ended up in throttle keys and audit details. | **Fixed** (2026-11-02): the entry `DELBERT_TRUST_FORWARDED_HOPS` from the right is used (default 1), it must be an IP address, otherwise the connection's address is used. Tests: `auth::client_address_tests`, `tests/enroll_throttle.rs` |
| F-08 | Info | `cargo audit` / `cargo deny` were not run (no network access to the advisory database in the review environment). | Open |

## Checked and found sound

- **Audit trail**: events are written in the same transaction as the change; appends are serialized by an advisory lock; update/delete/truncate are blocked by triggers *and* not granted to the runtime role (`0005`, `0026`). The only residual weakness was F-01.
- **Tenant isolation** (`tests/tenant_isolation.rs`): a tenant-admin and an operator of tenant A, against every tenant-scoped route of tenant B (17 reads, 12 writes): every answer is 404/405 or 403, nothing changes, the tenant list shows only A, platform routes (`/v1/users`, `/v1/proxies`, SSO, audit verify/anchors) are refused. An auditor scoped to A sees only A's events in the list and in the export. Note that the Json body is parsed before authorization (a wrong body gets 422 before 404); it leaks nothing but the shape of the route.
- **Names in bus subjects**: tenant and agent names cannot contain dots, wildcards, separators or spaces (a test covers it), so the per-agent subject permissions cannot be widened or shifted.
- **Enrollment**: the key is stored as SHA-256 of 256 random bits, looked up with `FOR UPDATE` (no over-use under concurrency), one answer for every kind of invalid key (no oracle), the certificate subject is chosen by the Core, not by the CSR.
- **Callout**: the certificate must carry exactly the public key on record for that tenant/agent (current or previous during a renewal), so deleted or rotated agents are refused and a certificate alone, without the key, is useless; permissions are confined to the agent's own subjects (unit-tested); sessions expire and are re-authorized.
- **Policy signing**: Ed25519 over JCS, verified strictly on the agent (see [ROTATION.md](ROTATION.md)); the new detached-signature API is domain-separated.

## Not reviewed

Needs a human reviewer, in this order: the agent's apply path (symlinks, ownership and modes of managed files, `package`/`service` arguments), `auth.rs` (sessions, MFA, throttling, API tokens), SSO and the BFF in `web/`, content sources (git, path handling of the editor's commits), artifact and secret handling, the proxy (store-and-forward, enrollment relay), the Operator's RBAC and its use of Secrets, container image hardening and dependencies (F-08). Also useful: fuzzing the YAML policy parser, the CSR parser and the artifact upload.

## Next steps

1. Ship the audit trail itself (not only the anchors) to the external sink, and a console view of the anchors.
2. F-05, F-06, F-04, then a review of the "Not reviewed" list by someone who did not write the code.
