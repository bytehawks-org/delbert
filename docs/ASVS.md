# Delbert - OWASP ASVS 4.0.3 level 2 checklist

Status of Delbert against the OWASP Application Security Verification Standard **4.0.3, level 2** (the level for applications that handle sensitive data and business logic; Delbert also manages the configuration of other hosts, which argues for level 3 in the parts that act on them). Written 2026-11-02 by reading the code and running the tests; see [SECURITY-REVIEW.md](SECURITY-REVIEW.md) for the findings behind it.

**Read this carefully.** It is a self-assessment by the author of the review, not a certification and not an independent verification. It follows the ASVS chapters and lists the requirements that matter for this product with the ASVS number; it does not enumerate all ~280 level-2 requirements one by one, and a few chapters (V1 architecture, V6.1 data classification, V10.2 malicious code) cannot be verified by reading code. Items marked ❓ were not checked.

| Mark | Meaning |
|------|---------|
| ✅ | met, with the evidence given (code, test) |
| 🟡 | partly met, or met by default configuration only |
| ❌ | not met |
| ➖ | not applicable |
| ❓ | not verified |

## Summary

| Chapter | ✅ | 🟡 | ❌ | ❓ | Main gaps |
|---------|----|----|----|----|-----------|
| V2 Authentication | 6 | 4 | 3 | 0 | no self-service password change, no breached-password check, no maximum length |
| V3 Session management | 9 | 2 | 0 | 0 | no `__Host-` cookie prefix, no step-up for sensitive actions |
| V4 Access control | 6 | 1 | 0 | 0 | MFA for administrators is a policy, optional by default |
| V5 Validation, sanitization, encoding | 6 | 1 | 1 | 1 | no SSRF protection on configurable URLs |
| V6 Cryptography | 4 | 1 | 1 | 0 | keys are files read by the process (providers planned) |
| V7 Error handling and logging | 7 | 1 | 2 | 0 | access-control failures not logged, no general security log |
| V8 Data protection | 4 | 1 | 0 | 1 | database encryption at rest left to the platform |
| V9 Communications | 2 | 2 | 0 | 0 | plain HTTP fallback (development), cipher policy is the library default |
| V10 Malicious code | 1 | 0 | 1 | 1 | images and binaries unsigned, no SBOM |
| V11 Business logic | 4 | 1 | 1 | 0 | no general API rate limit |
| V12 Files and resources | 3 | 0 | 1 | 0 | SSRF (see V5) |
| V13 API | 7 | 1 | 1 | 0 | no general rate limit; Swagger UI on by default |
| V14 Configuration | 5 | 1 | 1 | 1 | dependency exceptions need review dates; no SBOM |
| **Total** | **64** | **16** | **12** | **4** | |

(Counts are of the rows below, not of ASVS requirements.)

## V2 Authentication

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 2.1.1 | Passwords at least 12 characters | ✅ | `auth.rs` `MIN_PASSWORD = 12`, also for the bootstrap administrator |
| 2.1.2 | Allow 64, deny more than 128 characters | 🟡 | Long passwords are accepted; there is **no maximum** (the 2 MiB body limit bounds it). Add a 128-character cap |
| 2.1.5, 2.1.6 | Users can change their password (current + new) | ❌ | No self-service endpoint: an administrator sets it (`users:write`), which ends the user's sessions. Add `POST /v1/me/password` |
| 2.1.7 | Check against breached passwords | ❌ | ROADMAP ("password breach check"). The offline k-anonymity approach or a local list fits the air-gapped case |
| 2.1.9, 2.1.12 | No composition rules; password can be shown | ✅ | Length only; the console input is a normal password field |
| 2.2.1 | Anti-automation against credential stuffing and brute force | ✅ | Per user+address, per address and per user ceilings, 429 (`auth.rs`, `tests/auth.rs`); client address read from the trusted end of `X-Forwarded-For` (F-09) |
| 2.2.x | Generic failure message | ✅ | One 401 for wrong user and wrong password; a dummy hash is verified for unknown users, so response time does not tell which part was wrong |
| 2.4.1 | Passwords stored with an approved KDF | ✅ | Argon2id, per-password random salt (`auth.rs`); library default cost (19 MiB, t=2, p=1), the OWASP minimum. Raising it is a tuning decision |
| 2.5.x | Credential recovery | 🟡 | No self-service recovery by design; an administrator resets. Initial/reset secrets are not forced to change on first login (no `must_change_password` flow) |
| 2.7, 2.8 | OTP / time-based OTP | ✅ | TOTP, sealed secret, **a step is accepted once** (`totp_last_step`), recovery codes single-use, MFA failures throttled and audited |
| 2.8.x | MFA for administrators | 🟡 | `DELBERT_MFA_REQUIRED` = `none` / `admins` / `all`; the default is `none`. Recommended `admins` or `all` in production |
| 2.10.1-2.10.4 | Service credentials | 🟡 | Agents and proxies use certificates and signed proofs, API tokens are scoped, hashed and expiring (`api_tokens`). The development stack ships fixed passwords (`compose*.yaml`, documented as local only); the first administrator comes from an environment variable and is not forced to change it |
| WebAuthn / phishing-resistant MFA | (L3) | ❌ | ROADMAP |

## V3 Session management

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 3.2.1 | New session token on authentication | ✅ | A fresh 32-byte random token at every login |
| 3.2.3 | Token not in the URL | ✅ | Header or cookie only; `e2e` test "credentials never in the URL" |
| 3.2.4 | Tokens from an approved generator | ✅ | `OsRng`, 256 bits; only SHA-256 is stored |
| 3.3.1 | Logout and expiry invalidate the session server side | ✅ | `POST /v1/auth/logout` deletes the row; expired and idle rows are swept |
| 3.3.2 | Idle and absolute timeouts | ✅ | 30 minutes idle, 8 hours absolute (`IDLE_MINUTES`, `SESSION_HOURS`) |
| 3.3.4 | Users can list and end their sessions; administrators too | ✅ | `/v1/me/sessions`, `DELETE /v1/me/sessions/{id}`, administrator revoke; a password change ends all sessions |
| 3.4.1-3.4.3 | Cookie `Secure`, `HttpOnly`, `SameSite` | ✅ | `HttpOnly; SameSite=Strict`, `Secure` unless `DELBERT_COOKIE_INSECURE` (development). The console keeps the token in an encrypted cookie only its server can open |
| 3.4.4 | `__Host-` prefix | 🟡 | The Core cookie is `delbert_session`; the console cookie was not checked |
| 3.5 | Token-based sessions: API tokens | ✅ | Scoped to permissions and optionally a tenant, expiring, revocable, hash stored |
| 3.7.1 | Re-authentication for sensitive transactions | 🟡 | Disabling MFA needs password and second factor; destructive actions in the console ask for the target name; no step-up for, say, signing-key or role changes |
| CSRF (4.2.2 / 13.2.3) | Anti-CSRF | ✅ | `X-CSRF-Token` checked against a stored hash for cookie sessions; `Origin` check and `SameSite=Strict` in the console (e2e: cross-origin POST refused) |

## V4 Access control

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 4.1.1, 4.1.3 | Enforced on a trusted layer, least privilege | ✅ | Every handler checks a `resource:action` permission scoped by tenant; the UI is never the boundary (`docs/RBAC.md`) |
| 4.1.5 | Fail securely | ✅ | Unreachable tenants look missing (404); unknown role or permission denies |
| 4.2.1 | No IDOR on data and files | ✅ | `tests/tenant_isolation.rs`: tenant-admin and operator of one tenant against 17 reads and 12 writes of another, plus an auditor's list and export |
| 4.2.2 | CSRF | ✅ | see V3 |
| 4.3.1 | Administrative interfaces use MFA | 🟡 | see 2.8.x |
| 4.3.3 | Separation of duties for high-value actions | ✅ | Four-eyes approval per tenant (policies); platform-only permissions that a tenant role cannot hold. Not yet for shared artifacts and variables (ROADMAP) |
| (access to the bus) | Per-subject authorization | ✅ | NATS authorization callout confines each agent to its subjects (`delbert-natsauth`, unit tests); the certificate must match the key on record |

## V5 Validation, sanitization and encoding

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 5.1.3, 5.1.4 | Positive validation, structured data | ✅ | Names are allow-lists (letters, digits, `-_`, no dot for subject tokens); policies parse with `deny_unknown_fields` and are validated semantically; `tests/tenant_isolation.rs` (subject-breaking names) |
| 5.1.x | Hostile and oversized input | ✅ | YAML nesting is quadratic in the parser: `guard_yaml` (F-10); NUL bytes answer 422 (F-11); 2 MiB default body, 64 MiB artifacts. `tests/hostile_input.rs`, `delbert-policy/tests/robustness.rs` |
| 5.2.5 | Template injection and sandboxing | ✅ | MiniJinja has no code execution; its evaluation had **no resource limit** and a nested loop ran for ever, in the Core preview and on agents (F-12). Now bounded by `TEMPLATE_FUEL` everywhere (`delbert_policy::template_env`). `delbert-policy/tests/templates.rs` |
| 5.2.6 | SSRF protection | ❌ | Content sources (`https://` or `file://` git remotes), SSO issuers and S3 endpoints are fetched by the Core with no filter on private, loopback or link-local addresses. Mitigated by who can configure them (platform administrators; tenant git is off by default). Add an allow/deny list and resolve-then-connect checks |
| 5.3.4, 5.3.5 | SQL injection | ✅ | `sqlx` with bind parameters throughout; the few `format!` queries splice compile-time constants (`COLUMNS`) only |
| 5.3.3, 5.3.10 | Output encoding for the UI | ✅ | React escaping, strict CSP with nonce, HTML/Markdown from the API never rendered |
| 5.3.8 | OS command injection | 🟡 | The Core runs `git` with a fixed argument list (no shell, hooks off, `--`, protocol allow-list) and never touches managed systems. The agent runs package managers and `systemctl` with argument vectors; its apply path was **not reviewed** (path handling, symlinks, ownership) |
| 5.5.x | Safe deserialization | ✅ | Typed `serde` only; YAML `!tags` and aliases bounded (alias bomb test) |
| 5.x (parsers) | Parsers fed by the network | ❓ | CSR and certificate parsers survive mutation tests (`delbert-pki/tests/robustness.rs`); the YAML parser sits on an unmaintained library (RUSTSEC-2024-0449) |

## V6 Cryptography

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 6.2.1-6.2.3 | Failures fail closed; approved, current algorithms | ✅ | Ed25519 (policies, proofs, audit anchors), Argon2id, age (X25519, ChaCha20-Poly1305) for secrets, SHA-256, TLS 1.2/1.3 through rustls |
| 6.2.x | Constant-time comparison | ✅ | Hash comparison of tokens in the database; signature checks with `verify_strict` |
| 6.3.1-6.3.3 | Secure random numbers | ✅ | `OsRng` for tokens, keys, nonces, enrollment keys |
| 6.4.1 | Key management solution | 🟡 | Local, complete and the default by decision (age-sealed secrets, key files, internal CA); external KMS/HSM/Vault providers are designed as optional seams, not built |
| 6.4.2 | Keys not exposed to the application | ❌ | Signing and secrets keys are read from files into the Core process. The audit-anchor key can be a separate key (F-04) |
| (rotation) | Key and certificate rotation | ✅ | Signing key with overlap, CA, NATS issuer, secrets key, proxy certificate (`docs/ROTATION.md`, `tests/rotation.rs`) |

## V7 Error handling and logging

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 7.1.1, 7.1.2 | No credentials or secrets in logs | ✅ | Tests: a rejected enrollment key is in neither the trail nor the export; secrets are never rendered |
| 7.1.3, 7.2.1 | Authentication decisions logged | ✅ | Logins (ok, denied, throttled), MFA, tokens, enrollment (`enroll.denied`, `enroll.throttled`) are audit events |
| 7.2.2 | Access-control decisions, failures included, logged | ❌ | A 403 or masked 404 is not recorded anywhere except, at most, the request log. A separate security log (not the hash chain, which an attacker could flood) is needed |
| 7.1.4 | Enough context per event | ✅ | Actor, action, target, outcome, tenant, UTC time, details; agent events carry the drift found |
| 7.3.1 | Log injection | ✅ | Structured JSON events, canonicalized for hashing |
| 7.3.3 | Logs protected from tampering | ✅ | Append-only (trigger and privileges), hash chain, **signed anchors** with offline verification (F-01, F-03); export for a SIEM. The trail itself is not shipped off the database on a schedule yet |
| 7.3.4 | Synchronized UTC time source | ✅ | `timestamptz`, microsecond UTC in the hash |
| 7.4.1 | Generic error message with no internals | ✅ | `{"error": "internal error"}`; details only in the server log |
| 7.4.x | Last-resort handler | 🟡 | No catch-all layer: a panic inside a handler drops that connection instead of answering 500 |
| (log management) | Retention, rotation, alerting | ❌ | Not built (ROADMAP: retention, SIEM connector, NIS2 reports) |

## V8 Data protection

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 8.1.x | Sensitive data classified | ❓ | Secrets, TOTP seeds and tokens are treated as sensitive in the code; no written classification |
| 8.2.1 | No client-side caching of sensitive data | ✅ | `Cache-Control: no-store` on every API answer (F-13) and on the console pages |
| 8.3.1 | Sensitive data in the body, not the URL | ✅ | see 3.2.3 |
| 8.3.4 | Sensitive data identified and access controlled | ✅ | Secrets are write-only (never returned), per-agent re-encrypted, masked in the preview |
| 8.3.7 | Encrypted at rest | 🟡 | Secrets, TOTP seeds and Git tokens are sealed by the Core; the database and the artifact store are not encrypted by Delbert (use disk or object-store encryption) |
| 8.3.x | Minimal data collected | ✅ | Agents report a small fact subset and drift, nothing else leaves the host |

## V9 Communications

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 9.1.1 | TLS for all connections | 🟡 | HTTPS and mTLS everywhere in the documented deployment; without a certificate the Core serves plain HTTP with a warning (development) |
| 9.1.2, 9.1.3 | Strong ciphers, TLS 1.2/1.3 only | 🟡 | rustls defaults (no legacy protocols); the project states TLS 1.3 + mTLS, but a TLS 1.3-only policy is not enforced in code or in the NATS configuration examples |
| 9.2.1-9.2.5 | Server-to-server TLS, trusted certificates | ✅ | mTLS to NATS with the Delbert CA, proofs signed per request; the Operator, proxy and agents verify the CA |
| 9.2.x | Communications failure | ✅ | Agents keep the last verified policy and apply nothing unsigned |

## V10 Malicious code

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 10.2.x | No backdoors, time bombs | ❓ | Cannot be established by reading; the code was largely written with AI assistance, which argues for an independent human review |
| 10.3.1, 10.3.2 | Updates and downloads integrity protected | ❌ | No published images or packages; nothing is signed (ROADMAP: signed images, SBOM). Policies and artifacts are signed or hash-pinned |
| 10.3.x | Third-party code integrity | ✅ | `Cargo.lock` committed; CI builds from it |

## V11 Business logic

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 11.1.2, 11.1.3 | Sequential steps, realistic limits | ✅ | Policy versions are immutable, activation is a separate audited step, anti-rollback in the signed policy, enrollment keys expire and are single-use by default |
| 11.1.4 | Anti-automation | 🟡 | Login and enrollment are throttled (and the audit growth they cause is bounded); the rest of the API has no rate limit |
| 11.1.5 | Business-logic limits and four-eyes | ✅ | Per-tenant approval workflow (`tests/approval.rs`) |
| 11.1.6 | Race conditions | ✅ | Audit appends serialized by an advisory lock; key uses `FOR UPDATE` |
| (replay) | Replayed requests | ✅ | Signed agent requests accepted once (`replay.rs`, F-05) |
| General API rate limiting | | ❌ | A per-token / per-address limit on authenticated routes |

## V12 Files and resources

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 12.1.1 | Upload size limits | ✅ | 64 MiB for artifacts (413 tested), 2 MiB elsewhere |
| 12.1.2 | Compressed-file bombs | ➖ | Nothing is decompressed at runtime (the `zip` advisory concerns a build-time crate) |
| 12.3.1-12.3.2 | File names not used to build paths | ✅ | Content is addressed by tenant id and SHA-256; names are metadata (`tests/hostile_artifacts.rs`) |
| 12.4.1, 12.5.x | Files outside the web root, served safely | ✅ | Object store; downloads are `application/octet-stream` with `nosniff` |
| 12.6.1 | SSRF | ❌ | see 5.2.6 |

## V13 API and web service

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 13.1.1 | Consistent encoding and parsing | ✅ | JSON only, strict types |
| 13.1.3 | No sensitive data in URLs | ✅ | see 3.2.3 |
| 13.1.4 | Authorization at each level | ✅ | per route and per tenant |
| 13.1.5 | Unexpected content types rejected | ✅ | JSON extractor requires `application/json`; artifacts `octet-stream` |
| 13.2.1 | HTTP methods allow-listed | ✅ | 405 for others (tested in the isolation sweep) |
| 13.2.2 | Input schema validation | ✅ | typed bodies, 422 on violation |
| 13.2.5 | REST with explicit `Content-Type` | ✅ | |
| 13.1.x | API documentation exposure | 🟡 | `/openapi.json` and Swagger UI are on by default (`DELBERT_API_DOCS=false` turns them off); the public API surface is documented as necessary-only in `CLAUDE.md` |
| (rate limits, quotas) | | ❌ | see V11 |

## V14 Configuration

| ASVS | Requirement | | Evidence / gap |
|------|-------------|---|----------------|
| 14.1.x | Build and deployment pipeline | 🟡 | CI runs clippy (warnings reported, not fatal), tests with PostgreSQL and NATS, web typecheck and build, image builds. No signing, no provenance |
| 14.2.1 | Components free of known vulnerabilities | ✅ | `cargo audit` in CI and weekly; 7 advisories reviewed with reasons in `.cargo/audit.toml`. The exceptions have no review date and no owner |
| 14.2.x | Unused features removed, SBOM | ❌ | No SBOM |
| 14.3.2 | Debug modes off | ✅ | none shipped |
| 14.3.3 | No server version in headers | ❓ | not checked |
| 14.4.1-14.4.7 | HTTP security headers | ✅ | Console: strict CSP with nonce, `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy`, HSTS behind TLS. Core API: `no-store`, `nosniff`, `no-referrer`, `default-src 'none'; frame-ancestors 'none'` (F-13); the Swagger UI keeps its own |
| 14.5.2, 14.5.3 | `Origin` not used for authentication; strict CORS | ✅ | No CORS is configured; the console is same-origin through its server |
| 14.5.x | Host/proxy header trust | ✅ | `X-Forwarded-For` trusted only when configured, from the trusted hop count (F-09) |

## Gaps in priority order

| # | Gap | ASVS | Effort | Why this order |
|---|-----|------|--------|----------------|
| 1 | SSRF filter for content sources, SSO issuers, S3 endpoint | 5.2.6, 12.6.1 | medium | Reaches internal services from the Core; only platform administrators can configure it today |
| 2 | Self-service password change, maximum length, forced first change | 2.1.2, 2.1.5, 2.5.x | small | Basic account hygiene; a reset today needs an administrator |
| 3 | Security log for access-control failures (separate from the audit chain) | 7.2.2 | small | Needed to detect probing |
| 4 | General rate limit on authenticated routes | 11.1.4, 13.x | small | Availability across tenants |
| 5 | Breached-password check | 2.1.7 | small | |
| 6 | Signed images, SBOM, release pipeline | 10.3, 14.2 | medium | Required before anyone else installs it |
| 7 | MFA for administrators on by default; WebAuthn | 2.8, 4.3.1 | small / medium | Default is the weak part |
| 8 | Agent apply-path review (symlinks, ownership, argument handling) | 5.3.8 | medium | The agent runs as root on managed hosts |
| 9 | TLS 1.3-only policy, cipher policy in NATS and Core | 9.1.2 | small | The project claims TLS 1.3 |
| 10 | Schedule the export of the full audit trail; retention | 7.3, ROADMAP | medium | |

## Method and what is missing

Checked: the code of `auth.rs`, `api.rs`, `enroll.rs`, `audit.rs`, `bus*.rs`, `artifacts.rs`, `content.rs`, `variables.rs`, the crates `delbert-policy`, `delbert-pki`, `delbert-natsauth` and `delbert-wire`, the migrations for privileges, the CI workflows and the tests named above. **Not checked:** the agent's apply path and `package`/`service` verbs, the Operator, the proxy, the console's own cookie and BFF routes beyond what the e2e tests state, SSO flows against a live provider, and anything that needs a running NATS server in this environment. Re-run this list when those are reviewed.
