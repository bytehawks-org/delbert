# Delbert - Plan

What is still missing and the order to finish it (written 2026-11-15, from the 72 open rows of [ROADMAP.md](ROADMAP.md), the requirements in `CLAUDE.md` and the MVP assessment in [STATUS.md](STATUS.md)). ROADMAP stays the inventory; this file is the sequence. Sizes are rough guesses, not measurements: **S** up to a day, **M** a few days, **L** a week or more.

## Where it stands

| | Count |
|---|---|
| Roadmap rows complete / partial / to-do | 88 / 14 / 58 |
| Automated tests | about 221 |
| Installers proven by a real run | 1 of 4 (containers; packages by content only; Helm and Windows never run) |
| Releases published | 0 |

The gaps are of three kinds: things that exist but were **never proven** (phase 0), requirements of `CLAUDE.md` that are **not met yet** (phases 1 and 2), and work that only matters at scale or on Windows (phases 3 and 4).

## Phase 0 - Prove what exists (MVP exit, no new features)

Nothing else should start before this: every later phase builds on installers and a pipeline nobody has seen work.

| # | Step | Size | Needs | Done when |
|---|------|------|-------|-----------|
| 0.1 | CI green on `main`: `rust`, `web`, `images`, `windows`, `packaging` | S-M | the logs of the first run (the jobs were written blind; expect fixes in the WiX file, the PowerShell smoke test and the Helm templates) | five green jobs |
| 0.2 | **Done 2026-11-15** ([TESTING.md](TESTING.md)). Backup and restore drill on the container install, following [install.md](install.md) to the letter | S | Docker | restored stack passes `GET /v1/audit/verify`, an agent reconnects; findings fixed in the doc |
| 0.3 | **Done 2026-11-15 for Debian** ([TESTING.md](TESTING.md)): systemd 257 in a privileged container, a hand-built `.deb`; found and fixed a bug that blocked every rollback. Still open: the same on an RPM host and with the package nfpm builds | M | a RHEL-like host | TESTING.md records the run |
| 0.4 | Helm chart on a real K3s: install, upgrade, an agent enrolled from outside the cluster | M | a K3s cluster and DNS names | TESTING.md records it; the plain manifests of the control plane are deleted |
| 0.4b | Sign the RPM and DEB packages in the release workflow (found by CI: Fedora's rpm refuses unsigned packages; the scripts pass `--nosignature` until then) | M | a signing key as a repository secret | `rpm -K` passes on a released package; `--nosignature` removed |
| 0.5 | Tag `v0.1.0`; check each artifact (images and signatures, chart, packages, MSI, `SHA256SUMS`, `install-agent.sh` download path) | S-M | 0.1 to 0.4; repository variable `PACKAGE_MAINTAINER` | a host installed from the published artifacts only |

## Phase 1 - Close the safety gaps (before anybody else runs it)

Each item is a place where today's behaviour is weaker than what the design promises.

| # | Item | Size | Why now |
|---|------|------|---------|
| 1.1 | **Done 2026-11-15.** Local YAML mode off in production: `apply`/`check` of an unsigned file only with a local opt-in (`DELBERT_ALLOW_LOCAL_POLICY`), `apply-signed` the default path | S | `CLAUDE.md`: agents verify before applying. The `dg apply file.yaml` alias made the unsigned path more visible |
| 1.2 | **Process group done 2026-11-15**; audit output and groups open. `command`: kill the whole process group at timeout; output and exit code in the audit trail with secrets masked; supplementary groups | M | ABSTRACT §3 asks for the output in the audit; a timed-out child can leave grandchildren today |
| 1.3 | **Done 2026-11-15 for `cron`, `sysctl`, `get_url`**; blocks and mounts still need `state: absent`. Orphans for `cron`, `sysctl`, `block_in_file`, `mount`: removed when they leave the policy, like files (`keep_if_absent_in_policy` to keep) | M | a job that silently survives its policy is the opposite of state enforcement |
| 1.4 | Undefined `vars.x` refused at policy save (today only the preview catches it). Looked at on 2026-11-15: variables resolve per agent (group and agent layers), so the check must render for every targeted agent and decide what to do when a variable is added after the policy: a warning in the save response, not a refusal | M | fail at authoring time, not on the agent |
| 1.5 | CA certificate fetched from the Core with a pinned fingerprint (`--ca-sha256`) | S | removes the manual `ca.pem` copy from every agent install without weakening trust |
| 1.6 | Pagination and filters on every list endpoint | M | `CLAUDE.md`: limit the public API to the necessary; unbounded lists are also a load problem |
| 1.7 | NATS callout hardening (xkey encryption, disconnect on revocation); CRL for the HTTPS endpoints | M | revocation takes effect only at session expiry today |

## Phase 2 - Requirements of `CLAUDE.md` not met yet

| # | Requirement | Missing | Size |
|---|-------------|---------|------|
| 2.1 | Conflicts: configurable strategy chain, per-resource/policy overrides, auditable resolution records | `specificity`, overrides, resolution records, impact preview (`priority` and `error` exist) | L |
| 2.2 | Active Directory/LDAP login; SAML | both (OIDC is done; Entra ID never checked against a real tenant) | L |
| 2.3 | NIS2 audit: SIEM export | connector (syslog/HTTP), signed anchors for the chain, retention (NDJSON export exists) | M |
| 2.4 | Every element has an administrative control with CRUD | console pages for deliveries, facts, an agent's events, inconsistent agents (force release), the provenance of SSO assignments; forms or snippets for the 15 verbs | L |
| 2.5 | Separation of duties | four-eyes approval for shared artifacts and variables; approval diff and impact preview; service accounts | M |
| 2.6 | OpenSSL as fallback CA backend | only if a deployment needs it: the trait and the conformance suite are ready | M, on demand |
| 2.7 | Simple backup and restore | covered by 0.2; then artifact garbage collection and retention | S |

Order inside the phase: 2.4 and 2.5 first (they make the product administrable by someone who did not write it), then 2.1, then 2.3, then 2.2.

## Phase 3 - Windows from preview to supported

| # | Item | Size |
|---|------|------|
| 3.1 | Hand-run enrollment on Windows Server and Windows 11 (after 0.1) | S |
| 3.2 | Permission model: `acl` parameters instead of refusing `owner`/`group`/`mode` | L |
| 3.3 | `package` backend: MSI delivered as a pinned artifact | M |
| 3.4 | Remediation for Windows services; Event Log | M |
| 3.5 | Local users and groups, Scheduled Tasks, `command`, `registry` verb, reboots | L |
| 3.6 | Code signing of the executable and the MSI; arm64 | M |

## Phase 4 - Scale and availability

| # | Item | Size |
|---|------|------|
| 4.1 | NATS scale and failure-mode test (the oldest open row) | M |
| 4.2 | HA of the Core and NATS; PodDisruptionBudget; proxy HA and its configuration file | L |
| 4.3 | Operator: leader election, end-to-end test in CI, push instead of polling | M |
| 4.4 | Web end-to-end job in CI; arm64 images; signed packages and an apt/dnf repository | M |
| 4.5 | Artifacts: streaming above 64 MiB; content sources over SSH with signed commits | M |

## Not planned (optional, on demand)

External key and secret providers (OpenBao/Vault, PKCS#11, cloud KMS), Quadlet units, the shared ByteHawks theme package, sidecar agents and per-pod identity, WebAuthn and captcha. They stay in ROADMAP as to-do.

## What can be done where

| Where | Steps |
|-------|-------|
| A development session with Docker (like the ones so far) | 0.2, all of phase 1, 2.1, 2.3 to 2.5, 2.7, 4.3 (tests), 4.5 |
| Needs the CI logs | 0.1, 3.1 preparation, 3.6 |
| Needs real machines or a cluster | 0.3, 0.4, 3.1, 4.1, 4.2 |
| Needs external systems | 2.2 (an AD/LDAP and a SAML IdP; Keycloak and Samba in containers can stand in), Entra ID tenant |
