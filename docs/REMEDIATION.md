# Remediation and orphaned files

Two behaviours that decide what happens to a host when a policy version changes. Both are declared by the policy: not everything is handled the same way (a web server and a database are not).

## Orphaned files (implemented)

A new policy version may stop declaring a file: it was deleted, or renamed (the old path is simply no longer declared). The agent compares what the last clean cycle managed with what the new version declares and removes the difference.

- **What is remembered:** `state.json` → `managed`: path, kind (`file`, `link`, `directory`) and the `keep_if_absent_in_policy` flag **of the declaring resource**. Only `file` (file, link, directory), `copy` and `template` take part. `line_in_file` lines are never removed.
- **`keep_if_absent_in_policy: true`** on a resource keeps its path when the resource disappears. The directive is read from the old declaration, which is why it is stored with the path. Default: remove.
- **Only what Delbert applied.** A resource that never applied on a host (its `when` was false) is not recorded; a file somebody else put there is never touched. A path still declared by any resource (another id, or a `when` false on this host) is not an orphan.
- **Only after a clean cycle.** A cycle with a failed resource removes nothing and keeps the old record; the next clean cycle removes. With the remediation below, removal happens after verification, so a rollback never has to bring back removed files.
- A directory is removed only if empty (otherwise the report says "kept"). A removal that fails is retried.
- Each removal is a report entry `removed:<path>` and an audit event `agent.resource.changed` (`subject` = `remove file /etc/app.conf`).
- After an upgrade the record is empty: nothing is removed until a version has been applied once.
- Not covered: the offline CLI (`apply-signed`) does not remove orphans; the console does not yet preview the paths a save would remove.

## Remediation (implemented)

Decisions of 2026-11-01: the rollback is **atomic and whole-policy** (for simplicity and traceability), declared **by the policy**, and the Core treats a rolled-back agent as **inconsistent** until a person releases it.

### Declaring it

On a `service` resource (typically the restart **handler**: `restarted`/`reloaded` are only allowed on handlers):

```yaml
- id: nginx-restart
  handler: true
  service: { name: nginx, state: restarted }
  remediation:
    verify: { settle_seconds: 10, timeout_seconds: 60, port: 443 }  # port optional, 127.0.0.1 only
    on_failure: rollback          # none (default) | stop | rollback
    stop:  { graceful_seconds: 30, kill: after_timeout }            # kill: never is the default
    start: { timeout_seconds: 60 }
```

- **`verify`**: after the resource changed, the service must become `active` within `timeout_seconds`, stay `active` for `settle_seconds` and, if given, accept TCP connections on `127.0.0.1:port`. Without `verify` only a failing `systemctl` counts as a failure. All times are at most 3600 s.
- **`on_failure`**: `none` only reports (what is not declared is not automated; a database says `none`, or `rollback` with long `graceful_seconds` and `kill: never`). `stop` stops the service cleanly and leaves the host as it is. `rollback` does that and then re-applies the last known good policy.
- **`stop`**: `systemctl stop --no-block`, then the agent waits `graceful_seconds` (state `inactive`/`failed`). A forced `systemctl kill --signal=SIGKILL` happens only with `kill: after_timeout`, and is recorded as `agent.service.stop_forced`. With `kill: never` a service that does not stop is left alone and the rollback is not attempted. systemd's own `TimeoutStopSec` stays as the backstop.

### What the agent does

1. **Only an update can be undone.** Remediation is judged in a cycle that applies a version different from the last known good. Steady-state cycles only correct drift.
2. **Last known good (LKG).** A cycle that ends clean (no failed resource, no failed verification) stores its signed policy as `policy.lkg.jws` (and `state.json` → `lkg_version`); pinned artifacts stay in the content-addressed cache. It is a cache: without it `rollback` is *skipped* (event `agent.remediation.skipped`, nothing is stopped, nothing quarantined).
3. **On a failure with `on_failure` ≠ `none`:** clean stop of the failed service(s) → (`rollback`) the LKG is verified again (signature, target, canonical form) **judged as of its own issue time**, so its expiry and the anti-rollback rule do not refuse it: this is the one place where an older, already applied version may run again → the LKG is applied as a whole → the failed service is started (`start.timeout_seconds`) and verified with the LKG's own `verify` (else the failed one's). A failure of the rollback itself ends in `rollback_failed`: the agent stops automating.
4. **Orphans are removed only after verification**, so a failed update never deleted anything.
5. **Quarantine** (`state.json` → `quarantine`): the failed version is not applied again. While it is the policy the Core issues, the agent keeps the LKG in force (drift is corrected) and reports. A **greater version** lifts it. A **force** for exactly that version (below) lifts it once: the id is remembered (`last_force`), so a release is never obeyed twice.

### What the Core shows and does

- The report carries `remediation` (`state`: `rolled_back`, `rollback_failed`, `stopped`; `failed_version`, `running_version`, `resource`, `reason`, `at`, `steps`, `forced_kill`), the reported `version` is the one that actually runs, and `compliant` is false. `GET /v1/tenants/{t}/agents` returns it as `remediation`, with `force_pending`. `GET /v1/overview` counts `inconsistent` agents (a subset of `drifted`) and lists them first in `attention` with state `inconsistent`.
- The Core keeps issuing the failed version. **Forcing:** `POST /v1/tenants/{t}/agents/{a}/remediation/force {version, note}` (permission `agents:remediate`, held by `tenant-admin` and `platform-admin`; 409 unless the agent is quarantined at exactly that version). The Core signs `{version, id}` into the agent's effective policy and audits `remediation.force` with the user, the note and the remediation that was shown. The note should say which manual steps were taken on the host. `DELETE` on the same path withdraws a force the agent has not obeyed. The force ends when the agent reports a consistent state.
- Audit events from the agent: `agent.policy.rolled_back`, `agent.remediation.failed`, `agent.remediation.stopped`, `agent.remediation.skipped`, `agent.service.stop_forced`.

### Limits

- Linux with systemd only (`systemctl`); no Windows service or Podman container remediation yet.
- Only `service` resources; the verification is "active, stable, optionally a local port": no HTTP probe and no command probe (a `command` resource stays disabled by default).
- Rolling back re-applies the LKG, it does not undo what the update did outside the policy (data, package installations): declare `rollback` only where that is acceptable.
- The LKG ignores its own expiry for this purpose (it already ran on this host): a deliberate trade-off.
- **Verified with a scripted `systemctl` (unit tests) and the Core API against PostgreSQL/NATS; not on a real systemd host.** The sequence of commands (`show --property=ActiveState`, `stop --no-block`, `kill --signal=SIGKILL`, `start --no-block`) needs a run on one.
- Kubernetes: the Operator has no LKG; a rollout that misses its deadline should re-apply the previous bundle (see [OPERATOR.md](OPERATOR.md)), not done.

Status of each part: [ROADMAP.md](ROADMAP.md).
