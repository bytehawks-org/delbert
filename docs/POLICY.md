# Delbert - Policy Format (YAML)

**This is the authoring format for administrators.** The Core compiles it into per-endpoint *effective policies* (canonical JSON, JCS RFC 8785, Ed25519/JWS-signed, sensitive fields encrypted per agent) and sends only that to agents; agents never see YAML. Declarative, Ansible-inspired resource vocabulary. Unlike Ansible, a policy describes a **desired state** that the agent converges continuously (check → apply only if drifted), never a one-shot task list. See [ABSTRACT.md](ABSTRACT.md) §3 for signing and the execution principle (agents only).

Status: **draft v0.1**, phase 1 = Linux + containers. Windows: see [Windows (phase 2)](#windows-phase-2).

## Structure

```yaml
apiVersion: delbert/v1
kind: Policy
metadata:
  name: web-baseline
  tenant: example
  version: 12            # monotonic, set and signed by the Core
spec:
  target:                # who receives it
    groups: [web]
    when: "facts.os_family == 'debian'"
  vars:
    app_port: 8080
  resources:
    - id: nginx-pkg
      package: { name: nginx, state: present }

    - id: nginx-conf
      template:
        src: artifact://nginx.conf.j2     # artifact, hash pinned by the Core
        dest: /etc/nginx/nginx.conf
        owner: root
        group: root
        mode: "0644"
      depends_on: [nginx-pkg]
      notify: [nginx-reload]

    - id: nginx-svc
      service: { name: nginx, state: started, enabled: true }
      depends_on: [nginx-pkg]

    - id: nginx-reload
      handler: true                       # runs only when notified
      service: { name: nginx, state: reloaded }
```

Rules:

- Each resource has a unique `id` and **exactly one** verb key.
- Order is top-to-bottom, overridden by `depends_on`. Cycles are rejected at validation.
- `notify` triggers a `handler: true` resource only if the notifier changed something.
- `when` uses a restricted expression language (MiniJinja expressions over `facts` and `vars`); no function can run commands or read files.
- Artifacts (`artifact://`) are referenced by name; the signed policy pins their SHA-256.
- Unknown keys are errors (typed deserialization, `deny_unknown_fields`).

## Verbs (phase 1)

| Verb | Purpose | Main parameters | Ansible analogue |
|------|---------|-----------------|------------------|
| `file` | Path state | `path`, `state` (file, directory, link, absent), `owner`, `group`, `mode`, `target` | file |
| `copy` | Static file from artifact or inline | `src`/`content`, `dest`, `owner`, `group`, `mode` | copy |
| `template` | Rendered file | `src`, `dest`, `vars`, ownership/mode | template |
| `line_in_file` | Ensure a line | `path`, `line`, `regexp`, `state`, `insert_after`/`insert_before` | lineinfile |
| `block_in_file` | Ensure a marked block | `path`, `block`, `marker` | blockinfile |
| `get_url` | Download | `url`, `dest`, `sha256` (**mandatory**), ownership/mode | get_url |
| `package` | OS packages | `name`, `state` (present, absent, latest); backend auto-detected (apt, dnf, zypper, apk) | package |
| `service` | Service manager (systemd) | `name`, `state` (started, stopped, restarted, reloaded), `enabled` | service |
| `user` / `group` | Local accounts | `name`, `state`, `uid`/`gid`, `shell`, `groups` | user, group |
| `sysctl` | Kernel parameter | `key`, `value`, `persist` | sysctl |
| `cron` | Scheduled job | `name`, `schedule`, `command` (subject to `command` rules) | cron |
| `command` | Restricted exec | see ABSTRACT §3 | command |
| `container` | Docker/Podman container | `name`, `image` (digest recommended), `state`, `ports`, `volumes`, `env`, `restart` | docker_container |
| `container_volume` / `container_network` | Docker/Podman objects | `name`, `state`, driver options | docker_volume/network |

Notes:

- `template` uses **MiniJinja** (Jinja2-compatible, Apache-2.0), sandboxed: no file, env or exec access. Rendering happens **on the agent**, so secrets in `vars` never need to be rendered by the server.
- `line_in_file`/`block_in_file` are idempotent by construction (regexp match or marker); they never append blindly.
- `get_url` without `sha256` is rejected at validation.
- `command` is the only verb that runs arbitrary programs; all others use native implementations.
- Kubernetes objects are not a host verb: they are managed by the in-cluster Operator via CRDs (`kube-rs`), using the same signed-policy mechanism.

## Conflicts

Several policies can reach the same endpoint. Each verb defines a **resource key** (identity of what it governs):

| Verbs | Key |
|-------|-----|
| `file`, `copy`, `template`, `get_url` | absolute path (shared namespace) |
| `line_in_file` | path + `regexp` (or the line itself) |
| `block_in_file` | path + `marker` |
| `package`, `service` | name |
| `user`, `group` | name |
| `sysctl` | key |
| `container*` | kind + name |

Same key and identical normalized parameters → merged. Same key, different parameters → **conflict**. Disjoint parts of one object (different lines of one file) do not conflict. Resolution happens only in the Core (the agent receives a single, already resolved, signed policy).

Planned fields (not yet in the model):

```yaml
spec:
  priority: 100                 # used by the `priority` strategy
  conflict:
    strategy: [specificity, priority, error]   # chain, falls back to `error`
resources:
  - id: motd
    copy: { ... }
    conflict: { strategy: priority, priority: 500 }   # per-resource override
```

Strategies: `error` (default; the conflicting key is not applied, the rest is, endpoint reported `conflicted`), `specificity` (agent > dynamic group > static group > tenant), `priority`, `merge` (only for verbs that declare it). Precedence of settings: **resolution record** (admin decision for one key and endpoint/group, with winner, reason, expiry, approver; audited) > resource > policy > tenant/global default. The Core shows an impact preview of conflicts before publishing a policy.

Within a single policy the same rules are already enforced at validation time: two resources on the same key are rejected (`file`/`copy`, `copy`/`copy`, `copy`/`line_in_file` on one path; same `package` or `service` name; `line_in_file` with the same `regexp`/line). `file` plus `line_in_file` on one path is fine, and handlers are exempt from the check.

## Agent semantics (implemented)

- `file`: `state: file` creates an empty file if missing; `absent` removes files, links and **empty** directories only (never recursive).
- `copy`/`line_in_file` write atomically (temp file + rename) and keep the existing mode/owner unless the policy sets them. `line_in_file` needs the file to exist (except `state: absent`).
- Owner/group names are resolved from the local `/etc/passwd` and `/etc/group` (numeric ids accepted); NSS sources such as LDAP are not consulted yet.
- Resources whose dependency failed, was skipped or is unsupported are `skipped`. In check mode a resource that cannot be evaluated because a dependency has not converged is reported as drift.

## Packages, services, templates (implemented)

- `package`: backend auto-detected (apt-get, dnf, zypper, apk) through the command runner; `present`/`absent` implemented, `latest` returns an error for now. Names are restricted to a safe character set (no leading dash).
- `service` (systemd): `started`/`stopped` and `enabled` are states; `restarted`/`reloaded` are one-shot actions allowed **only on handlers**, otherwise they could never converge.
- `template`: MiniJinja, rendered on the agent with `vars` (see "Variables" below) and `facts` (`hostname`, `os_id`, `os_version_id`). Undefined variables are errors; no loader, no file or command access. Trailing newlines are preserved.
- System commands are executed as argv vectors (no shell) and are refused when the agent runs with a sandbox `--root`.

## Variables

`vars` in a template come from layers, resolved by the **Core per agent** and delivered in the signed effective policy, so what an agent renders depends only on verified data. From lowest to highest precedence:

1. the policy's own `spec.vars` (the author's defaults; policies that disagree are a conflict as before);
2. **shared** (global) variables, managed by the platform (`globals:write`);
3. **tenant** variables;
4. **group** variables, for the groups the agent belongs to (several groups apply in alphabetical order, the last wins and the disagreement is reported as a conflict);
5. **agent** (host) variables;
6. the template resource's own `vars` (an explicit value written into the resource).

A variable can be a **constant** (`locked`): nothing below its layer can change it: lower layers are ignored (and reported when their value differs), the policy's default is overridden, the resource's own value for that name is removed. Setting a variable that a higher layer locked is refused (409). Names are `[A-Za-z_][A-Za-z0-9_]*` (usable as `vars.name`); values are JSON (at most 16 KiB). Variables are **not a secret store**: values are readable by whoever can read variables and the audit trail keeps only their SHA-256; use `spec.secrets` for anything sensitive.

Predictability: `GET /v1/tenants/{t}/agents/{a}/variables` returns each variable as the agent receives it, with the layer it comes from and the layers it hides; `GET .../render` renders every template resource of the agent's effective policy exactly as the agent will, with secrets masked (`********`) and host facts as placeholders, and reports undefined variables as errors per template. Changing any layer changes the effective policy, so the agent's version moves and agents are told to pull.

Not covered yet: variable changes do not go through the four-eyes approval of a tenant (they are authenticated, authorized and audited).

## Secrets and artifacts in policies

- `spec.secrets: [name, ...]` asks for tenant secrets; templates read them as `{{ secrets.name }}` (undefined names are errors). Secret values never appear in YAML.
- `artifact://<name>` in `copy.src` and `template.src` refers to an artifact uploaded through the API: the tenant's own, or else a **shared (global)** one of the platform (a tenant overrides a shared artifact by uploading one with the same name). On the agent it is pinned by the SHA-256 in the signed policy. Local YAML runs (`check`/`apply`) still read artifacts from a directory and skip the pin.

## Backend selection

- Package manager, init system and container engine are detected as facts at runtime; a policy declares intent (`package`, `service`, `container`), not the tool.
- A verb unsupported on the host's platform makes that resource `unsupported` in the compliance report; it does not abort the rest of the policy.

## Check/apply contract

Every verb implements:

1. `check()` → compliant | drifted(diff) | unsupported | error, **no side effects**;
2. `apply()` → executed only when drifted;
3. a diff for the audit trail (secrets masked via `sensitive: true` fields).

## Windows (phase 2)

Deferred. Intended baseline paradigm: **copy, insert into file, restart service**, reusing the same verb names where semantics are portable (`copy`, `template`, `line_in_file`, `service`, `get_url`). Items to study before design:

- permissions: POSIX `mode`/`owner` vs ACLs (new `acl` parameters rather than overloading `mode`);
- Service Control Manager semantics (start type, recovery, dependencies);
- registry as a new verb (`registry`), including 32/64-bit views;
- package sources (MSI, winget, Chocolatey) and signature verification;
- line endings, encodings (BOM, UTF-16), path syntax and locked files;
- reboots (pending-reboot detection, policy-controlled);
- execution context: LocalSystem vs user, UAC, PowerShell execution policy for `command`;
- Windows Update and GPO/Intune coexistence (avoid fighting other managers).
