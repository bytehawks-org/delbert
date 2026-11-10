# Delbert - Policy Format (YAML)

**This is the authoring format for administrators.** The Core compiles it into per-endpoint *effective policies* (canonical JSON, JCS RFC 8785, Ed25519/JWS-signed, sensitive fields encrypted per agent) and sends only that to agents; agents never see YAML. Declarative, Ansible-inspired resource vocabulary. Unlike Ansible, a policy describes a **desired state** that the agent converges continuously (check → apply only if drifted), never a one-shot task list. See [ABSTRACT.md](ABSTRACT.md) §3 for signing and the execution principle (agents only).

Status: **draft v0.1**, phase 1 = Linux + containers. Windows (preview): see [Windows (phase 2)](#windows-phase-2) and [WINDOWS.md](WINDOWS.md).

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
- `when` (per resource) is a MiniJinja expression over `facts` and `vars`, evaluated **by the agent on its own host**; no function can run commands or read files. False: the resource is `not_applicable` (counts as compliant) and so are the resources that depend on it. An expression that cannot be evaluated (an undefined name; test with `facts.custom.x is defined`) **fails** the resource: it is never applied or dropped by guess. `target.when` (whole policy) is not supported: use groups. See "Facts".
- `remediation` (service resources, usually the restart handler): `verify`, `on_failure: none|stop|rollback`, `stop {graceful_seconds, kill}`, `start`: what the agent verifies after a change and what it does when the service does not come up (clean stop, rollback of the whole policy to the last known good, forced kill only if declared). See [REMEDIATION.md](REMEDIATION.md).
- `spec.target`: `groups` (agents in any of them), `agents` (agents by name, a policy for one host); both empty = every agent of the tenant. When the policy comes from a repository the folder sets it ([REPOSITORY.md](REPOSITORY.md)). `target.when` is not supported.
- `keep_if_absent_in_policy: true` (file, copy, template): the agent keeps the path when a later version no longer declares it; by default it removes what it had applied. See [REMEDIATION.md](REMEDIATION.md).
- Artifacts (`artifact://`) are referenced by name; the signed policy pins their SHA-256.
- Unknown keys are errors (typed deserialization, `deny_unknown_fields`).

## Verbs (phase 1)

| Verb | Purpose | Main parameters | Ansible analogue |
|------|---------|-----------------|------------------|
| `file` | Path state | `path`, `state` (file, directory, link, absent), `owner`, `group`, `mode`, `target` | file |
| `copy` | Static file from artifact or inline | `src`/`content`, `dest`, `owner`, `group`, `mode` | copy |
| `template` | Rendered file | `src`, `dest`, `vars`, ownership/mode | template |
| `line_in_file` | Ensure a line is there, or (`state: absent`) that it is not | `path`, `line`, `regexp`, `state`, `insert_after`/`insert_before` | lineinfile |
| `block_in_file` | Ensure a marked block (**implemented**) | `path`, `block`, `marker`, `state` | blockinfile |
| `get_url` | Download (**implemented**, see "Downloads") | `url`, `dest`, `sha256` (**mandatory**), ownership/mode | get_url |
| `package` | OS packages | `name`, `state` (present, absent, latest); backend auto-detected (apt, dnf, zypper, apk) | package |
| `service` | Service manager (systemd) | `name`, `state` (started, stopped, restarted, reloaded), `enabled` | service |
| `user` / `group` | Local accounts (**implemented**, see "Users and groups") | `name`, `state`, `uid`/`gid`, `group`, `groups`, `shell`, `home`, `comment`, `system`, `create_home` | user, group |
| `sysctl` | Kernel parameter (**implemented**) | `key`, `value`, `persist` | sysctl |
| `cron` | Scheduled job (**implemented**, off by default: see "Scheduled jobs") | `name`, `schedule`, `user`, `command` (argv), `env`, `state` | cron |
| `mount` | Filesystem in `/etc/fstab` and mounted (**implemented**, see "Mounts") | `path`, `src`, `fstype`, `opts`, `state` (mounted, present, unmounted, absent), `dump`, `passno` | mount |
| `command` | Restricted exec (**implemented**, off by default: see "Commands") | `argv`, `creates`/`onlyif`/`unless`, `user`, `timeout_seconds`, `cwd`, `env` | command |
| `container` | Docker/Podman container (**implemented**, see "Containers") | `name`, `image` (digest recommended), `state`, `ports`, `volumes`, `env`, `env_from`, `secret_from`, `restart`, `command`, `engine` | docker_container |
| `container_volume` / `container_network` | Docker/Podman objects | `name`, `state`, driver options | docker_volume/network |

Notes:

- `template` uses **MiniJinja** (Jinja2-compatible, Apache-2.0), sandboxed: no file, env or exec access. Rendering happens **on the agent**, so secrets in `vars` never need to be rendered by the server.
- `line_in_file`/`block_in_file` are idempotent by construction (regexp match or marker); they never append blindly. See "Lines and blocks".
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
| `user`, `group` | name (each in its own namespace) |
| `sysctl` | key |
| `cron` | name |
| `mount` | mount point |
| `command` | none (a command is identified by its resource id) |
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
- `template`: MiniJinja, rendered on the agent with `vars` (see "Variables" below) and `facts` (see "Facts"). Undefined variables are errors; no loader, no file or command access. Trailing newlines are preserved.
- System commands are executed as argv vectors (no shell) and are refused when the agent runs with a sandbox `--root`.

## Lines and blocks

```yaml
- id: no-root-ssh              # make sure a setting is there, replacing whatever the line said
  line_in_file: { path: /etc/ssh/sshd_config, regexp: '^#?\s*PermitRootLogin\b', line: "PermitRootLogin no" }
- id: no-debug                 # remove a configuration line: every line that matches goes
  line_in_file: { path: /etc/app/app.conf, regexp: '^\s*debug\s*=', line: "", state: absent }
- id: no-legacy-host           # without regexp: the exact line
  line_in_file: { path: /etc/hosts, line: "10.0.0.9 legacy", state: absent }
- id: backends                 # several lines kept together between two markers
  block_in_file:
    path: /etc/hosts
    marker: "# {mark} app backends"
    block: |
      10.0.0.1 db
      10.0.0.2 cache
```

- `line_in_file` with `state: absent` removes all the lines matching `regexp` (or equal to `line`); `line` is required by the format and ignored when a `regexp` is given. A missing file is compliant.
- `block_in_file` writes `block` between a BEGIN and an END line made from `marker` (`{mark}` is replaced; default `# {mark} DELBERT MANAGED BLOCK`). The block is replaced in place when the markers exist and appended at the end otherwise; `state: absent` removes it with its markers. Give each block of a file its own marker: two blocks with the same marker are a conflict. A BEGIN without its END fails the resource (the file is not guessed at). The file must exist (`file` creates it); a `copy`/`template` of the same path is a conflict.
- Neither is removed when it leaves the policy (unlike files): declare `state: absent` for a version, then drop the resource.

## Users and groups

```yaml
- id: deploy-group
  group: { name: deploy, gid: 1800 }
- id: deploy-user
  user: { name: deploy, uid: 1800, group: deploy, groups: [www-data], shell: /bin/bash, home: /home/deploy, comment: "Deploy user", create_home: true }
  depends_on: [deploy-group]
- id: former-employee
  user: { name: jdoe, state: absent }
```

- Local accounts only: the state is read from `/etc/passwd` and `/etc/group`, changes go through `groupadd`/`groupmod`/`groupdel` and `useradd`/`usermod`/`userdel` (argv, no shell), which keep `shadow` and `gshadow` consistent. LDAP/AD accounts are neither seen nor touched. The tools must be installed (they are on every mainstream distribution; on Alpine add the `shadow` package).
- **No password is ever set:** a new account is locked for password login. Give access with keys (`copy` to `~/.ssh/authorized_keys`) or `sudo` rules delivered as files.
- **`root`, uid 0 and gid 0 are refused** by validation: no policy can create a second superuser or change the first.
- Only what is declared is compared and changed (`uid`, primary `group`, `shell`, `home`, `comment`). `groups` is **additive**: the user is added to the listed groups, other memberships are left alone. `system` and `create_home` matter only when the account is created; changing `home` later does not move the directory.
- `state: absent` runs `userdel` / `groupdel`: the home directory and the user's files stay where they are, nothing is deleted by inference.
- The primary group must exist before the user: declare it and use `depends_on`.
- Not on Windows.

## Kernel parameters

```yaml
- id: forwarding
  sysctl: { key: net.ipv4.ip_forward, value: "1" }
```

The value is read and written directly in `/proc/sys` (no command is run) and, unless `persist: false`, also written to `/etc/sysctl.d/90-delbert-<key>.conf` so it survives a reboot. Values compare with runs of blanks as one. An unknown key fails the resource. Removing the resource leaves the value and the file in place. Not on Windows.

## Scheduled jobs

```yaml
- id: nightly-backup
  cron:
    name: backup                      # the file /etc/cron.d/backup
    schedule: "30 2 * * 1-5"          # five fields, or @hourly @daily @weekly @monthly @yearly @reboot
    user: backup                      # the account it runs as (default root): system-wide or per user
    command: [/usr/local/bin/backup.sh, --target, /srv/backup]
    env: { MAILTO: ops@example.com }
```

A scheduled job is a way to run a program, so it follows the rules of the `command` resource ([ABSTRACT.md](ABSTRACT.md) §3):

- **Off by default, enabled only on the host.** The executable (`command[0]`, an absolute path) must be on the agent's local allow-list: `DELBERT_CRON_ALLOW=/usr/local/bin/backup.sh:/usr/bin/certbot` in `/etc/delbert/agent.env` (or `--cron-allow`). Without it every `cron` resource fails with a message that says so. No policy, variable or fact can change the list.
- **An argv, not a shell line.** Each argument is quoted when the cron line is written, and `%` is escaped, so pipes, redirections, `;`, `$(...)` are plain text for the program. Need a pipeline? Deliver a script with `copy` and schedule the script.
- `env` accepts only `MAILTO`, `MAILFROM`, `CRON_TZ`, `TZ`, `LANG`, `LC_ALL`, `RANDOM_DELAY` (not `SHELL` or `PATH`, which would choose what really runs).
- One job per resource, one file per job (`/etc/cron.d/<name>`, mode 0644, written crash-safely); the agent runs nothing itself. A file of that name that Delbert did not write is never replaced or removed. `state: absent` removes the job and needs no allow-list. A job that merely leaves the policy stays: remove it with `state: absent`.
- Per-user crontabs (`crontab -e` spool) are not edited: a job for a user is a job in `/etc/cron.d` with `user:`. `/etc/cron.d` must exist (a cron daemon is installed). Not on Windows (Scheduled Tasks are a separate verb to design).

The allow-list is a guard against mistakes and against a job nobody on the host agreed to, not a sandbox: a policy can also deliver files, so trust in the Core's signing key remains the boundary.

## Downloads

```yaml
- id: exporter
  get_url:
    url: "https://downloads.example.com/node_exporter-1.9.0.tar.gz"
    dest: /opt/node_exporter.tar.gz
    sha256: 6f0b0e7a...   # 64 hexadecimal digits, mandatory
    mode: "0644"
```

The agent downloads the file itself (outbound HTTPS, the system's trust store, the proxy of its environment). The content is pinned: a destination that already has the hash is compliant **without any request**; a download is kept in memory, hashed, and written crash-safely only when the hash matches, so a wrong or tampered file changes nothing on the host. A local change is drift and is repaired from the source. `http://` is accepted (the hash protects the content, not its confidentiality); credentials in the URL are refused. Limit: 256 MiB. Prefer an artifact with `copy` when the Core can hold the file: it needs no route from the host to the Internet and survives the source disappearing.

## Mounts

```yaml
- id: share-dir
  file: { path: /srv/share, state: directory }
- id: share
  mount: { path: /srv/share, src: "nas.example.com:/export", fstype: nfs, opts: "ro,noexec" }
  depends_on: [share-dir]
```

| `state` | `/etc/fstab` | Mounted now |
|---------|--------------|-------------|
| `mounted` (default) | line present | yes |
| `present` | line present | left as it is |
| `unmounted` | line present | no |
| `absent` | line removed | no |

- One line of `/etc/fstab` is edited (replaced where it is, the rest byte for byte, written crash-safely); an existing line that says the same in another layout is left alone. Then `mount <path>` / `umount <path>` (argv, no shell) act on that line, so the file and the running system cannot disagree. What is mounted is read from `/proc/mounts`.
- Changed options are applied with `mount -o remount`. A different `src` or `fstype` on a mounted filesystem needs an unmount, which is never done by inference: declare `unmounted` for one version.
- A busy filesystem fails the resource and leaves `/etc/fstab` as it was. The mount point must exist (`file` + `depends_on`). `/` is refused; fields with blanks are refused.
- A mount that leaves the policy stays: use `state: absent`. Not on Windows.

## Commands

```yaml
- id: init-db                       # runs once: the marker does not exist yet
  command:
    argv: [/usr/local/bin/init-db, --schema, /etc/app/schema.sql]
    creates: /var/lib/app/.initialised
    user: app
    timeout_seconds: 300
- id: reload-app                    # a handler: runs when something that notifies it changed
  handler: true
  command:
    argv: [/usr/sbin/nginx, -s, reload]
    onlyif: [/usr/sbin/nginx, -t]   # only if the configuration is valid
    user: root
    timeout_seconds: 30
```

The only verb that runs a program chosen by the policy ([ABSTRACT.md](ABSTRACT.md) §3). Every rule is enforced by the agent:

- **Off by default, enabled only on the host.** Every executable, guards included, must be on the agent's local allow-list: `DELBERT_COMMAND_ALLOW=/usr/local/bin/init-db:/usr/sbin/nginx` in `/etc/delbert/agent.env` (or `--command-allow`). An entry can pin the content: `/usr/local/bin/init-db@<sha256>`. Without the list every `command` fails, in check mode too, with a message that says so. No policy, variable or fact can change it.
- **No shell.** `argv` goes to the program as it is: no expansion, pipes or redirections. Deliver a script with `copy` (pinned artifact) and allow the script.
- **A guard is mandatory** (validation refuses a command without one): `creates` (run while the path does not exist), `onlyif` (run if this argv exits 0), `unless` (run if it exits non-zero). All the declared guards must agree. Guards run at every check, as the same user: they must not change anything.
- **It must converge.** After a successful run the guard is asked again and must say "no need": otherwise the resource fails (`not converged`). The exception is a command on a **handler**: it is an action that runs when notified and its guard is only a precondition.
- **Declared user, mandatory timeout, closed environment.** `user` is required (`root` included; another account is looked up in `/etc/passwd`, its supplementary groups are not applied). At `timeout_seconds` (1 to 3600) the program is killed and the resource fails. It sees only `PATH`, `HOME`, `USER`, `LOGNAME`, `LC_ALL=C` and the policy's `env` (`LD_*` refused); the working directory is `cwd` or `/`.
- **What is recorded.** A run is a `resource.changed` audit event with the program (never its arguments) and the guard's reason; a failure carries the exit code and the first 300 characters of the error output. The output of a successful run stays in the agent's log, not in the audit trail (outputs can hold secrets; masking is not designed yet).
- Not on Windows. A sandbox `--root` never runs anything.

As for `cron`, the allow-list is a guard, not a sandbox: a policy can also deliver files. An allowed interpreter (`/bin/sh`, `python3`) allows everything: list programs and scripts, not interpreters, and pin scripts with their hash.

## Facts

What the agent knows about its own host, read from files (no command is run). Available in templates and `when` as `facts.*`.

| Fact | Content |
|------|---------|
| `os_family` | `debian`, `rhel`, `suse`, `arch`, `alpine`, `linux`, `windows` (from `ID` / `ID_LIKE` of `/etc/os-release`) |
| `distribution` | `ID` of `/etc/os-release` (`ubuntu`, `rocky`); `os_id` is the same value under the name of the first version |
| `os_version` | `VERSION_ID`; also `os_version_id` |
| `kernel` | kernel release |
| `hostname`, `domain` | short host name; domain of an FQDN hostname, else the kernel's NIS domain |
| `ips` | addresses of the host, without loopback, link-local and container interfaces (`docker*`, `veth*`, `cni*`, `br-*`, ...) |
| `machine_id` | `/etc/machine-id` (**local**) |
| `custom.<file>.<key>` | documents in `DELBERT_FACTS_DIR` (default `/etc/delbert/facts.d`): `*.yaml`, `*.yml`, `*.json` up to 64 KiB, the file name without extension is the key (**local**) |

**Two sets.** The first seven (the *shared subset*) are reported to the Core every `DELBERT_FACTS_INTERVAL_SECS` (default 900, minimum 60) and immediately when they change, with the compliance report. The Core keeps only that subset, overwritten at each report, with no history and no audit events, and removes it with the agent (`GET /v1/tenants/{t}/agents` returns it as `facts` and `facts_at`). The **local** facts never leave the host: policies can use them in `when` and templates, the Core cannot. Delbert is not a CMDB.

**Trust.** The shared subset is what the agent says about itself: informational, never used for authorization, scoping or conflict resolution. In the console and in `GET .../render` the shared facts are the reported ones; the local ones are placeholders.

**`when` and conflicts.** The Core does not see the host. Two resources that name the same thing and **both** have a `when` (different ones) are kept, and the compilation reports "both kept"; if both hold on one host the agent fails both and applies neither. If only one has a `when` the usual conflict rules apply.

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

## Containers

The `container` verb manages a Podman or Docker container through the engine's command line (an argv, no shell). Podman is used if present, else Docker (`engine:` chooses). Linux hosts.

```yaml
spec:
  secrets: [db]                       # secrets mounted into containers must be listed here
  resources:
    - id: app
      container:
        name: app
        image: registry.example.com/app@sha256:...   # fully qualified, a digest is recommended
        state: running                # running (default) | stopped | absent
        ports: ["8080:80", "127.0.0.1:9090:90/tcp"]
        volumes: ["/srv/app:/data:ro"]
        env: { MODE: prod }           # literal
        env_from: [LOG_LEVEL]         # policy variables (shared/tenant/group/agent layers) by name
        secret_from:                  # secrets as read-only files, never as environment variables
          - { secret: db, path: /run/secrets/db, mode: "0400" }
        restart: unless-stopped       # no | on-failure | always | unless-stopped
        command: [serve, --port, "80"]
```

- **Configuration from Delbert, not from the deployment:** `env_from` takes variables from the layered `vars` ([Variables](#variables)); a name that is not defined fails the resource. `secret_from` writes each secret to `/run/delbert/secrets/<container>/<secret>` (tmpfs, mode `mode`, default `0400`) and bind-mounts it read-only (`:ro,Z`, the `Z` is the private SELinux label Podman needs on Fedora/RHEL). Secrets never appear in a command line, in `inspect` or in a hash. A container that runs as a non-root user needs a readable `mode` (e.g. `0444`: the file is in a `0700` directory of the host).
- **Recreation:** a running container cannot be edited. The agent labels what it creates with `io.bytehawks.delbert.hash`, an HMAC (key derived from the agent's identity) of image, ports, volumes, environment, secrets, restart policy and command, and **recreates** the container (`rm -f`, `run`) when it differs: a changed variable or a rotated secret does this. A secret file that went missing (`/run` is cleared by a reboot) or differs also recreates it, because a file replaced under a running container is a new inode that the bind mount does not follow. The image is pulled only when the container is created, so use a digest.
- **Safety:** nothing privileged can be declared (no `--privileged`, capabilities, devices, host network or pid). A container that exists with the same name but without the `io.bytehawks.delbert.managed` label is never touched: the resource fails. `state: absent` removes the container and its secret files. Container names are the resource key: two resources for one name conflict.
- Not covered yet: networks, volumes as objects (`container_volume`, `container_network`), registry credentials, healthchecks, user namespaces, Windows. **Podman 5.7 rootless is verified with a real container; Docker only through the same command line, not run.**

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

The baseline paradigm is implemented as a preview ([WINDOWS.md](WINDOWS.md)): **copy, insert into file, restart service**, with the same verb names (`file`, `copy`, `template`, `line_in_file`, `service`).

- **Paths:** a path is absolute when it starts with `/` or with a drive (`C:/app/app.conf`, `C:\app\app.conf`); `..` is refused with either separator. A drive path fails on a non-Windows agent, so scope such resources with `when: "facts.os_family == 'windows'"`.
- **Attributes:** `owner`, `group` and `mode` fail on Windows (they are not ignored); files inherit the ACL of their directory.
- **Services:** `started`, `stopped`, `restarted`, `enabled` map to the Service Control Manager; `reloaded` fails.
- **Not on Windows yet:** `package`, `container`, remediation (`verify` / `on_failure`).

Still to study before design:

- permissions: POSIX `mode`/`owner` vs ACLs (new `acl` parameters rather than overloading `mode`);
- Service Control Manager semantics (start type, recovery, dependencies);
- registry as a new verb (`registry`), including 32/64-bit views;
- package sources (MSI, winget, Chocolatey) and signature verification;
- line endings, encodings (BOM, UTF-16), path syntax and locked files;
- reboots (pending-reboot detection, policy-controlled);
- execution context: LocalSystem vs user, UAC, PowerShell execution policy for `command`;
- Windows Update and GPO/Intune coexistence (avoid fighting other managers).
