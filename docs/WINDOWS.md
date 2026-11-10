# Delbert - Windows agent

State of the Windows port (phase 2 of [ABSTRACT.md](ABSTRACT.md) §5), how to install the agent and what is still missing. Only the **agent** runs on Windows; the Core, the proxy and the Operator stay on Linux/Kubernetes (the administration tools `delbert-pki` and `delbert-sign` also build for Windows).

**How far this is verified.** The agent, the proxy and the tools compile and link for `x86_64-pc-windows-gnu` (cross-built from Linux), and the portable logic (drive paths, sandbox mapping, refusal on other systems) is covered by unit tests that run on Linux. Nothing here was executed on a Windows host during development: the first real run is the `windows` job of the CI workflow (unit tests, [`smoke-test.ps1`](../packaging/windows/smoke-test.ps1), MSI install and removal on `windows-2022`). Treat the Windows agent as **preview** until that job is green and a real enrollment was done by hand.

## What works

| Area | Windows behaviour |
|------|-------------------|
| Enrollment, renewal, NATS (mTLS), signed policies, reports, audit events | same code as Linux (rustls, no OpenSSL, no system store) |
| `file`, `copy`, `template`, `line_in_file` | yes; paths with a drive letter (`C:/ProgramData/app/app.conf` or `C:\...`) |
| Crash-safe replacement | exclusive temporary file in the same directory, flush, atomic rename over the destination. The directory itself cannot be flushed without FFI: after a power loss the file holds the old or the new content, never a mix |
| `service` | Service Control Manager: `started`, `stopped`, `restarted`, `enabled` (automatic start) / disabled (manual start). `reloaded` is refused (no such notion) |
| Facts | from the registry: `os_family` = `distribution` = `windows`, `os_version` (`10.0.26100`), `kernel` (with the update revision), `hostname`, `domain`, `ips`, `machine_id` (`MachineGuid`); custom facts in `C:\ProgramData\Delbert\facts.d` |
| Running | Windows Service `DelbertAgent` (LocalSystem, automatic delayed start, restarted by the SCM on failure); log in `C:\ProgramData\Delbert\logs\agent.log` (rotated at start above 10 MiB, one old file kept) |

## What does not (yet)

| Area | State |
|------|-------|
| `owner`, `group`, `mode` | **refused** on Windows (the resource fails with a clear message) instead of being silently ignored; files inherit the ACL of their directory. ACL parameters are not designed yet |
| `package` | no backend (winget is not usable as LocalSystem on every edition; Chocolatey and MSI need a decision on sources and signatures) |
| `container` | not on Windows |
| Remediation (`verify` / `on_failure`, [REMEDIATION.md](REMEDIATION.md)) | drives `systemctl`: not available for Windows services |
| `registry` verb, reboots, Windows Update / GPO coexistence, UTF-16 and BOM handling in `line_in_file` | not started ([POLICY.md](POLICY.md) "Windows") |
| Event Log | the agent logs to a file only |
| arm64 | not built |
| Code signing of the executable and the MSI | not done: SmartScreen and application-control policies will complain until the release is signed |

## Writing policies for both systems

A policy path is either POSIX (`/etc/app.conf`) or has a drive (`C:/app/app.conf`). A drive path on a Linux agent **fails** the resource (it is never guessed), so scope resources with the fact:

```yaml
resources:
  - id: conf-linux
    when: "facts.os_family != 'windows'"
    copy: { content: "port=8080\n", dest: /etc/app/app.conf, mode: "0640" }
  - id: conf-windows
    when: "facts.os_family == 'windows'"
    copy: { content: "port=8080\r\n", dest: "C:/ProgramData/App/app.conf" }
    notify: [restart-app]
  - id: restart-app
    handler: true
    service: { name: AppService, state: restarted }
```

Use forward slashes in YAML (`C:/...`); backslashes work but need quoting. Line endings are written as given: use `\r\n` where the application needs them. With a sandbox root (`--root`, tests) a drive path lands in `<root>/C/...`.

## Install

Three equivalent ways; all need an elevated session. The agent needs the Core URL (or the site's proxy), the Delbert CA certificate (`ca.pem`), a name and a one-time enrollment key ([install.md](install.md) "Agents").

```powershell
# 1. Script: downloads the MSI of the latest release, checks its SHA-256, installs, enrolls, starts.
.\install-agent.ps1 -CoreUrl https://delbert.example.com:8443 -CaFile .\ca.pem -AgentId web-01 -EnrollKey <key>

# 2. MSI, unattended (GPO, Intune, SCCM):
msiexec /i delbert-agent-<version>-x64.msi /qn CORE_URL=https://delbert.example.com:8443 `
    CA_FILE=C:\Temp\ca.pem AGENT_ID=web-01 ENROLL_PSK=<key>

# 3. By hand, from the zip:
Copy-Item delbert-agent.exe 'C:\Program Files\Delbert\'
& 'C:\Program Files\Delbert\delbert-agent.exe' service install --core-url https://delbert.example.com:8443 `
    --ca-file .\ca.pem --agent-id web-01 --psk <key>
```

What happens, in every case: `delbert-agent service install` creates `C:\ProgramData\Delbert` with an ACL for SYSTEM, Administrators and the owner only (inheritance from `ProgramData` removed), registers the service, enrolls when the four values are given (the key is used once and stored nowhere: not in the registry, not on disk, hidden in the MSI log) and starts the service once an identity exists. Without the enrollment values the service is registered but not started: run `delbert-agent enroll ...` and `Start-Service DelbertAgent`.

While it runs, the enrollment key is on the command line of the install process and therefore visible to local administrators; it is single-use and expires.

| Where | What |
|-------|------|
| `C:\Program Files\Delbert\delbert-agent.exe` | the agent |
| `C:\ProgramData\Delbert\identity` | key, certificate, CA, trusted signing keys (kept on upgrade and removal) |
| `C:\ProgramData\Delbert` | state, cached policy, artifact cache, `facts.d`, `logs` |
| `HKLM\SYSTEM\CurrentControlSet\Services\DelbertAgent\Environment` | optional settings as a multi-string value, e.g. `DELBERT_INTERVAL_SECS=120`, `RUST_LOG=debug`, `DELBERT_NATS_URL=...`; restart the service after a change |

Upgrade: install the newer MSI (the service is removed and registered again; the identity stays). Removal: `msiexec /x` or `delbert-agent service uninstall`; delete `C:\ProgramData\Delbert` to forget the identity, and delete the agent in the Core.

## Design notes

- **No `unsafe`.** The SCM goes through the `windows-service` crate and the registry through `winreg` (safe APIs; the workspace keeps `unsafe_code = "forbid"`). Two system tools are called by full path with fixed arguments and only their exit code is used: `icacls.exe` (private directories, well-known SIDs so the display language does not matter) and `sc.exe config` (start type of a service; rewriting the whole service configuration through the API could alter its image path).
- **The executable installs itself.** The MSI only copies the file and calls `service install` / `service uninstall`, so the MSI, the zip and a manual install cannot drift apart. Source: [`packaging/windows/delbert-agent.wxs`](../packaging/windows/delbert-agent.wxs) (WiX 5).
- **Same contract as Linux:** outbound connections only, nothing listens, no local state that cannot be rebuilt (apart from the identity), policies verified before anything is applied.

## Next steps

1. Get the `windows` CI job green; enroll a real Windows Server and a Windows 11 client by hand against a Core, and record it in [TESTING.md](TESTING.md).
2. Decide the permission model (`acl` parameters) and the `package` backend (MSI with pinned hash as an artifact is the candidate: no third-party package manager needed).
3. Remediation for Windows services; Event Log; code signing in the release workflow; arm64.
