<#
.SYNOPSIS
  Smoke test of the Windows agent on a real Windows host (used by the CI workflow; needs an
  elevated session). It applies a small policy to a temporary directory, reads a real service
  from the Service Control Manager, then registers and removes the agent's own service.
#>
param([Parameter(Mandatory)][string]$Agent)
$ErrorActionPreference = 'Stop'
$Agent = (Resolve-Path $Agent).Path

# Run the agent and require one of the expected exit codes (0 compliant, 2 drift, 1 failure).
function Invoke-Agent([int]$Expect, [string[]]$Arguments) {
    & $Agent @Arguments
    if ($LASTEXITCODE -ne $Expect) { throw "delbert-agent $Arguments exited with $LASTEXITCODE (expected $Expect)" }
}

$work = Join-Path $env:TEMP ("delbert-smoke-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
$dir = $work -replace '\\', '/'
$policy = Join-Path $work 'policy.yaml'
@"
apiVersion: delbert/v1
kind: Policy
metadata: { name: smoke, tenant: t1 }
spec:
  resources:
    - id: dir
      file: { path: "$dir/app", state: directory }
    - id: conf
      copy: { content: "port=8080\n", dest: "$dir/app/app.conf" }
      depends_on: [dir]
    - id: extra
      file: { path: "$dir/app/extra.conf" }
      depends_on: [dir]
    - id: line
      line_in_file: { path: "$dir/app/extra.conf", line: "debug=false" }
      depends_on: [extra]
    - id: eventlog
      service: { name: EventLog, state: started, enabled: true }
"@ | Set-Content -Encoding utf8 $policy

Write-Host '== check before: drift (exit code 2)'
Invoke-Agent 2 @('check', $policy)
Write-Host '== apply, then check: compliant'
Invoke-Agent 0 @('apply', $policy)
Invoke-Agent 0 @('check', $policy)
if ((Get-Content -Raw "$work\app\app.conf") -ne "port=8080`n") { throw 'app.conf has the wrong content' }
if ((Get-Content "$work\app\extra.conf") -notcontains 'debug=false') { throw 'extra.conf misses the line' }
if (Get-ChildItem "$work\app" -Force | Where-Object Name -like '*.delbert.tmp.*') { throw 'temporary files left behind' }

Write-Host '== a POSIX attribute is refused, not ignored'
(Get-Content $policy) -replace 'dest: "(.*)app.conf" }', 'dest: "${1}app.conf", mode: "0644" }' | Set-Content -Encoding utf8 $policy
Invoke-Agent 1 @('check', $policy)

Write-Host '== Windows Service: install, inspect, uninstall'
Invoke-Agent 0 @('service', 'install')
$service = Get-Service DelbertAgent
if ($service.StartType -ne 'Automatic') { throw "unexpected start type $($service.StartType)" }
$data = Join-Path $env:ProgramData 'Delbert'
$others = (Get-Acl $data).Access | Where-Object { $_.IdentityReference -notmatch 'SYSTEM|Administrators|OWNER RIGHTS' }
if ($others) { throw "the data directory is open to: $($others.IdentityReference -join ', ')" }
Invoke-Agent 0 @('service', 'uninstall')
if (Get-Service DelbertAgent -ErrorAction SilentlyContinue) { throw 'the service is still registered' }

Remove-Item -Recurse -Force $work
Write-Host 'SMOKE-OK'
