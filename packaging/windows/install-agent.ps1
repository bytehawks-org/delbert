<#
.SYNOPSIS
  Install the Delbert agent on Windows from the published MSI, enroll it and start the service.

.DESCRIPTION
  Run in an elevated PowerShell (docs/WINDOWS.md):

    .\install-agent.ps1 -CoreUrl https://delbert.example.com:8443 -CaFile .\ca.pem `
                        -AgentId web-01 -EnrollKey <enrollment key>

  The MSI installs C:\Program Files\Delbert\delbert-agent.exe and registers the service
  "DelbertAgent" (LocalSystem, automatic). Data (identity, state, logs) is kept in
  C:\ProgramData\Delbert, readable by SYSTEM and Administrators only. The enrollment key is
  used once and stored nowhere. Without -EnrollKey the agent is installed but not enrolled.

.PARAMETER Version
  Release to install (default: the latest).
.PARAMETER Msi
  Install this MSI file instead of downloading one.
#>
[CmdletBinding()]
param(
    [string]$CoreUrl,
    [string]$CaFile,
    [string]$AgentId = $env:COMPUTERNAME.ToLower(),
    [string]$EnrollKey,
    [string]$Version,
    [string]$Msi,
    [string]$Repo = 'bytehawks-org/delbert'
)
$ErrorActionPreference = 'Stop'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this script in an elevated PowerShell (Administrator).' }
if ($EnrollKey) {
    if (-not $CoreUrl) { throw '-CoreUrl is required with -EnrollKey.' }
    if (-not $CaFile -or -not (Test-Path $CaFile)) { throw '-CaFile (the Delbert CA certificate) is required with -EnrollKey.' }
    $CaFile = (Resolve-Path $CaFile).Path
}

$tmp = Join-Path $env:TEMP ("delbert-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    if (-not $Msi) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (-not $Version) {
            $Version = (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest").tag_name
        }
        $Version = $Version.TrimStart('v')
        $file = "delbert-agent-$Version-x64.msi"
        $base = "https://github.com/$Repo/releases/download/v$Version"
        Write-Host "downloading $file"
        Invoke-WebRequest -UseBasicParsing "$base/$file" -OutFile (Join-Path $tmp $file)
        Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')
        $line = Get-Content (Join-Path $tmp 'SHA256SUMS') | Where-Object { $_.EndsWith(" $file") } | Select-Object -First 1
        $want = if ($line) { ($line -split '\s+')[0] } else { '' }
        $have = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $file)).Hash
        if (-not $want -or $want -ne $have) { throw "checksum mismatch for $file" }
        $Msi = Join-Path $tmp $file
    }
    $Msi = (Resolve-Path $Msi).Path

    # The MSI enrolls and starts the service when the four enrollment properties are given.
    $arguments = @('/i', "`"$Msi`"", '/qn', '/norestart')
    if ($EnrollKey) {
        $arguments += "CORE_URL=`"$CoreUrl`"", "CA_FILE=`"$CaFile`"", "AGENT_ID=`"$AgentId`"", "ENROLL_PSK=`"$EnrollKey`""
    }
    $process = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin 0, 3010) { throw "msiexec failed with exit code $($process.ExitCode)" }

    $service = Get-Service DelbertAgent
    Write-Host "Delbert agent installed; service DelbertAgent is $($service.Status)."
    if ($service.Status -ne 'Running') {
        Write-Host 'Enroll it:  & "C:\Program Files\Delbert\delbert-agent.exe" enroll --core-url ... --ca-file ... --agent-id ... --psk ...'
        Write-Host 'then:       Start-Service DelbertAgent'
    }
    Write-Host 'Log: C:\ProgramData\Delbert\logs\agent.log'
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
