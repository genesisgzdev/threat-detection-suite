# Requires an isolated Windows VM, a loadable signed TDS driver and explicit confirmation.
# This script records observations. It does not treat a missing ETW-TI event as cleanup.

[CmdletBinding()]
param(
    [switch]$LabConfirm,
    [string]$ResultPath = "tests/windows/early-bird-apc-last-run.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Result {
    param([hashtable]$Payload)
    $directory = Split-Path -Parent $ResultPath
    if ($directory -and -not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    $Payload | ConvertTo-Json -Depth 6 | Set-Content -Path $ResultPath -Encoding utf8
}

if (-not $LabConfirm) {
    Write-Result @{
        status = "not_executed"
        reason = "Refused without -LabConfirm. Static compilation is not evidence of Early Bird APC correlation."
        observedEtwTi = $false
        observedDriver = $false
    }
    Write-Error "Lab harness refused to run on this host."
}

$service = Get-Service -Name "TdsMonitor" -ErrorAction SilentlyContinue
$driver = Get-PnpDevice -FriendlyName "*TDS*" -ErrorAction SilentlyContinue
$started = Get-Date -Format "o"

Write-Result @{
    status = "started"
    startedAt = $started
    computer = $env:COMPUTERNAME
    isolated = $false
    servicePresent = [bool]$service
    driverPresent = [bool]$driver
    observedEtwTi = $false
    observedDriver = $false
    note = "Create a suspended process, queue an APC, resume the thread and attach PID plus creation time before comparing driver, ETW-TI and user-mode lines."
}

if (-not $service -or -not $driver) {
    Write-Result @{
        status = "not_observed"
        startedAt = $started
        finishedAt = (Get-Date -Format "o")
        observedEtwTi = $false
        observedDriver = $false
        reason = "Driver or service is not present. Absence of ETW-TI is not treated as evidence of cleanup."
    }
    Write-Error "Lab environment is incomplete."
}

Write-Output "Harness is ready for manual injection recording. Continue in the isolated VM and append timestamps to $ResultPath."
