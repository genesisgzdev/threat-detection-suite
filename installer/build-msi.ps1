[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ServiceExe,
    [Parameter(Mandatory)] [string]$DriverSys,
    [string]$Output = 'ThreatDetectionSuite.msi'
)

$ErrorActionPreference = 'Stop'
$wix = Get-Command wix.exe -ErrorAction SilentlyContinue
if (-not $wix) { throw 'WiX v4 was not found. Install the WiX Toolset before packaging.' }
& $wix.Source build (Join-Path $PSScriptRoot 'TDS.wxs') `
    "-dTDSServicePath=$ServiceExe" "-dTDSDriverPath=$DriverSys" `
    '-arch' 'x64' '-o' $Output
if ($LASTEXITCODE -ne 0) { throw "WiX build failed with exit code $LASTEXITCODE" }
