[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [ValidateSet('x64')]
    [string]$Platform = 'x64'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'ThreatDetectionSuite\TDSDriver\TDSDriver.vcxproj'

if (-not (Test-Path -LiteralPath $project)) {
    throw "Missing WDK project: $project. Create it from the repository's checked-in driver project before building."
}

$msbuild = Get-Command msbuild.exe -ErrorAction SilentlyContinue
if (-not $msbuild) { throw 'MSBuild was not found. Install Visual Studio 2022 C++ and WDK.' }

& $msbuild.Source $project "/m" "/p:Configuration=$Configuration" "/p:Platform=$Platform" "/warnAsError"
if ($LASTEXITCODE -ne 0) { throw "Driver build failed with exit code $LASTEXITCODE" }
