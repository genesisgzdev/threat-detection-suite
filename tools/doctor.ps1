[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$checks = @(
    @{ Name = 'Windows'; Pass = [OperatingSystem]::IsWindows() },
    @{ Name = 'TDSService'; Pass = [bool](Get-Service -Name TDSService -ErrorAction SilentlyContinue) },
    @{ Name = 'TDSCoreKernel'; Pass = [bool](Get-Service -Name TDSCoreKernel -ErrorAction SilentlyContinue) },
    @{ Name = 'ProgramData'; Pass = Test-Path 'C:\ProgramData\TDS' },
    @{ Name = 'ResponseMode'; Pass = [Environment]::GetEnvironmentVariable('TDS_RESPONSE_MODE', 'Machine') -in @('observe', 'alert', 'contain', 'terminate') }
)

$failed = 0
foreach ($check in $checks) {
    $state = if ($check.Pass) { 'OK' } else { $failed++; 'FAIL' }
    '{0,-16} {1}' -f $state, $check.Name
}
if ($failed) { exit 1 }
