[CmdletBinding(SupportsShouldProcess)]
param([switch]$RemoveDriver)

$ErrorActionPreference = 'Stop'
$names = @('TDSService')
if ($RemoveDriver) { $names += 'TDSCoreKernel' }
foreach ($name in $names) {
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($service -and $PSCmdlet.ShouldProcess($name, 'stop and delete service')) {
        Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
        & sc.exe delete $name | Out-Null
    }
}
