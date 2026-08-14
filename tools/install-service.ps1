[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$InstallRoot,
    [ValidateSet('observe', 'alert', 'contain', 'terminate')]
    [string]$ResponseMode = 'observe',
    [switch]$InstallDriver
)

$ErrorActionPreference = 'Stop'
$serviceName = 'TDSService'
$driverName = 'TDSCoreKernel'
$serviceExe = Join-Path $InstallRoot 'TDSService.exe'
$driverSys = Join-Path $InstallRoot 'ThreatDetectionKernel.sys'

if (-not (Test-Path -LiteralPath $serviceExe)) { throw "Missing service binary: $serviceExe" }
if ($InstallDriver -and -not (Test-Path -LiteralPath $driverSys)) { throw "Missing driver binary: $driverSys" }

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($PSCmdlet.ShouldProcess($serviceName, 'stop and replace service')) { Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue }
    & sc.exe delete $serviceName | Out-Null
}

if ($PSCmdlet.ShouldProcess($serviceName, 'create service')) {
    & sc.exe create $serviceName binPath= "`"$serviceExe`"" start= auto type= own DisplayName= "Threat Detection Suite" | Out-Null
    & sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null
    & sc.exe config $serviceName obj= LocalSystem | Out-Null
}

[Environment]::SetEnvironmentVariable('TDS_RESPONSE_MODE', $ResponseMode, 'Machine')

if ($InstallDriver -and $PSCmdlet.ShouldProcess($driverName, 'install kernel driver service')) {
    & sc.exe create $driverName type= kernel start= demand binPath= "`"$driverSys`"" DisplayName= "Threat Detection Suite Kernel" | Out-Null
    & sc.exe config $driverName start= demand | Out-Null
}

if ($PSCmdlet.ShouldProcess($serviceName, 'start service')) { Start-Service -Name $serviceName }
