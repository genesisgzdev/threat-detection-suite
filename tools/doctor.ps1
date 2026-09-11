[CmdletBinding()]
param([switch]$RequireDriver, [switch]$Json)

# Works in Windows PowerShell 5.1 as well as PowerShell 7.
$onWindows = $env:OS -eq 'Windows_NT'
$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check($Name, $State, $Detail) {
    $checks.Add([pscustomobject]@{ Check = $Name; State = $State; Detail = $Detail })
}
if (-not $onWindows) {
    Add-Check 'Equipo' 'error' 'TDS necesita Windows. Puedes leer sus informes desde otro sistema.'
} else {
    $service = Get-Service -Name TDSService -ErrorAction SilentlyContinue
    $driver = Get-Service -Name TDSCoreKernel -ErrorAction SilentlyContinue
    if (-not $service) { Add-Check 'Servicio' 'error' 'TDS no esta instalado. Sigue docs/USO.md.' }
    elseif ($service.Status -ne 'Running') { Add-Check 'Servicio' 'error' 'TDS esta instalado pero detenido. Revisa el Visor de eventos antes de iniciarlo.' }
    else { Add-Check 'Servicio' 'ok' 'TDS esta en marcha.' }
    if ($driver -and $driver.Status -eq 'Running') { Add-Check 'Controlador' 'ok' 'El controlador adicional esta en marcha.' }
    else {
        $state = if ($RequireDriver) { 'error' } else { 'aviso' }
        Add-Check 'Controlador' $state 'No esta activo. La recogida de eventos del controlador no esta disponible.'
    }
    $mode = [Environment]::GetEnvironmentVariable('TDS_RESPONSE_MODE', 'Machine')
    if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'observe' }
    if ($mode -in @('observe', 'alert')) { Add-Check 'Respuesta' 'ok' "Configurado: $mode. No autoriza terminar procesos." }
    elseif ($mode -in @('contain', 'terminate')) { Add-Check 'Respuesta' 'aviso' "Configurado: $mode. Puede intervenir sobre conexiones o procesos." }
    else { Add-Check 'Respuesta' 'error' 'El modo configurado no se reconoce. Revisa TDS_RESPONSE_MODE.' }
    $path = [Environment]::GetEnvironmentVariable('TDS_LOG_PATH', 'Machine')
    if ([string]::IsNullOrWhiteSpace($path)) { $path = 'C:\ProgramData\TDS\tds_threat_events.jsonl' }
    if (Test-Path -LiteralPath $path -PathType Leaf) { Add-Check 'Informe' 'ok' "Archivo encontrado: $path" }
    else { Add-Check 'Informe' 'aviso' "Aun no hay un informe en $path. Esto no confirma que el equipo este protegido." }
}
if ($Json) { ConvertTo-Json -InputObject @($checks.ToArray()) -Depth 3 }
else {
    Write-Output "`nTDS | Estado del equipo`n"
    $checks | Format-Table Check, State, Detail -Wrap -AutoSize
    Write-Output 'El estado configurado puede requerir reiniciar el servicio o Windows para entrar en vigor.'
}
if (@($checks | Where-Object State -eq 'error').Count) { exit 1 }
exit 0
