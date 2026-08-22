$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$driver = Get-Content (Join-Path $root 'ThreatDetectionSuite\TDSDriver\TDSDriver.c') -Raw
$common = Get-Content (Join-Path $root 'ThreatDetectionSuite\TDSCommon\TDSCommon.h') -Raw
$service = Get-Content (Join-Path $root 'ThreatDetectionSuite\TDSEngine\TDSService.cpp') -Raw

@(
    'IoCreateDeviceSecure',
    'IoValidateDeviceIoControlAccess(Irp, FILE_WRITE_ACCESS)',
    'IoValidateDeviceIoControlAccess(Irp, FILE_READ_ACCESS)',
    'IsAuthorizedPolicyCaller',
    'status = FwpmSubLayerAdd0',
    'status = FwpsCalloutRegister0',
    'status = FwpmFilterAdd0',
    'CleanupWFP'
) | ForEach-Object {
    if ($driver -notmatch [regex]::Escape($_)) { throw "Missing driver security contract: $_" }
}

if ($common -notmatch 'IOCTL_TDS_SET_PROTECTION_POLICY[^\r\n]*FILE_ANY_ACCESS') {
    throw 'Policy IOCTL ABI access bits changed'
}
if ($common -notmatch 'IOCTL_TDS_GET_NEXT_EVENT[^\r\n]*FILE_ANY_ACCESS') {
    throw 'Event IOCTL ABI access bits changed'
}
if ($service -notmatch 'OpenDriverWithPolicy' -or $service -notmatch 'ApplyProtectionPolicy') {
    throw 'Service reconnect path does not reapply policy'
}

Write-Host 'TDS Windows driver security contract: ok'
