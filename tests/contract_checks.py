#!/usr/bin/env python3
"""Repository-only checks for the shared TDS kernel/user event ABI."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
common = (ROOT / "ThreatDetectionSuite/TDSCommon/TDSCommon.h").read_text(encoding="utf-8-sig")
bridge = (ROOT / "tools/bridge/TDSBridge.cpp").read_text(encoding="utf-8-sig")
service = (ROOT / "ThreatDetectionSuite/TDSEngine/TDSService.cpp").read_text(encoding="utf-8-sig")
driver = (ROOT / "ThreatDetectionSuite/TDSDriver/TDSDriver.c").read_text(encoding="utf-8-sig")
driver = (ROOT / "ThreatDetectionSuite/TDSDriver/TDSDriver.c").read_text(encoding="utf-8-sig")
engine = (ROOT / "ThreatDetectionSuite/TDSEngine/TDSEngine.cpp").read_text(encoding="utf-8-sig")
correlator = (ROOT / "ThreatDetectionSuite/TDSEngine/correlator/SequenceCorrelator.cpp").read_text(encoding="utf-8-sig")

enum_block = re.search(r"typedef enum _TDS_EVENT_TYPE \{(.*?)\} TDS_EVENT_TYPE;", common, re.S)
if not enum_block:
    raise SystemExit("event enum missing")
symbols = set(re.findall(r"\bTDSEvent[A-Za-z0-9_]+\b", enum_block.group(1)))
used = set(re.findall(r"\bTDSEvent[A-Za-z0-9_]+\b", bridge + service)) - {"TDSEvents"}
missing = sorted(used - symbols)
if missing:
    raise SystemExit(f"event symbols missing from shared ABI: {', '.join(missing)}")

for ioctl in ("IOCTL_TDS_SET_PROTECTION_POLICY", "IOCTL_TDS_GET_NEXT_EVENT", "IOCTL_TDS_GET_QUEUE_STATS"):
    if ioctl not in common or ioctl not in service:
        raise SystemExit(f"IOCTL contract missing: {ioctl}")

if "METHOD_OUT_DIRECT" in common:
    raise SystemExit("event IOCTL must use METHOD_BUFFERED while the driver copies SystemBuffer")
if "TDS_RESPONSE_MODE" not in service:
    raise SystemExit("service response policy wiring missing")
for marker in ("network->Ipv4Address = remoteAddress->uint32", "network->RemotePort = remotePort->uint16", "network->Protocol = protocol->uint8"):
    if marker not in driver:
        raise SystemExit(f"WFP network event field is not wired: {marker}")
if "inFixedValues->valueCount <= remoteAddressIndex" not in driver:
    raise SystemExit("WFP network event indexes are not bounds-checked")
if "FILE_WRITE_ACCESS" not in common or "FILE_READ_ACCESS" not in common:
    raise SystemExit("IOCTL access contract is not separated")
if "CmRegisterCallbackEx" not in driver or "g_RegistryCallbackRegistered" not in driver:
    raise SystemExit("registry callback is declared but not registered and cleaned up")
if driver.count("if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4)") != 1:
    raise SystemExit("WFP ALE IPv4 condition must have one guarded path")
if "const uint32_t targetPid = data->TargetPid" not in engine:
    raise SystemExit("injection response must target the decoded target PID")
if "TDSEventEtwTiApcInjection" not in correlator or "EarlyInitializationPattern" not in correlator:
    raise SystemExit("ETW/APC correlation path missing")
driver = (ROOT / "ThreatDetectionSuite/TDSDriver/TDSDriver.c").read_text(encoding="utf-8-sig")
for marker in ("PsSetCreateThreadNotifyRoutine", "PsSetLoadImageNotifyRoutine", "g_DroppedEventCount", "FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT", "data->ImagePathOffset = sizeof(TDS_PROCESS_EVENT_DATA)"):
    if marker not in driver:
        raise SystemExit(f"driver runtime marker missing: {marker}")
if "case TDSEventImageLoad" not in service:
    raise SystemExit("image-load decoder missing")
cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8-sig")
if "set_target_properties(TDSCore PROPERTIES" not in cmake:
    raise SystemExit("shared TDSCore runtime library is not pinned")

driver = (ROOT / "ThreatDetectionSuite/TDSDriver/TDSDriver.c").read_text(encoding="utf-8-sig")
if "IOCTL_TDS_SET_RUNTIME_POLICY" not in common or "IOCTL_TDS_SET_RUNTIME_POLICY" not in driver:
    raise SystemExit("runtime policy IOCTL contract missing")
if "IoValidateDeviceIoControlAccess(Irp, FILE_WRITE_ACCESS)" not in driver or "IoValidateDeviceIoControlAccess(Irp, FILE_READ_ACCESS)" not in driver:
    raise SystemExit("explicit policy/event IOCTL access validation missing")
if "FILE_ANY_ACCESS" in common:
    raise SystemExit("shared IOCTL ABI leaves a privileged operation at FILE_ANY_ACCESS")
if "IoCreateDeviceSecure" not in driver:
    raise SystemExit("driver device ACL is not enforced")
if "IsAuthorizedPolicyCaller" not in driver:
    raise SystemExit("policy caller authorization check missing")
if "IsEdrProcess" in driver or "TDSService.exe" in driver:
    raise SystemExit("driver policy authorization must not rely on an executable name")
if "code == IOCTL_TDS_SET_PROTECTION_POLICY || code == IOCTL_TDS_SET_RUNTIME_POLICY" not in driver:
    raise SystemExit("runtime policy IOCTL is declared but not handled")
if "OpenDriverWithPolicy" not in service or "ApplyProtectionPolicy" not in service:
    raise SystemExit("service reconnect policy reapplication missing")

print("TDS contract checks: ok")
