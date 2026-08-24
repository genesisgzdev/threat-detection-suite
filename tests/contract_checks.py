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
heuristics = (ROOT / "ThreatDetectionSuite/TDSEngine/HeuristicsEngine.cpp").read_text(encoding="utf-8-sig")

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
if "TDS_POLICY_FLAG_ENABLE_WFP" not in service or "TDS_POLICY_FLAG_ENABLE_MINIFILTER" not in service:
    raise SystemExit("service must explicitly enable the registered telemetry callbacks")
if "ReadBoundedWideString" not in bridge or "wprintf(L\"Path: %s \", (WCHAR*)((BYTE*)ev + ev->ImagePathOffset))" in bridge:
    raise SystemExit("bridge must validate NUL termination inside the event payload")
if "if ((policy.Flags & TDS_POLICY_FLAG_ENABLE_WFP) == 0) return;" not in driver:
    raise SystemExit("WFP callback ignores its runtime enable flag")
if "if (classifyOut) classifyOut->actionType = FWP_ACTION_PERMIT;" not in driver:
    raise SystemExit("WFP callback must default to permit before validating telemetry inputs")
if "if ((policy.Flags & TDS_POLICY_FLAG_ENABLE_MINIFILTER) == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;" not in driver:
    raise SystemExit("minifilter callback ignores its runtime enable flag")
for marker in ("network->Ipv4Address = remoteAddress->uint32", "network->RemotePort = remotePort->uint16", "network->Protocol = protocol->uint8"):
    if marker not in driver:
        raise SystemExit(f"WFP network event field is not wired: {marker}")
if "inFixedValues->valueCount <= remoteAddressIndex" not in driver:
    raise SystemExit("WFP network event indexes are not bounds-checked")
if "FILE_WRITE_ACCESS" not in common or "FILE_READ_ACCESS" not in common:
    raise SystemExit("IOCTL access contract is not separated")
if "CmRegisterCallbackEx" not in driver or "g_RegistryCallbackRegistered" not in driver:
    raise SystemExit("registry callback is declared but not registered and cleaned up")
if "if (inFixedValues->layerId != FWPS_LAYER_ALE_AUTH_CONNECT_V4) return;" not in driver:
    raise SystemExit("WFP callback must reject layers whose field indexes it cannot decode")
if "const uint32_t targetPid = data->TargetPid" not in engine:
    raise SystemExit("injection response must target the decoded target PID")
if "TDSEventEtwTiApcInjection" not in correlator or "EarlyInitializationPattern" not in correlator:
    raise SystemExit("ETW/APC correlation path missing")
etw = (ROOT / "ThreatDetectionSuite/TDSEngine/collectors/EtwCollector.cpp").read_text(encoding="utf-8-sig")
events = (ROOT / "ThreatDetectionSuite/TDSCommon/TDSEvents.h").read_text(encoding="utf-8-sig")
if "EtwApcEvent{event.Pid, 0, false}" not in etw or "TargetKnown" not in events or "RemoteThreadEvent{event.Pid}" in etw:
    raise SystemExit("ETW collector must not treat the emitter PID as the target")
if "if (event.Type == TDSEventProcessCreate)" not in heuristics or "m_processContexts.erase(event.Pid)" not in heuristics:
    raise SystemExit("heuristic context must reset on a new PID generation")
if "IsServiceProcess(targetProcess) || IsLsass(targetProcess)" not in driver:
    raise SystemExit("LSASS protection helper is not wired into the object callback")
if 'if (mode == "terminate") return {ResponseMode::Terminate, 85, 95};' not in (ROOT / "ThreatDetectionSuite/TDSEngine/ResponsePolicy.h").read_text(encoding="utf-8-sig"):
    raise SystemExit("terminate response thresholds must preserve contain-before-terminate ordering")
minifilter = driver[driver.index("FLT_PREOP_CALLBACK_STATUS TDSPreWriteCallback"):driver.index("CONST FLT_OPERATION_REGISTRATION Callbacks")]
if "FltGetRequestorProcess(Data)" not in minifilter or "PsGetProcessId(req)" not in minifilter:
    raise SystemExit("minifilter events must use the I/O requestor process identity")
if "PsGetCurrentProcessId()" in minifilter:
    raise SystemExit("minifilter attribution must not use the callback worker process")
if "SaveToDisk() {}" in correlator or "LoadFromDisk() {}" in correlator:
    raise SystemExit("sequence correlator must not expose empty persistence hooks")
driver = (ROOT / "ThreatDetectionSuite/TDSDriver/TDSDriver.c").read_text(encoding="utf-8-sig")
fuzzer = (ROOT / "tools/fuzzer_advanced.cpp").read_text(encoding="utf-8-sig")
if "static_cast<DWORD>(target_size)" in fuzzer and "DeviceIoControl" in fuzzer:
    raise SystemExit("IOCTL fuzzer must not claim a size larger than its backing allocation")
if "const DWORD input_length = static_cast<DWORD>(alloc_size)" not in fuzzer:
    raise SystemExit("IOCTL fuzzer must cap input length to the allocated buffer")
for marker in ("PsSetCreateThreadNotifyRoutine", "PsSetLoadImageNotifyRoutine", "g_DroppedEventCount", "g_EventHighWatermark", "FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT", "data->ImagePathOffset = sizeof(TDS_PROCESS_EVENT_DATA)"):
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
callback = driver[driver.rfind("OB_PREOP_CALLBACK_STATUS TDSPreCallback"):]
if "TDS_POLICY_FLAG_PROTECT_SERVICE" not in callback:
    raise SystemExit("service protection flag is not wired into the object callback")
if "IoValidateDeviceIoControlAccess(Irp, FILE_WRITE_ACCESS)" not in driver or "IoValidateDeviceIoControlAccess(Irp, FILE_READ_ACCESS)" not in driver:
    raise SystemExit("explicit policy/event IOCTL access validation missing")
if "FILE_ANY_ACCESS" in common:
    raise SystemExit("shared IOCTL ABI leaves a privileged operation at FILE_ANY_ACCESS")
if "IoCreateDeviceSecure" not in driver:
    raise SystemExit("driver device ACL is not enforced")
if "IsAuthorizedPolicyCaller" not in driver:
    raise SystemExit("policy caller authorization check missing")
ips = (ROOT / "ThreatDetectionSuite/TDSEngine/ips/IPSManager.cpp").read_text(encoding="utf-8-sig")
if "IsProtectedProcess" not in ips or 'L"lsass.exe"' not in ips or 'L"TDSService.exe"' not in ips:
    raise SystemExit("user-mode response deny-list for protected processes is missing")
if "IsEdrProcess" in driver or "TDSService.exe" in driver:
    raise SystemExit("driver policy authorization must not rely on an executable name")
if "code == IOCTL_TDS_SET_PROTECTION_POLICY || code == IOCTL_TDS_SET_RUNTIME_POLICY" not in driver:
    raise SystemExit("runtime policy IOCTL is declared but not handled")
if "OpenDriverWithPolicy" not in service or "ApplyProtectionPolicy" not in service:
    raise SystemExit("service reconnect policy reapplication missing")
for marker in ("TDS_QUEUE_STATS", "HighWatermark", "DroppedEvents"):
    if marker not in common + service:
        raise SystemExit(f"queue observability contract missing: {marker}")
event_bus = (ROOT / "ThreatDetectionSuite/TDSEngine/EventBus.h").read_text(encoding="utf-8-sig")
if "std::priority_queue<Event, std::vector<Event>, EventTimestampOrder>" not in event_bus or "left.Timestamp > right.Timestamp" not in event_bus:
    raise SystemExit("analysis queue must order events by shared timestamp")
if "Requeue it instead of turning a sizing mistake into" not in driver or "InterlockedPushEntrySList(&g_EventQueueHead, &item->ListEntry);" not in driver:
    raise SystemExit("undersized event reads must preserve the queued event")
flt_failure = driver[driver.index("status = FltRegisterFilter"):driver.index("return STATUS_SUCCESS;", driver.index("status = FltRegisterFilter"))]
for marker in ("PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine)", "PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine)"):
    if marker not in flt_failure:
        raise SystemExit("filter startup rollback must unregister every registered notify callback")

print("TDS contract checks: ok")
