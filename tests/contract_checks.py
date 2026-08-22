#!/usr/bin/env python3
"""Repository-only checks for the shared TDS kernel/user event ABI."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
common = (ROOT / "ThreatDetectionSuite/TDSCommon/TDSCommon.h").read_text(encoding="utf-8-sig")
bridge = (ROOT / "tools/bridge/TDSBridge.cpp").read_text(encoding="utf-8-sig")
service = (ROOT / "ThreatDetectionSuite/TDSEngine/TDSService.cpp").read_text(encoding="utf-8-sig")

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
driver = (ROOT / "ThreatDetectionSuite/TDSDriver/TDSDriver.c").read_text(encoding="utf-8-sig")
for marker in ("PsSetCreateThreadNotifyRoutine", "PsSetLoadImageNotifyRoutine", "g_DroppedEventCount", "FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT", "data->ImagePathOffset = sizeof(TDS_PROCESS_EVENT_DATA)"):
    if marker not in driver:
        raise SystemExit(f"driver runtime marker missing: {marker}")
if "case TDSEventImageLoad" not in service:
    raise SystemExit("image-load decoder missing")

print("TDS contract checks: ok")
