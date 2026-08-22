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

for ioctl in ("IOCTL_TDS_SET_PROTECTION_POLICY", "IOCTL_TDS_GET_NEXT_EVENT"):
    if ioctl not in common or ioctl not in service:
        raise SystemExit(f"IOCTL contract missing: {ioctl}")

if "METHOD_OUT_DIRECT" in common:
    raise SystemExit("event IOCTL must use METHOD_BUFFERED while the driver copies SystemBuffer")
if "TDS_RESPONSE_MODE" not in service:
    raise SystemExit("service response policy wiring missing")

driver = (ROOT / "ThreatDetectionSuite/TDSDriver/TDSDriver.c").read_text(encoding="utf-8-sig")
if "IOCTL_TDS_SET_RUNTIME_POLICY" not in common or "IOCTL_TDS_SET_RUNTIME_POLICY" not in driver:
    raise SystemExit("runtime policy IOCTL contract missing")
if "IoValidateDeviceIoControlAccess(Irp, FILE_WRITE_ACCESS)" not in driver or "IoValidateDeviceIoControlAccess(Irp, FILE_READ_ACCESS)" not in driver:
    raise SystemExit("explicit policy/event IOCTL access validation missing")
if "FILE_ANY_ACCESS" not in common:
    raise SystemExit("shared IOCTL ABI unexpectedly changed")
if "IoCreateDeviceSecure" not in driver:
    raise SystemExit("driver device ACL is not enforced")
if "IsAuthorizedPolicyCaller" not in driver:
    raise SystemExit("policy caller authorization check missing")
if "code == IOCTL_TDS_SET_PROTECTION_POLICY || code == IOCTL_TDS_SET_RUNTIME_POLICY" not in driver:
    raise SystemExit("runtime policy IOCTL is declared but not handled")
if "OpenDriverWithPolicy" not in service or "ApplyProtectionPolicy" not in service:
    raise SystemExit("service reconnect policy reapplication missing")

print("TDS contract checks: ok")
