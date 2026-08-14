#!/usr/bin/env python3
"""Forward TDS JSONL alerts to an OTLP/HTTP logs endpoint.

The exporter is intentionally separate from the detector: a SOC outage must
never block local detection or response. Unsent lines remain in the bounded
local spool until the next attempt.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def endpoint() -> str:
    value = os.environ.get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "").strip()
    if value:
        return value
    base = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip().rstrip("/")
    return f"{base}/v1/logs" if base else ""


def to_otlp(record: dict) -> dict:
    body = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
    return {
        "resourceLogs": [{
            "resource": {"attributes": [{"key": "tds.product", "value": {"stringValue": "ThreatDetectionSuite"}}]},
            "scopeLogs": [{"scope": {"name": "tds"}, "logRecords": [{
                "timeUnixNano": str(int(record.get("timestamp", 0)) * 1_000_000),
                "severityText": str(record.get("severity", "UNKNOWN")),
                "body": {"stringValue": body},
                "attributes": [
                    {"key": "tds.category", "value": {"stringValue": str(record.get("category", "UNKNOWN"))}},
                    {"key": "process.pid", "value": {"intValue": str(int(record.get("pid", 0)))}}],
            }]}],
        }]
    }


def send(payload: dict) -> bool:
    url = endpoint()
    if not url:
        return False
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("OTEL_EXPORTER_OTLP_HEADERS", "").strip()
    if token:
        headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
    request = Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with urlopen(request, timeout=10) as response:
            return 200 <= response.status < 300
    except (HTTPError, URLError, TimeoutError):
        return False


def run() -> None:
    path = Path(os.environ.get("TDS_LOG_PATH", r"C:\ProgramData\TDS\tds_threat_events.jsonl"))
    offset_path = path.with_suffix(path.suffix + ".otlp.offset")
    offset = int(offset_path.read_text().strip()) if offset_path.exists() else 0
    while True:
        if path.exists():
            size = path.stat().st_size
            if offset > size:
                offset = 0
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                stream.seek(offset)
                pending = []
                for line in stream:
                    try:
                        pending.append((json.loads(line), stream.tell()))
                    except json.JSONDecodeError:
                        continue
                new_offset = stream.tell()
            if pending:
                batch = pending[:100]
                payload = {"resourceLogs": []}
                for record, _ in batch:
                    converted = to_otlp(record)["resourceLogs"][0]
                    payload["resourceLogs"].append(converted)
                if send(payload):
                    offset = batch[-1][1]
                    offset_path.write_text(str(offset), encoding="utf-8")
            elif not pending:
                offset = new_offset
                offset_path.write_text(str(offset), encoding="utf-8")
        time.sleep(float(os.environ.get("TDS_OTLP_POLL_SECONDS", "2")))


if __name__ == "__main__":
    run()
