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
import tempfile
from urllib.parse import unquote
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
    configured_headers = os.environ.get("OTEL_EXPORTER_OTLP_HEADERS", "").strip()
    if configured_headers:
        for item in configured_headers.split(","):
            name, separator, value = item.partition("=")
            if not separator or not name.strip():
                raise ValueError("OTEL_EXPORTER_OTLP_HEADERS must contain name=value pairs")
            headers[name.strip()] = unquote(value.strip())
    request = Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with urlopen(request, timeout=10) as response:
            return 200 <= response.status < 300
    except (HTTPError, URLError, TimeoutError):
        return False


MAX_LINE_BYTES = 1024 * 1024


def read_batch(path: Path, offset: int, limit: int = 100) -> tuple[list[dict], int]:
    """Read complete JSONL records with byte offsets and bounded memory."""
    records = []
    with path.open("rb") as stream:
        stream.seek(offset)
        for _ in range(limit):
            start = stream.tell()
            line = stream.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_LINE_BYTES:
                while line and not line.endswith(b"\n"):
                    line = stream.readline(MAX_LINE_BYTES + 1)
                if not line.endswith(b"\n"):
                    return records, start
                offset = stream.tell()
                continue
            if not line.endswith(b"\n"):
                break  # The producer has not finished this record yet.
            offset = stream.tell()
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    # Validate mappings before acknowledging a malformed line.
                    to_otlp(record)
                    records.append(record)
            except (ValueError, TypeError, UnicodeError, OverflowError):
                continue
    return records, offset


def export_once(path: Path, offset_path: Path) -> bool:
    """Commit the cursor only after the complete batch is accepted."""
    if not path.exists():
        return False
    info = path.stat()
    identity = [info.st_dev, info.st_ino]
    offset = 0
    try:
        checkpoint = json.loads(offset_path.read_text(encoding="utf-8"))
        if isinstance(checkpoint, dict) and checkpoint.get("identity") == identity:
            offset = int(checkpoint["offset"])
        elif isinstance(checkpoint, int):
            offset = checkpoint  # Migrate checkpoints from older releases.
    except (OSError, ValueError, TypeError, KeyError):
        pass
    if offset < 0 or offset > info.st_size:
        offset = 0
    records, next_offset = read_batch(path, offset)
    if next_offset == offset:
        return False
    if records:
        payload = {"resourceLogs": [to_otlp(record)["resourceLogs"][0] for record in records]}
        if not send(payload):
            return False
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=offset_path.parent,
                                         prefix=offset_path.name + ".", delete=False) as output:
            temporary = Path(output.name)
            json.dump({"identity": identity, "offset": next_offset}, output)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(offset_path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return True


def run() -> None:
    path = Path(os.environ.get("TDS_LOG_PATH", r"C:\ProgramData\TDS\tds_threat_events.jsonl"))
    offset_path = path.with_suffix(path.suffix + ".otlp.offset")
    interval = float(os.environ.get("TDS_OTLP_POLL_SECONDS", "2"))
    if not 0 < interval <= 3600:
        raise ValueError("TDS_OTLP_POLL_SECONDS must be between 0 and 3600")
    while True:
        try:
            export_once(path, offset_path)
        except (OSError, ValueError) as error:
            print(f"TDS exporter: {error}", flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    run()
