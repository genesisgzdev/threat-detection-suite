import importlib.util
import os
import unittest
from pathlib import Path


MODULE = Path(__file__).parents[1] / "tools/soc/otlp_exporter.py"
spec = importlib.util.spec_from_file_location("tds_otlp_exporter", MODULE)
exporter = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(exporter)


class OtlpMappingTests(unittest.TestCase):
    def test_endpoint_is_disabled_without_configuration(self):
        old_logs = os.environ.pop("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", None)
        old_base = os.environ.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)
        try:
            self.assertEqual(exporter.endpoint(), "")
        finally:
            if old_logs is not None:
                os.environ["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = old_logs
            if old_base is not None:
                os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = old_base

    def test_otlp_mapping_preserves_security_fields(self):
        record = {
            "timestamp": 1700000000000,
            "severity": "HIGH",
            "category": "C2_COMMUNICATION",
            "pid": 1234,
            "description": "suspicious \"beacon\"",
        }
        mapped = exporter.to_otlp(record)
        log = mapped["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
        self.assertEqual(log["severityText"], "HIGH")
        self.assertEqual({item["key"] for item in log["attributes"]}, {"tds.category", "process.pid"})
        self.assertIn("beacon", log["body"]["stringValue"])


if __name__ == "__main__":
    unittest.main()
