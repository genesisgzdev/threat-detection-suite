import http.server
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from test_otlp_exporter import exporter


class DeliveryTests(unittest.TestCase):
    def test_real_http_delivery_retry_partial_line_and_rotation(self):
        requests = []
        class Handler(http.server.BaseHTTPRequestHandler):
            status = 503
            def do_POST(self):
                requests.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(self.status)
                self.end_headers()
            def log_message(self, *_args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                'OTEL_EXPORTER_OTLP_LOGS_ENDPOINT': f'http://127.0.0.1:{server.server_port}/v1/logs',
                'OTEL_EXPORTER_OTLP_HEADERS': '',
            }):
                path = Path(directory) / 'events.jsonl'
                checkpoint = Path(directory) / 'cursor'
                path.write_bytes(b'{"pid":1}\n{"pid":')
                self.assertFalse(exporter.export_once(path, checkpoint))
                self.assertFalse(checkpoint.exists())
                Handler.status = 200
                self.assertTrue(exporter.export_once(path, checkpoint))
                self.assertFalse(exporter.export_once(path, checkpoint))
                with path.open('ab') as output:
                    output.write(b'2}\n')
                self.assertTrue(exporter.export_once(path, checkpoint))
                replacement = path.with_suffix('.new')
                replacement.write_bytes(b'{"pid":3}\n')
                replacement.replace(path)
                self.assertTrue(exporter.export_once(path, checkpoint))
                delivered = [json.loads(item['resourceLogs'][0]['scopeLogs'][0]['logRecords'][0]['body']['stringValue'])['pid'] for item in requests]
                self.assertEqual(delivered, [1, 1, 2, 3])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_batches_are_bounded_and_invalid_records_are_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            path.write_text('null\n[]\nnot-json\n' + '{"pid":1}\n' * 300)
            records, offset = exporter.read_batch(path, 0)
            self.assertEqual(len(records), 97)
            self.assertLess(offset, path.stat().st_size)
