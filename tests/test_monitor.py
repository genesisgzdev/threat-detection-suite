import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import urlopen, Request
from urllib.error import HTTPError

spec = importlib.util.spec_from_file_location('monitor', Path(__file__).resolve().parents[1] / 'tools/monitor.py')
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


class MonitorTests(unittest.TestCase):
    def test_live_append_and_rotation_are_visible_without_losing_partial_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            self.assertEqual(monitor.read_events(path)['status'], 'waiting')
            path.write_text('{"description":"first"}\n{"description":', encoding='utf-8')
            self.assertEqual(len(monitor.read_events(path)['events']), 1)
            with path.open('a', encoding='utf-8') as stream:
                stream.write('"second"}\ninvalid\n')
            data = monitor.read_events(path)
            self.assertEqual([e['description'] for e in data['events']], ['second', 'first'])
            self.assertEqual(data['invalidLines'], 1)
            path.replace(path.with_suffix('.old'))
            path.write_text('{"description":"new file"}\n', encoding='utf-8')
            self.assertEqual(monitor.read_events(path)['events'][0]['description'], 'new file')

    def test_http_reads_configured_file_and_rejects_foreign_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            value = {'description': '<script>not executable</script>', 'severity': 'HIGH'}
            path.write_text(json.dumps(value) + '\n', encoding='utf-8')
            server = ThreadingHTTPServer(('127.0.0.1', 0), monitor.make_handler(path, 200))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                with urlopen(base + '/api/events') as response:
                    self.assertEqual(response.headers['Cache-Control'], 'no-store')
                    self.assertEqual(json.load(response)['events'][0]['description'], value['description'])
                with urlopen(base) as response:
                    text = response.read().decode()
                    self.assertIn('textContent=event.description', text)
                    self.assertNotIn('NONCE_VALUE', text)
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(base + '/api/events', headers={'Host': 'unrelated.example'}))
                self.assertEqual(caught.exception.code, 403)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
