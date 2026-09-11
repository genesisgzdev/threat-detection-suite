"""Read actual TDS events through a local, read-only web interface."""
from __future__ import annotations

import argparse
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
from urllib.parse import urlsplit


def read_events(path: Path, limit: int = 200) -> dict:
    try:
        # Read only the end of large files. An interrupted final write is retried
        # on the next refresh instead of being presented as a damaged event.
        with path.open('rb') as source:
            source.seek(0, 2)
            size = source.tell()
            start = max(0, size - 1024 * 1024)
            source.seek(start)
            if start:
                source.readline()
            content = source.read(1024 * 1024)
        lines = content.splitlines(keepends=True)
        events = deque(maxlen=limit)
        invalid = 0
        for line in lines:
            if not line.endswith(b'\n'):
                continue
            try:
                value = json.loads(line)
                if not isinstance(value, dict) or not isinstance(value.get('description'), str):
                    raise ValueError('event has no description')
                events.append({key: value.get(key) for key in ('timestamp', 'severity', 'category', 'description', 'pid', 'ioc')})
            except (ValueError, UnicodeError):
                invalid += 1
        return {'status': 'available', 'events': list(reversed(events)), 'invalidLines': invalid,
                'limited': bool(start or len(lines) > limit), 'path': str(path)}
    except FileNotFoundError:
        return {'status': 'waiting', 'events': [], 'message': 'Todavía no encontramos el archivo de eventos. Comprueba que TDS está en marcha y que la ruta es correcta.'}
    except OSError:
        return {'status': 'unreadable', 'events': [], 'message': 'No pudimos leer el archivo. Comprueba sus permisos y vuelve a intentarlo.'}


def make_handler(path: Path, limit: int):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if urlsplit('http://' + self.headers.get('Host', '')).hostname not in ('127.0.0.1', 'localhost'):
                self.send_error(403)
                return
            route = urlsplit(self.path).path
            nonce = secrets.token_urlsafe(24)
            if route == '/api/events':
                content = json.dumps(read_events(path, limit), ensure_ascii=False).encode('utf-8')
                mime = 'application/json; charset=utf-8'
            elif route == '/':
                content = Path(__file__).with_name('monitor.html').read_text(encoding='utf-8').replace('NONCE_VALUE', nonce).encode('utf-8')
                mime = 'text/html; charset=utf-8'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *_args):
            pass
    return Handler


def main():
    parser = argparse.ArgumentParser(description='Abre un panel con los eventos reales de TDS. No cambia el equipo.')
    parser.add_argument('--log', type=Path, default=Path(os.environ.get('TDS_LOG_PATH', r'C:\ProgramData\TDS\tds_threat_events.jsonl')))
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--limit', type=int, default=200, help='eventos recientes que muestra el panel')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.limit < 1:
        parser.error('Elige un puerto de 1 a 65535 y al menos un evento.')
    try:
        with ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(args.log, args.limit)) as server:
            print(f'TDS | Abre http://127.0.0.1:{args.port}\nArchivo: {args.log}\nCtrl+C para cerrar el panel.', flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        return 0
    except OSError as error:
        parser.exit(1, f'No pude abrir el panel: {error}. Prueba otro puerto con --port.\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
