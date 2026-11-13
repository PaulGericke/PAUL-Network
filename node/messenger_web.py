import hmac
import json
import os
import re
import secrets
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit
import messenger


MESSENGER_VERSION = '4.3'
DEFAULT_PORT = 47863


def ensure_access_code(data_dir):
    key_path = Path(data_dir) / 'messenger-web.key'
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if not key_path.exists():
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, 'w') as f:
                f.write(secrets.token_urlsafe(15))
    token = key_path.read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,64}', token):
        raise RuntimeError('Ungültiger Messenger-Zugangscode in /data')
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return token


def registration_info(data_dir):
    return {
        'enabled': True,
        'version': MESSENGER_VERSION,
        'port': int(os.getenv('MESSENGER_PORT', str(DEFAULT_PORT))),
        'access_code': ensure_access_code(data_dir),
    }


def start(data_dir, my_id, state, port=None):
    token = ensure_access_code(data_dir)
    page = Path(__file__).with_name('messenger.html').read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def respond(self, code, value, kind='application/json; charset=utf-8'):
            payload = value if isinstance(value, bytes) else json.dumps(value).encode()
            self.send_response(code)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def authorized(self):
            value = self.headers.get('Authorization','')
            if not hmac.compare_digest(value, 'Bearer ' + token):
                self.respond(401, {'error':'Bitte den Geräte-Zugangscode eingeben.'})
                return False
            return True

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == '/':
                return self.respond(200, page, 'text/html; charset=utf-8')
            if path != '/api/state':
                return self.respond(404, {'error':'Nicht gefunden'})
            if not self.authorized():
                return
            now = time.time()
            local = dict(state)
            local['gateway_connected'] = now - local.get('last_pull',0) < 120
            local['loop_healthy'] = now - local.get('loop_at',0) < 15
            self.respond(200, {'node':my_id,'name':os.getenv('MESSENGER_NAME', my_id),
                'contacts': messenger.contacts(data_dir, my_id), 'radio':local,'server_time':now,
                'max_bytes':messenger.MAX_TEXT,'fast_bytes':messenger.FAST_MAX,'max_attempts':messenger.MAX_ATTEMPTS,'messages':messenger.history(data_dir)})

        def do_POST(self):
            path = urlsplit(self.path).path
            if path not in ('/api/send','/api/retry','/api/cancel'):
                return self.respond(404, {'error':'Nicht gefunden'})
            if not self.authorized():
                return
            origin = self.headers.get('Origin')
            if origin and urlsplit(origin).netloc != self.headers.get('Host'):
                return self.respond(403, {'error':'Ungültiger Ursprung'})
            try:
                if self.headers.get('Content-Type','').split(';')[0] != 'application/json':
                    raise ValueError('JSON erforderlich')
                size = int(self.headers.get('Content-Length','0'))
                if size < 1 or size > 2048:
                    raise ValueError('Ungültige Anfragegröße')
                body = json.loads(self.rfile.read(size))
                peer = str(body.get('peer','')).lower()
                if not re.fullmatch('[0-9a-f]{16}', peer) or peer == my_id:
                    raise ValueError('Gültige Empfänger-Node-ID erforderlich')
                if path == '/api/send':
                    content = body.get('text')
                    if not isinstance(content, str) or not content.strip():
                        raise ValueError('Bitte eine Nachricht eingeben')
                    if len(content.encode('utf-8')) > messenger.MAX_TEXT:
                        raise ValueError(f'Maximal {messenger.MAX_TEXT} UTF-8-Bytes pro Nachricht')
                    with messenger.database(data_dir) as db:
                        count = db.execute("SELECT count(*) FROM messages WHERE direction='out' AND status='queued'").fetchone()[0]
                    if count >= 10:
                        raise ValueError('Warteschlange voll: maximal zehn Nachrichten')
                    mid = messenger.queue(data_dir,peer,content)
                    self.respond(201, {'id':mid,'status':'queued'})
                else:
                    mid = str(body.get('id',''))
                    if not re.fullmatch('[0-9a-f]{16}',mid):
                        raise ValueError('Ungültige Nachrichten-ID')
                    if not messenger.change_status(data_dir,mid,peer,path.rsplit('/',1)[-1]):
                        return self.respond(409, {'error':'Status bereits geändert. Ansicht wird aktualisiert.'})
                    self.respond(200, {'ok':True})
            except (ValueError, TypeError, AttributeError) as exc:
                self.respond(400, {'error':str(exc)})

    server = HTTPServer((os.getenv('MESSENGER_BIND','0.0.0.0'), int(port if port is not None else os.getenv('MESSENGER_PORT',str(DEFAULT_PORT)))), Handler)
    threading.Thread(target=server.serve_forever, daemon=True, name='messenger-web').start()
    return server
