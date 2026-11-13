"""Restricted signed desired-state exchange; no root commands in the node."""
import base64
import json
import os
from pathlib import Path
import secrets
import threading
import time
import urllib.parse
import urllib.request
import ipaddress
from protocol import canonical_bytes

TAILSCALE_NET = ipaddress.ip_network('100.64.0.0/10')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def atomic(path, value):
    path = Path(path)
    tmp = path.with_suffix('.agent.tmp')
    with tmp.open('w') as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    tmp.replace(path)


def accept(data, node, nonce, response):
    desired = response.get('wifi')
    if response.get('node') != node or response.get('nonce') != nonce or not isinstance(desired, dict):
        raise ValueError('WiFi response identity mismatch')
    revision = desired.get('revision')
    if type(revision) is not int or revision < 0 or desired.get('mode') not in ('auto', 'on', 'off'):
        raise ValueError('Invalid WiFi desired state')
    ssid = desired.get('ssid')
    if ssid is not None and (not isinstance(ssid, str) or not 1 <= len(ssid.encode()) <= 32 or not all(c.isprintable() for c in ssid)):
        raise ValueError('Invalid WiFi name')
    path = Path(data) / 'wifi-control.json'
    old = json.loads(path.read_text()) if path.exists() else {'revision': -1}
    if revision < old.get('revision', -1):
        raise ValueError('WiFi revision moved backwards')
    if revision == old.get('revision') and desired['mode'] != old.get('mode'):
        raise ValueError('WiFi revision conflict')
    value = {'schema': 1, 'node': node, 'revision': revision, 'mode': desired['mode']}
    if ssid is not None or old.get('ssid') is not None:
        value['ssid'] = ssid if ssid is not None else old['ssid']
    if value != old:
        atomic(path, value)


def transport_allowed(data, collector):
    parsed = urllib.parse.urlsplit(collector)
    data = Path(data)
    allowed = bool(parsed.scheme == 'https' and parsed.netloc) or (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1'))
    if allowed:
        return True
    if parsed.scheme != 'http' or not parsed.hostname:
        return False
    try:
        tailscale = ipaddress.ip_address(parsed.hostname) in TAILSCALE_NET
    except ValueError:
        return False
    if not tailscale:
        return False
    try:
        trust = json.loads((data / 'collector-transport.json').read_text())
    except Exception:
        return False
    return trust == {'schema': 1, 'collector': collector.rstrip('/'), 'transport': 'tailscale-http'}


def start(data, collector, private, public, node, gateway, emit):
    data = Path(data)
    if not transport_allowed(data, collector):
        emit('WIFI_CONTROL_DISABLED', reason='HTTPS, local relay, or host-verified Tailscale transport required')
        return

    def worker():
        last_error = 0
        while True:
            try:
                status = json.loads((data / 'wifi-status.json').read_text())
                nonce = secrets.token_hex(16)
                body = {'schema': 'paulnet-wifi-v1', 'kind': 'wifi_control', 'node': node,
                        'gateway': gateway, 'public_key': base64.b64encode(public).decode(),
                        'timestamp': int(time.time()), 'nonce': nonce, 'status': status}
                body['signature'] = base64.b64encode(private.sign(canonical_bytes(body))).decode()
                request = urllib.request.Request(collector.rstrip('/') + '/v1/register',
                    data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'}, method='POST')
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
                with opener.open(request, timeout=8) as response:
                    result = json.loads(response.read(32768).decode())
                accept(data, node, nonce, result)
            except Exception as error:
                # No credentials or server error bodies in logs. Offline failures
                # cannot block RF processing or alter the persisted local mode.
                if time.monotonic() - last_error >= 300:
                    emit("WIFI_CONTROL_ERROR", error=type(error).__name__)
                    last_error = time.monotonic()
            time.sleep(30)

    threading.Thread(target=worker, name='paul-wifi-control', daemon=True).start()
