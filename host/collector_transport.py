"""Collector transport policy shared by PAUL host and node components."""
import ipaddress
import os
import json
from pathlib import Path
import re
import subprocess
import urllib.parse

TAILSCALE_NET = ipaddress.ip_network('100.64.0.0/10')
LOCAL_HOSTS = {'localhost', '127.0.0.1', '::1'}
TRUST_FILE = 'collector-transport.json'
PUBLIC_COLLECTOR = 'https://node.paulnetwork.io'
# Old private collector addresses that are rewritten to the public collector (comma-separated, optional).
LEGACY_COLLECTORS = {u.strip().rstrip('/') for u in os.environ.get('PAUL_LEGACY_COLLECTORS', '').split(',') if u.strip()}


def canonical(url):
    """Map retired, explicitly-known collector endpoints to the public VPS ingress."""
    value = str(url or '').rstrip('/')
    return PUBLIC_COLLECTOR if value in LEGACY_COLLECTORS else value


def _tailscale_ip(host):
    try:
        return ipaddress.ip_address(host) in TAILSCALE_NET
    except ValueError:
        return False


def classify(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme == 'https' and parsed.netloc:
        return 'https'
    if parsed.scheme == 'http' and parsed.hostname in LOCAL_HOSTS:
        return 'local-http'
    if parsed.scheme == 'http' and parsed.hostname and _tailscale_ip(parsed.hostname):
        return 'tailscale-http'
    return None


def verify_host_route(url):
    """Return transport class; require tailscale device for cleartext CGNAT."""
    mode = classify(url)
    if mode != 'tailscale-http':
        return mode
    host = urllib.parse.urlsplit(url).hostname
    p = subprocess.run(['ip', '-j', 'route', 'get', host], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, text=True, timeout=20)
    if p.returncode:
        return None
    try:
        routes = json.loads(p.stdout)
    except Exception:
        return None
    for route in routes:
        if str(route.get('dev', '')).startswith('tailscale'):
            return mode
    return None


def trust_value(url, mode):
    return {'schema': 1, 'collector': url.rstrip('/'), 'transport': mode}


def node_allows(url, data):
    mode = classify(url)
    if mode in ('https', 'local-http'):
        return True
    if mode != 'tailscale-http':
        return False
    p = Path(data) / TRUST_FILE
    try:
        value = json.loads(p.read_text())
    except Exception:
        return False
    return value == trust_value(url, mode)
