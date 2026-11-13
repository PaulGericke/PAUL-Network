#!/usr/bin/env python3
"""PAUL targeted code OTA in the existing container: same ID, image and settings.

Code backups and durable journals provide rollback without a replacement node.
Legacy image-switch recovery is retained only for interrupted older transactions.
"""
import argparse
import base64
import copy
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import collector_transport
import uuid

CONTAINER = 'paul-node'
UPDATER_VERSION = '4.1.0-inplace2'
LIFECYCLE_SCHEMA = 1
ROOT = Path('/opt/paul-node')
ALIASES = ('paul-node', 'opennet-node', 'paulnet-node')
IMAGE_RE = re.compile(r'^(?:[^/]+/)?(?:paulnet-node|paul-node)(?::|@)')
NAME_RE = re.compile(r'^(?:opennet-node|paulnet-node|paul-node)(?:-before[-_].*|-rollback[-_].*)?$')
IDENTITY_FILES = ('node-id', 'ed25519-private.key', 'messenger-web.key')
REQUIRED = {'Dockerfile.node', 'node.py', 'protocol.py', 'rtk.py', 'requirements.txt'}
MAX_PACKAGE = 32 * 1024 * 1024


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=path.name + '.', dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
        dirfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def env_dict(descriptor):
    return dict(e.split('=', 1) for e in descriptor['Config'].get('Env', []) if '=' in e)


def data_mount(descriptor):
    destination = env_dict(descriptor).get('DATA_DIR', '/data')
    mounts = [m for m in descriptor.get('Mounts', []) if m.get('Destination') == destination]
    if len(mounts) != 1 or mounts[0].get('Type') != 'bind' or not mounts[0].get('RW'):
        raise RuntimeError('Node requires one writable persistent data bind mount')
    return mounts[0]


def is_node(d):
    labels = d.get('Config', {}).get('Labels') or {}
    image = d.get('Config', {}).get('Image', '')
    name = d.get('Name', '').lstrip('/')
    return bool(NAME_RE.fullmatch(name) and (IMAGE_RE.match(image) or
                labels.get('io.paulnetwork.component') == 'node'))


def same_identity(a, b):
    try:
        am, bm = data_mount(a), data_mount(b)
        ae, be = env_dict(a), env_dict(b)
        return (os.path.realpath(am['Source']) == os.path.realpath(bm['Source']) and
                am['Destination'] == bm['Destination'] and
                ae.get('GATEWAY_EUI') == be.get('GATEWAY_EUI'))
    except (KeyError, RuntimeError):
        return False


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, sock, timeout=120):
        super().__init__('localhost', timeout=timeout)
        self.unix_socket = sock

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_socket)


class Docker:
    def __init__(self, sock='/var/run/docker.sock'):
        self.socket = sock
        self.prefix = ''
        version = self.request('GET', '/version')['ApiVersion']
        api = tuple(int(v) for v in version.split('.'))
        if api < (1, 24):
            raise RuntimeError('Docker API 1.24 or newer required')
        # Docker may reject API versions below its configured minimum.
        # Negotiate from the daemon's unversioned /version response and then
        # use exactly the API version the daemon advertises.
        self.prefix = '/v%s' % version

    def request(self, method, path, body=None, missing=False, raw=False):
        conn = UnixHTTP(self.socket)
        try:
            payload = json.dumps(body).encode() if body is not None else None
            headers = {'Content-Type': 'application/json'} if body is not None else {}
            conn.request(method, self.prefix + path, payload, headers)
            response = conn.getresponse()
            data = response.read()
            if missing and response.status in (400, 404):
                # Some older Docker engines answer a missing named container with
                # HTTP 400 instead of 404. Treat only the explicit Docker
                # "No such container" error as absence; every other 400 stays
                # fatal so API/version/configuration errors are never hidden.
                if response.status == 404:
                    return None
                try:
                    message = json.loads(data.decode()).get('message', '')
                except Exception:
                    message = ''
                if isinstance(message, str) and message.lower().startswith('no such container'):
                    return None
            if response.status == 304 and method == 'POST' and re.search(r'/containers/[^/]+/(start|stop)(?:\?|$)', path):
                return {}
            if response.status >= 300:
                # Docker error bodies may include config values. Never print them.
                raise RuntimeError('Docker %s %s returned HTTP %s' % (method, path.split('?')[0], response.status))
            if raw:
                return data
            return json.loads(data.decode()) if data else {}
        finally:
            conn.close()

    def inspect(self, name):
        return self.request('GET', '/containers/%s/json' % urllib.parse.quote(name, safe=''), missing=True)

    def containers(self):
        result = []
        for item in self.request('GET', '/containers/json?all=1'):
            d = self.inspect(item['Id'])
            if d:
                result.append(d)
        return result

    def policy(self, cid, policy):
        self.request('POST', '/containers/%s/update' % cid, {'RestartPolicy': policy})

    def stop(self, cid):
        d = self.inspect(cid)
        if d and (d['State'].get('Running') or d['State'].get('Restarting')):
            self.request('POST', '/containers/%s/stop?t=20' % cid)

    def start(self, cid):
        d = self.inspect(cid)
        if d and not d['State'].get('Running'):
            self.request('POST', '/containers/%s/start' % cid)

    def rename(self, cid, name):
        self.request('POST', '/containers/%s/rename?name=%s' % (cid, urllib.parse.quote(name, safe='')))

    def remove(self, cid):
        # No force, no volume deletion. Caller must first stop the exact ID.
        self.request('DELETE', '/containers/%s?v=false&force=false' % cid)

    def create(self, name, body):
        return self.request('POST', '/containers/create?name=' + urllib.parse.quote(name, safe=''), body)['Id']

    def image(self, name):
        return self.request('GET', '/images/%s/json' % urllib.parse.quote(name, safe=''))

    def tag(self, image, tag):
        repo, value = tag.rsplit(':', 1)
        self.request('POST', '/images/%s/tag?repo=%s&tag=%s' %
                     (urllib.parse.quote(image, safe=''), urllib.parse.quote(repo, safe=''), value))

    def logs(self, cid):
        raw = self.request('GET', '/containers/%s/logs?stdout=1&stderr=1&tail=200' % cid, raw=True)
        # Non-TTY Docker logs use 8-byte stream headers.
        d = self.inspect(cid)
        if d and d['Config'].get('Tty'):
            return raw.decode(errors='replace')
        text, offset = [], 0
        while offset + 8 <= len(raw):
            n = int.from_bytes(raw[offset + 4:offset + 8], 'big')
            if offset + 8 + n > len(raw):
                break
            text.append(raw[offset + 8:offset + 8 + n].decode(errors='replace'))
            offset += 8 + n
        return ''.join(text)


def source_node(docker, requested=None):
    if requested:
        d = docker.inspect(requested)
        if not d or not is_node(d):
            raise RuntimeError('Requested source is not an identified PAUL node')
        return d
    canonical = docker.inspect(CONTAINER)
    if canonical:
        if not is_node(canonical):
            raise RuntimeError('Name paul-node is occupied by a different application')
        return canonical
    sources = [docker.inspect(n) for n in ALIASES[1:]]
    sources = [d for d in sources if d and is_node(d)]
    if len(sources) != 1:
        raise RuntimeError('Expected one existing node; select a source with --source')
    return sources[0]


def identity_hashes(data):
    result = {}
    for name in IDENTITY_FILES:
        p = Path(data) / name
        if p.is_file():
            raw = p.read_text().strip().encode() if name == 'node-id' else p.read_bytes()
            result[name] = hashlib.sha256(raw).hexdigest()
    if 'node-id' not in result or 'ed25519-private.key' not in result:
        raise RuntimeError('Existing node ID/private key missing; refusing to generate a new identity')
    return result


def ensure_identity(data, expected):
    current = identity_hashes(data)
    if any(current.get(name) != digest for name, digest in expected.items()):
        raise RuntimeError('Persistent identity or existing access code changed')


def snapshot_identity(data):
    result = {}
    for name in IDENTITY_FILES:
        p = Path(data) / name
        if p.is_symlink():
            raise RuntimeError('Identity symlink requires manual inspection')
        if p.is_file():
            st = p.stat()
            result[name] = {'bytes': base64.b64encode(p.read_bytes()).decode(),
                            'mode': st.st_mode & 0o777, 'uid': st.st_uid, 'gid': st.st_gid}
    return result


def restore_identity(data, values, hashes):
    # Restore only stable identity/access files if a failed candidate changed
    # them. Do not overwrite messages, sequences, replay protection or airtime.
    for name, value in values.items():
        p = Path(data) / name
        raw = p.read_bytes() if p.is_file() else None
        expected = base64.b64decode(value['bytes'])
        if raw == expected:
            continue
        if p.is_symlink():
            raise RuntimeError('Identity became a symlink; recovery requires inspection')
        fd, tmp = tempfile.mkstemp(prefix=name + '.', dir=str(data))
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(expected)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, value['mode'])
            os.chown(tmp, value['uid'], value['gid'])
            os.replace(tmp, str(p))
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    ensure_identity(data, hashes)


def validate_source(d):
    if not d['State'].get('Running') or d['State'].get('Restarting'):
        raise RuntimeError('Source node must be running normally before migration/update')
    host = d['HostConfig']
    if host.get('AutoRemove') or host.get('ContainerIDFile') or host.get('VolumesFrom'):
        raise RuntimeError('Unsupported automatic removal/container dependencies; inspect host first')
    if host.get('NetworkMode') != 'host':
        raise RuntimeError('This release supports the verified host-network node setup only')
    if (d['Config'].get('Labels') or {}).get('io.balena.service-name'):
        raise RuntimeError('Balena-supervised nodes require a supervisor application release')
    m = data_mount(d)
    return Path(m['Source']), identity_hashes(m['Source'])


def create_config(old, old_image, image, tx):
    config = copy.deepcopy(old['Config'])
    defaults = image.get('Config') or {}
    old_defaults = old_image.get('Config') or {}
    for key in ('Cmd', 'Entrypoint', 'WorkingDir', 'User', 'Healthcheck'):
        if config.get(key) == old_defaults.get(key):
            if key in defaults:
                config[key] = copy.deepcopy(defaults[key])
            else:
                config.pop(key, None)
    # Image-owned defaults (PATH, Python version, etc.) follow the new image;
    # deployment-specific overrides and all existing application settings stay.
    old_env = env_dict(old)
    inherited = dict(e.split('=', 1) for e in old_defaults.get('Env', []) if '=' in e)
    merged = dict(e.split('=', 1) for e in defaults.get('Env', []) if '=' in e)
    runtime_defaults = {'PATH', 'LANG', 'GPG_KEY', 'PYTHON_VERSION', 'PYTHON_SHA256',
                        'PYTHON_PIP_VERSION', 'PYTHON_SETUPTOOLS_VERSION'}
    merged.update({k: v for k, v in old_env.items()
                   if k not in runtime_defaults or inherited.get(k) != v})
    config['Env'] = [k + '=' + v for k, v in merged.items()]
    labels = dict(config.get('Labels') or {})
    labels.update({'io.paulnetwork.component': 'node', 'io.paulnetwork.lifecycle': '1',
                   'io.paulnetwork.transaction': tx})
    config['Labels'] = labels
    config['Image'] = image['Id']
    config['HostConfig'] = copy.deepcopy(old['HostConfig'])
    # A stopped legacy container must never be revived after reboot.
    config['HostConfig']['RestartPolicy'] = {'Name': 'unless-stopped', 'MaximumRetryCount': 0}
    for key in ('Hostname', 'Domainname'):
        if config.get(key) == old['Id'][:12]:
            config[key] = ''
    return config


def read_url(url, limit=MAX_PACKAGE):
    req = urllib.request.Request(url, headers={'User-Agent': 'PAUL-Updater/' + UPDATER_VERSION})
    with urllib.request.urlopen(req, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError('Update response exceeds size limit')
    return data


def validate_extract(archive, directory):
    total, seen = 0, set()
    with tarfile.open(str(archive), 'r:gz') as bundle:
        members = bundle.getmembers()
        if len(members) > 1000:
            raise RuntimeError('Too many archive entries')
        for member in members:
            p = PurePosixPath(member.name)
            normalized = str(p)
            if (not member.name or '\\' in member.name or p.is_absolute() or '..' in p.parts or
                    member.issym() or member.islnk() or not (member.isfile() or member.isdir()) or
                    normalized in seen):
                raise RuntimeError('Unsafe or duplicate archive entry')
            seen.add(normalized)
            total += member.size
            if total > 64 * 1024 * 1024:
                raise RuntimeError('Archive exceeds extracted size limit')
        if not REQUIRED.issubset(seen):
            raise RuntimeError('Incomplete node release')
        # All members inspected before any extraction; only regular files/dirs.
        for member in members:
            dest = Path(directory) / member.name
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source, dest.open('wb') as target:
                    target.write(source.read())
                dest.chmod(0o644)


def local_web_expected(data):
    """Use the same validated Pi profile gate as node 0.5.31."""
    try:
        status = json.loads((Path(data) / 'wifi-status.json').read_text())
    except (FileNotFoundError, OSError, ValueError, TypeError):
        return False
    profile = status.get('profile') if isinstance(status, dict) else None
    return bool(isinstance(profile, dict) and status.get('supported') is True
                and profile.get('schema') == 1
                and profile.get('family') in ('raspberry-pi', 'rak-v2-mntd',
                                              'sensecap-m1', 'finestra')
                and str(profile.get('board', '')).startswith('Raspberry Pi ')
                and profile.get('host_version') == 'wifi-pi-v3'
                and profile.get('backend') == 'systemd-networkmanager-hostapd')


def healthy(docker, cid, data, hashes, version=None, timeout=90, restart_baseline=0):
    expected_node = (Path(data) / 'node-id').read_text().strip()
    deadline = time.monotonic() + timeout
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic() < deadline:
        d = docker.inspect(cid)
        if (not d or not d['State'].get('Running') or d['State'].get('Restarting') or
                (version is not None and d.get('RestartCount', 0) > restart_baseline)):
            raise RuntimeError('Candidate exited or restarted')
        ensure_identity(data, hashes)
        token = Path(data) / 'messenger-web.key'
        if local_web_expected(data):
            if not token.is_file():
                raise RuntimeError('Validated Pi local web access key is missing')
            port = int(env_dict(d).get('MESSENGER_PORT', '47863'))
            try:
                url = 'http://127.0.0.1:%d/api/state' % port
                try:
                    opener.open(url, timeout=2).close()
                    raise RuntimeError('Messenger accepts an unauthenticated API request')
                except urllib.error.HTTPError as error:
                    if error.code != 401:
                        raise
                req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token.read_text().strip()})
                with opener.open(req, timeout=2) as response:
                    state = json.load(response)
                if (state.get('node') == expected_node and state.get('radio', {}).get('loop_healthy') and
                        (version is None or state.get('radio', {}).get('version') == version)):
                    return True
            except (OSError, ValueError):
                pass
        else:
            for line in docker.logs(cid).splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if (event.get('type') == 'NODE_STARTED' and event.get('node') == expected_node and
                        (version is None or event.get('version') == version)):
                    return True
        time.sleep(1)
    raise RuntimeError('Node/Messenger health check timed out')


class Lifecycle:
    def __init__(self, docker, root=ROOT, health=healthy):
        self.docker, self.root, self.health = docker, Path(root), health
        self.pending = self.root / 'transaction.json'

    def plan(self, source=None):
        old = source_node(self.docker, source)
        data, hashes = validate_source(old)
        duplicates = [d for d in self.docker.containers() if d['Id'] != old['Id'] and is_node(d) and same_identity(old, d)]
        return old, data, hashes, duplicates

    def quiesce(self, d):
        self.docker.policy(d['Id'], {'Name': 'no', 'MaximumRetryCount': 0})
        self.docker.stop(d['Id'])

    def recover(self):
        from in_place import Update
        updater = Update(self.docker, self.root, self.code_health, identity=self.code_identity)
        updater.recover()
        if not self.pending.exists():
            return
        tx = json.loads(self.pending.read_text())
        if tx.get('schema') != LIFECYCLE_SCHEMA:
            raise RuntimeError('Unknown transaction schema; automatic recovery refused')
        if tx['phase'] == 'committed':
            new = self.docker.inspect(tx['current_id'])
            if not new or new['Name'].lstrip('/') != CONTAINER:
                raise RuntimeError('Committed node missing; manual recovery required')
            self.finish(tx)
            return
        old = self.docker.inspect(tx['source']['Id'])
        if not old:
            raise RuntimeError('Rollback source missing; leaving data untouched')
        for d in self.docker.containers():
            if (d.get('Config', {}).get('Labels') or {}).get('io.paulnetwork.transaction') == tx['id'] and d['Id'] != old['Id']:
                self.quiesce(d)
                self.docker.remove(d['Id'])
        original_name = tx['source']['Name'].lstrip('/')
        occupant = self.docker.inspect(original_name)
        if occupant and occupant['Id'] != old['Id']:
            raise RuntimeError('Rollback name occupied; refusing to remove another container')
        if old['Name'].lstrip('/') != original_name:
            self.docker.rename(old['Id'], original_name)
        restore_identity(tx['data'], tx.get('identity_values', {}), tx['hashes'])
        if tx.get('version_before') is not None:
            (Path(tx['data']) / 'version').write_text(tx['version_before'])
        self.docker.policy(old['Id'], tx['source']['HostConfig']['RestartPolicy'])
        if tx['source']['State'].get('Running'):
            self.docker.start(old['Id'])
        ensure_identity(tx['data'], tx['hashes'])
        atomic_json(self.root / 'last-rollback.json', {'schema': 1, 'at': int(time.time()), 'source': original_name})
        self.pending.unlink()
        print('ROLLBACK: previous node restored; persistent data retained')

    def finish(self, tx):
        current = self.docker.inspect(tx['current_id'])
        if not current:
            raise RuntimeError('Current node disappeared during cleanup')
        for saved in [tx['source']] + tx['duplicates']:
            d = self.docker.inspect(saved['Id'])
            if d and d['Id'] != current['Id']:
                if not same_identity(current, d):
                    raise RuntimeError('Legacy container identity changed; cleanup refused')
                self.quiesce(d)
                self.docker.remove(d['Id'])
        self.docker.tag(current['Image'], 'paul-node:current')
        if tx.get('operation') == 'update':
            self.docker.tag(tx['source']['Image'], 'paul-node:previous')
        # One bounded protected recovery descriptor, no dormant restartable node.
        if tx['operation'] == 'update' or not (self.root / 'previous.json').exists():
            atomic_json(self.root / 'previous.json', tx['source'])
        atomic_json(self.root / 'config.json', {'schema': 1, 'container': CONTAINER, 'data': tx['data']})
        atomic_json(self.root / 'last-update.json', {'schema': 1, 'at': int(time.time()),
                    'operation': tx['operation'], 'image': current['Image'], 'container': CONTAINER})
        self.pending.unlink()
        if tx['operation'] == 'update':
            try:
                self.prune_images(current['Image'], tx['source']['Image'])
            except Exception:
                print('NOTICE: node healthy; old managed image cleanup deferred')

    def prune_images(self, current, previous):
        used = {d['Image'] for d in self.docker.containers()}
        used.update((current, previous))
        filters = urllib.parse.quote(json.dumps({'label': ['io.paulnetwork.lifecycle=1']}), safe='')
        for image in self.docker.request('GET', '/images/json?filters=' + filters):
            tags = image.get('RepoTags') or []
            if image['Id'] in used or any(not t.startswith('paul-node:') for t in tags):
                continue
            for tag in tags:
                self.docker.request('DELETE', '/images/%s?force=false' % urllib.parse.quote(tag, safe=''))
            self.docker.request('DELETE', '/images/%s?force=false' % urllib.parse.quote(image['Id'], safe=''), missing=True)

    def code_health(self, cid, version, baseline):
        descriptor = self.docker.inspect(cid)
        data = Path(data_mount(descriptor)['Source'])
        txpath = self.root / 'code-transaction.json'
        tx = json.loads(txpath.read_text())
        hashes = tx['node_hashes']
        if self.health is healthy:
            return healthy(self.docker, cid, data, hashes, version, restart_baseline=baseline)
        return self.health(self.docker, cid, data, hashes, version)

    def code_identity(self, tx, rollback):
        if not rollback:
            descriptor = self.docker.inspect(tx['cid'])
            data = Path(data_mount(descriptor)['Source'])
            tx['node_data'] = str(data)
            tx['node_hashes'] = identity_hashes(data)
            tx['identity_values'] = snapshot_identity(data)
            tx['version_before'] = (data / 'version').read_text() if (data / 'version').exists() else None
        else:
            restore_identity(tx['node_data'], tx['identity_values'], tx['node_hashes'])
            if 'messenger-web.key' not in tx['node_hashes']:
                generated = Path(tx['node_data']) / 'messenger-web.key'
                if generated.is_symlink():raise RuntimeError('Generated access code became a symlink')
                if generated.exists():generated.unlink()
            if tx.get('version_before') is not None:
                (Path(tx['node_data']) / 'version').write_text(tx['version_before'])

    def apply_code(self, release, version, source=None):
        from in_place import Update
        self.recover()
        old, data, hashes, duplicates = self.plan(source)
        directory = Path(release)
        expected = {'node.py', 'protocol.py', 'rtk.py', 'messenger.py', 'messenger_web.py',
                    'messenger.html', 'wifi_agent.py'}
        allowed = expected | {'Dockerfile.node', 'requirements.txt'}
        actual = {p.name for p in directory.iterdir() if p.name != '__pycache__'}
        if not expected.issubset(actual) or not actual.issubset(allowed):
            raise RuntimeError('Unreviewed node release layout; no image/container replacement')
        if any(p.is_symlink() or not p.is_file() for p in directory.iterdir() if p.name != '__pycache__'):
            raise RuntimeError('Node release must contain regular files')
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', str(version)):
            raise RuntimeError('Invalid code release version')
        if ('VERSION = "' + str(version) + '"') not in (directory / 'node.py').read_text():
            raise RuntimeError('Node source and target version mismatch')
        expected_dockerfile = '''FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --progress-bar off --no-cache-dir -r requirements.txt
COPY protocol.py rtk.py messenger.py messenger_web.py messenger.html wifi_agent.py node.py ./
CMD ["python", "-u", "node.py"]
'''
        if (directory / 'Dockerfile.node').read_text().strip() != expected_dockerfile.strip():
            raise RuntimeError('Release requests different image/start settings; explicit review required, no replacement')
        config = old['Config']
        if config.get('WorkingDir') != '/app' or config.get('Entrypoint') or config.get('Cmd') not in (
                ['python', '-u', 'node.py'], ['python3', '-u', 'node.py']):
            raise RuntimeError('Existing node start command needs explicit review; no replacement')
        with tempfile.TemporaryDirectory(prefix='paul-inplace-payload-') as folder:
            import shutil
            for name in expected:shutil.copy2(directory / name, Path(folder) / name)
            updater = Update(self.docker, self.root, self.code_health, identity=self.code_identity)
            updater.apply(old['Id'], folder, str(version), (directory / 'requirements.txt').read_text(), True,
                          before_write=lambda: [self.quiesce(d) for d in duplicates])
        current = self.docker.inspect(old['Id'])
        ensure_identity(data, hashes)
        # No container removal, including historical duplicates. Disable the
        # exact same-identity extras so they cannot restart beside this node.
        atomic_json(self.root / 'config.json', {'schema': 1, 'container': current['Name'].lstrip('/'),
                    'container_id': old['Id'], 'data': str(data), 'update_mode': 'in-place'})
        atomic_json(self.root / 'last-update.json', {'schema': 1, 'at': int(time.time()),
                    'operation': 'code-update', 'container_id': old['Id'], 'version': version})

    def execute(self, image=None, version=None, source=None):
        if image is not None:
            raise RuntimeError('Image replacement is disabled; use apply_code on the existing container')
        self.recover()
        old, data, hashes, duplicates = self.plan(source)
        # Explicit legacy-name migration is a rename of the same container.
        if old['Name'].lstrip('/') != CONTAINER:
            if self.docker.inspect(CONTAINER):raise RuntimeError('Canonical name is occupied')
            self.docker.rename(old['Id'], CONTAINER)
        for extra in duplicates:self.quiesce(extra)
        ensure_identity(data, hashes)
        atomic_json(self.root / 'config.json', {'schema': 1, 'container': CONTAINER,
            'container_id': old['Id'], 'data': str(data), 'update_mode': 'in-place'})
        print('MIGRATED: existing container ID retained ' + old['Id'][:12])


def check_update(docker, lifecycle, check_only=False):
    if not check_only:
        lifecycle.recover()
    d = source_node(docker)
    data, unused = validate_source(d)
    node_id = (data / 'node-id').read_text().strip()
    current = (data / 'version').read_text().strip()
    collector = collector_transport.canonical(env_dict(d).get('COLLECTOR_URL', ''))
    parsed = urllib.parse.urlsplit(collector)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        raise RuntimeError('Existing COLLECTOR_URL is missing/invalid')
    query = urllib.parse.urlencode({'node': node_id, 'version': current, 'updater_version': UPDATER_VERSION})
    update = json.loads(read_url(collector + '/v1/update/check?' + query, 1024 * 1024))
    if update.get('update_available') is not True:
        print('PAUL %s: no targeted node update' % current)
        return
    # The collector authorization/targeting contract remains unchanged. Do not
    # consume an old advertised host-updater that would restore opennet-node.
    if update.get('rollout_enabled') is False or update.get('rollout_targeted') is False:
        raise RuntimeError('Collector returned contradictory rollout authorization')
    if update.get('node') and update['node'] != node_id:
        raise RuntimeError('Update is addressed to another node')
    target = str(update['target_version'])
    if target == current:
        return
    # PAUL_NO_AUTOMATIC_DOWNGRADE_V1
    current_release = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?", current)
    target_release = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", target)
    if not current_release or not target_release:
        raise RuntimeError('Automatic update version cannot be ordered safely; use an explicit manual release')
    if tuple(map(int, target_release.groups())) <= tuple(map(int, current_release.groups())):
        print('SKIP: automatic downgrade/non-increasing release blocked: ' + current + ' -> ' + target)
        return
    if update.get('latest_version') and str(update['latest_version']) != target:
        raise RuntimeError('Target and advertised package version differ')
    if check_only:
        print('CHECK-ONLY: targeted node update available; no Docker changes')
        return
    digest = str(update.get('sha256', ''))
    if not re.fullmatch('[0-9a-fA-F]{64}', digest):
        raise RuntimeError('Invalid package SHA256')
    package_url = urllib.parse.urljoin(collector + '/', update['package_url'])
    package_origin = urllib.parse.urlsplit(package_url)
    if (package_origin.scheme, package_origin.netloc) != (parsed.scheme, parsed.netloc):
        raise RuntimeError('Package must be served by the configured collector origin')
    package = read_url(package_url)
    if hashlib.sha256(package).hexdigest() != digest.lower():
        raise RuntimeError('Package checksum mismatch')
    with tempfile.TemporaryDirectory(prefix='paul-node-update-') as temporary:
        folder = Path(temporary)
        archive = folder / 'release.tar.gz'
        archive.write_bytes(package)
        validate_extract(archive, folder / 'release')
        lifecycle.apply_code(folder / 'release', target)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='check', choices=('plan', 'migrate', 'check', 'apply-release', 'recover', 'rollback-code'))
    parser.add_argument('--source')
    parser.add_argument('--root', default=str(ROOT))
    parser.add_argument('--release')
    parser.add_argument('--version')
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args(argv)
    if args.self_test:
        assert CONTAINER == 'paul-node' and LIFECYCLE_SCHEMA == 1
        assert NAME_RE.fullmatch('opennet-node-before-v0.5.22-20260928')
        assert not NAME_RE.fullmatch('opennet-collector')
        print('PASS: lifecycle self-test')
        return
    if os.geteuid() != 0:
        raise RuntimeError('Run as root on the node')
    docker = Docker()
    root = Path(args.root)
    lifecycle = Lifecycle(docker, root)
    if args.action == 'plan':
        old, data, hashes, duplicates = lifecycle.plan(args.source)
        print(json.dumps({'source': old['Name'].lstrip('/'), 'target': CONTAINER,
                          'image': old['Config']['Image'], 'data': str(data),
                          'legacy_containers': [d['Name'].lstrip('/') for d in duplicates],
                          'pending_transaction': lifecycle.pending.exists(),
                          'identity_present': bool(hashes)}, indent=2))
        return
    if args.check_only:
        check_update(docker, lifecycle, True)
        return
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(str(root), 0o700)
    with (root / 'update.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Another PAUL lifecycle operation is running')
            return
        if args.action == 'rollback-code':
            from in_place import Update
            pending = root / 'code-transaction.json'
            if pending.exists():raise RuntimeError('Recover pending transaction before explicit rollback')
            atomic_json(pending, json.loads((root / 'last-code-update.json').read_text()))
            Update(docker, root, lifecycle.code_health, identity=lifecycle.code_identity).recover(rollback_committed=True)
        elif args.action == 'recover':
            lifecycle.recover()
        elif args.action == 'migrate':
            lifecycle.execute(source=args.source)
        elif args.action == 'apply-release':
            if not args.release or not args.version:
                parser.error('apply-release requires --release and --version')
            lifecycle.recover()
            lifecycle.apply_code(args.release, args.version, args.source)
        else:
            check_update(docker, lifecycle)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('PAUL lifecycle stopped: ' + str(error), file=sys.stderr)
        sys.exit(1)
