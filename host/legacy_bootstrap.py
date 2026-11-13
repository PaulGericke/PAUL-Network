"""One-command migration from pre-v3 PAUL host updaters to the canonical updater."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

import collector_transport
import paul_node as core

ROOT = Path('/opt/paul-node')
TIMERS = ('paul-updater.timer', 'opennet-updater.timer', 'paulnet-updater.timer', 'paul-node-updater.timer')
SERVICES = tuple(x.replace('.timer', '.service') for x in TIMERS)


def run(args, check=True, timeout=120):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args[:3]))
    return p


def state(unit, action='is-active'):
    return run(['systemctl', action, '--quiet', unit], False).returncode == 0


def atomic_text(path, text, mode):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError('Managed path is a symlink: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.new')
    tmp.write_text(text)
    tmp.chmod(mode)
    os.replace(str(tmp), str(path))


def main(self_path, package):
    if os.geteuid() != 0:
        raise RuntimeError('Run as root on the node')
    docker = core.Docker()
    old = core.source_node(docker)
    data, unused = core.validate_source(old)
    node = (data / 'node-id').read_text().strip()
    if not re.fullmatch(r'[0-9a-f]{16}', node):
        raise RuntimeError('Existing node ID is invalid')
    collector = collector_transport.canonical(core.env_dict(old).get('COLLECTOR_URL', ''))
    mode = collector_transport.verify_host_route(collector)
    if not mode:
        raise RuntimeError('Collector transport is not trusted; HTTPS, localhost, or routed Tailscale HTTP required')
    if not Path('/run/systemd/system').is_dir():
        raise RuntimeError('systemd host required')
    if any(state(unit) for unit in SERVICES):
        raise RuntimeError('An updater service is currently running; retry after it finishes')

    root = ROOT
    backup = root / ('legacy-bootstrap-backup-' + str(int(time.time())))
    backup.mkdir(parents=True, exist_ok=False, mode=0o700)
    files = {}
    units = {}
    override = Path('/etc/systemd/system/paul-updater.service.d/zzzzz-paul-central.conf')
    for path in (root/'central-updater.py', Path('/etc/systemd/system/paul-updater.service'), Path('/etc/systemd/system/paul-updater.timer'), override):
        files[str(path)] = {'exists': path.exists(), 'content': path.read_text() if path.exists() else None,
                            'mode': (path.stat().st_mode & 0o777) if path.exists() else None}
    for unit in TIMERS:
        units[unit] = {'active': state(unit), 'enabled': state(unit, 'is-enabled')}
    core.atomic_json(backup/'state.json', {'schema':1,'node':node,'container_id':old['Id'],'files':files,'timers':units})

    updater = Path(self_path).read_text()
    service = (Path(package)/'host'/'paul-updater.service').read_text()
    timer = (Path(package)/'host'/'paul-updater.timer').read_text()
    for unit in TIMERS:
        run(['systemctl','stop',unit],False)
    try:
        atomic_text(root/'central-updater.py', updater, 0o700)
        atomic_text('/etc/systemd/system/paul-updater.service', service, 0o644)
        atomic_text('/etc/systemd/system/paul-updater.timer', timer, 0o644)
        atomic_text(override, '[Service]\nExecStart=\nExecStart=/usr/bin/python3 /opt/paul-node/central-updater.py\nUser=root\nTimeoutStartSec=1800\n', 0o644)
        for unit in TIMERS[1:]:
            run(['systemctl','disable',unit],False)
        run(['systemctl','daemon-reload'])
        effective = run(['systemctl','show','paul-updater.service','-p','ExecStart','--value']).stdout
        if '/opt/paul-node/central-updater.py' not in effective:
            raise RuntimeError('Canonical updater service is not effective')
        current = docker.inspect(old['Id'])
        if not current or current['Id'] != old['Id']:
            raise RuntimeError('Node container changed during bootstrap')
        run(['/usr/bin/python3','/opt/paul-node/central-updater.py','--check-only'])
        run(['systemctl','enable','--now','paul-updater.timer'])
    except Exception:
        for p, item in files.items():
            path=Path(p)
            if item['exists']:
                atomic_text(path,item['content'],item['mode'])
            elif path.exists():
                path.unlink()
        run(['systemctl','daemon-reload'],False)
        for unit, before in units.items():
            if before['enabled']:run(['systemctl','enable',unit],False)
            else:run(['systemctl','disable',unit],False)
            if before['active']:run(['systemctl','start',unit],False)
        raise
    from central_worker import HOST_VERSION
    print(json.dumps({'ok':True,'node':node,'container_id':old['Id'],'collector_transport':mode,
                      'host_updater':HOST_VERSION,'canonical_timer':'paul-updater.timer','backup':str(backup)},indent=2))
