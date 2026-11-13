"""Host-side worker for the signed serial installation protocol."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import tempfile
import urllib.parse
import gnss_heal  # PAUL_GNSS_HEAL_V1
import urllib.request
import fcntl
import hardware
import collector_transport
import paul_node as core

PACKAGE = Path(__file__).resolve().parent.parent
VERSION = '0.5.30'
HOST_VERSION = '4.2.17'
ROOT = Path('/opt/paul-node')
STATE = ROOT / 'central-update-state.json'

class UnsupportedCapability(RuntimeError):
    pass

SIGNER = '''import os,sys,json,base64,time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
body=json.load(sys.stdin)
key=Ed25519PrivateKey.from_private_bytes((Path(os.environ.get('DATA_DIR','/data'))/'ed25519-private.key').read_bytes())
public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
body['public_key']=base64.b64encode(public).decode()
body['signature']=base64.b64encode(key.sign(json.dumps(body,sort_keys=True,separators=(',',':')).encode())).decode()
print(json.dumps(body))
'''

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):
        return None

def fetch(url, data=None):
    request=urllib.request.Request(url, data=data, headers={'Content-Type':'application/json','User-Agent':'PAUL-Updater/'+HOST_VERSION})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(request,timeout=30) as r:
        raw=r.read(512*1024+1)
    if len(raw)>512*1024:raise RuntimeError('Response exceeds limit')
    return raw

def report(d, collector, node, phase, token=None, detail=''):
    body={'schema':'paulnet-host-ota-v1','kind':'host_update','node':node,
          'gateway':core.env_dict(d).get('GATEWAY_EUI',''), 'timestamp':int(time.time()),
          'nonce':secrets.token_hex(16),'status':{'release':VERSION,'phase':phase,
          'token':token,'cid':d['Id'],'detail':detail[:300]}}
    p=subprocess.run(['docker','exec','-i',d['Id'],'python','-c',SIGNER],
        input=json.dumps(body),stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,timeout=30)
    if p.returncode:raise RuntimeError('Cannot sign host report in existing node')
    signed=json.loads(p.stdout)
    result=json.loads(fetch(collector+'/v1/register',json.dumps(signed).encode()))
    if result.get('ok') is not True or result.get('node')!=node or result.get('nonce')!=body['nonce'] or result.get('version')!=VERSION:
        raise RuntimeError('Host report response mismatch')
    return result

def eligibility():
    model=Path('/proc/device-tree/model')
    if not model.exists() or not hardware.supported_board(model.read_text().strip('\x00\n')):
        return 'No supported Raspberry Pi board detected'
    if re.search(r'(?im)^(?:ID|NAME)=.*balena',Path('/etc/os-release').read_text()):
        return 'BalenaOS requires its supervisor integration'
    if not Path('/run/systemd/system').is_dir() or not shutil.which('nmcli'):
        return 'Existing systemd and NetworkManager required'
    if not Path('/sys/class/net/wlan0').exists():
        return 'No wlan0 radio; interface selection required'
    return None

SNAPSHOT_STAMP = '20260831T235959Z'
SNAPSHOT_POLICY = '#!/bin/sh\n# PAUL temporary package policy\nexit 101\n'


def os_codename():
    try:
        raw = Path('/etc/os-release').read_text()
    except OSError:
        return ''
    values = {}
    for line in raw.splitlines():
        if '=' not in line or line.lstrip().startswith('#'):
            continue
        key, value = line.split('=', 1)
        values[key] = value.strip().strip('"')
    return values.get('VERSION_CODENAME', '').lower()


def apt_run(args, env, options=()):
    command = ['apt-get'] + list(options) + list(args)
    p = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True, timeout=600, env=env)
    if p.stdout:
        print(p.stdout, end='', flush=True)
    return p


def snapshot_options(folder):
    root = Path(folder)
    lists = root / 'lists'
    (lists / 'partial').mkdir(parents=True, exist_ok=True)
    sources = root / 'sources.list'
    sources.write_text(
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/' + SNAPSHOT_STAMP + '/ bullseye main\n'
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/' + SNAPSHOT_STAMP + '/ bullseye-security main\n'
    )
    return [
        '-o', 'Dir::Etc::sourcelist=' + str(sources),
        '-o', 'Dir::Etc::sourceparts=-',
        '-o', 'Dir::State::lists=' + str(lists),
        '-o', 'Acquire::Check-Valid-Until=false',
        '-o', 'Acquire::Retries=2',
    ]


def dependency_source(packages, env):
    # Pre-download every missing package before the node/application transaction.
    # A Bullseye 404 is the known archive-rotation failure already seen on test gateways.
    update = apt_run(['update'], env)
    if update.returncode == 0:
        download = apt_run(['install', '--download-only', '-y', '--no-install-recommends'] + packages, env)
        if download.returncode == 0:
            return []
        failure = download.stdout or ''
    else:
        failure = update.stdout or ''
    if os_codename() != 'bullseye' or ('404' not in failure and 'Failed to fetch' not in failure):
        raise RuntimeError('APT dependency pre-download failed')
    print('PAUL: Bullseye package fetch failed; using isolated Debian snapshot ' + SNAPSHOT_STAMP, flush=True)
    return 'snapshot'


def dependencies():
    # Install AP utilities only. Never install/replace NetworkManager.
    tools={'iw':'iw','ip':'iproute2','nft':'nftables','hostapd':'hostapd','hostapd_cli':'hostapd','dnsmasq':'dnsmasq-base','curl':'curl'}
    packages=sorted(set(package for tool,package in tools.items() if not shutil.which(tool)))
    if not packages:return
    if not Path('/etc/debian_version').exists() or not shutil.which('apt-get'):
        raise RuntimeError('AP packages missing; automatic package install supports Debian hosts only')
    policy=Path('/usr/sbin/policy-rc.d')
    if policy.exists() or policy.is_symlink():
        raise RuntimeError('Existing package service policy requires review before adding AP packages')
    env=dict(os.environ,DEBIAN_FRONTEND='noninteractive')
    source = dependency_source(packages, env)
    if source == 'snapshot' and packages == ['hostapd'] and direct_bullseye_hostapd(env):
        return
    options = []
    snapshot = None
    if source == 'snapshot':
        snapshot = tempfile.TemporaryDirectory(prefix='paul-apt-snapshot-')
        options = snapshot_options(snapshot.name)
        if apt_run(['update'], env, options).returncode:
            snapshot.cleanup()
            raise RuntimeError('Bullseye snapshot update failed')
        if apt_run(['install', '--download-only', '-y', '--no-install-recommends'] + packages, env, options).returncode:
            snapshot.cleanup()
            raise RuntimeError('Bullseye snapshot dependency pre-download failed')
    # Keep package postinst scripts from starting global hostapd/DHCP services.
    policy.write_text(SNAPSHOT_POLICY)
    policy.chmod(0o755)
    try:
        result = apt_run(['install','-y','--no-install-recommends'] + packages, env, options)
        if result.returncode:
            raise RuntimeError('APT dependency installation failed')
    finally:
        if policy.exists() and policy.read_text() == SNAPSHOT_POLICY:
            policy.unlink()
        if snapshot is not None:
            snapshot.cleanup()

def self_update(update, destination):
    if update.get('updater_update_available') is not True:return False
    target=str(update.get('updater_version',''))
    if not re.fullmatch(r'\d+\.\d+\.\d+',target) or tuple(map(int,target.split('.'))) <= tuple(map(int,HOST_VERSION.split('.'))):
        raise RuntimeError('Refusing host updater downgrade/unordered release')
    url=update['_collector']
    address=urllib.parse.urljoin(url+'/',str(update['updater_url']))
    if urllib.parse.urlsplit(address)[:2] != urllib.parse.urlsplit(url)[:2]:
        raise RuntimeError('Host updater origin mismatch')
    raw=fetch(address)
    if hashlib.sha256(raw).hexdigest()!=str(update['updater_sha256']).lower():raise RuntimeError('Host updater checksum mismatch')
    compile(raw,str(destination),'exec')
    path=Path(destination)
    if path.is_symlink():raise RuntimeError('Updater destination is a symlink')
    previous=path.with_name(path.name+'.previous')
    shutil.copy2(path,previous);previous.chmod(0o700)
    temp=path.with_name('.'+path.name+'.new')
    temp.write_bytes(raw);temp.chmod(0o700)
    path.with_name(path.name+'.pending').write_text(hashlib.sha256(raw).hexdigest()+'\n')
    os.replace(str(temp),str(path))
    return True

def prepare_timeout():
    override=Path('/etc/systemd/system/paul-updater.service.d/zzzzz-paul-host-timeout.conf')
    setting='[Service]\nTimeoutStartSec=1800\n'
    if override.is_symlink():raise RuntimeError('Timeout override is a symlink')
    if override.exists() and override.read_text()==setting:return False
    override.parent.mkdir(parents=True,exist_ok=True)
    override.write_text(setting);override.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True,timeout=30)
    return True


def ordered_release(value):
    match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:-[A-Za-z0-9._-]+)?', str(value))
    if not match:
        raise RuntimeError('Cannot order persisted host release')
    return tuple(map(int, match.groups()))


def archive_state(state):
    core.atomic_json(ROOT / 'central-update-state.previous.json', state)
    STATE.unlink()


def read_state(node, cid, data):
    if not STATE.exists():
        return None
    if STATE.is_symlink():
        raise RuntimeError('Persisted host state is a symlink')
    state = json.loads(STATE.read_text())
    if state.get('node') != node or state.get('cid') != cid:
        raise RuntimeError('Persisted host identity changed')
    installed = (data / 'version').read_text().strip()
    release = state.get('release')
    # The old worker omitted a release field. Only a clean done receipt can
    # inherit the installed version; incomplete or failed work is never erased.
    if release is None and state.get('phase') == 'done':
        release = installed
    if state.get('phase') == 'done' and ordered_release(installed) != ordered_release(release):
        raise RuntimeError('Completed host receipt does not match installed version')
    if state.get('phase') == 'done' and ordered_release(release) < ordered_release(VERSION):
        if ordered_release(installed) != ordered_release(release):
            raise RuntimeError('Completed host receipt does not match installed version')
        for name in ('wifi-install-pending.json', 'code-transaction.json', 'transaction.json'):
            if (ROOT / name).exists():
                raise RuntimeError('Old host completion has unresolved recovery journal')
        state['release'] = release
        archive_state(state)
        return None
    if release is not None and ordered_release(release) != ordered_release(VERSION):
        raise RuntimeError('Previous host release is incomplete or newer; explicit recovery required')
    state['release'] = VERSION
    return state


def saved_country(data):
    path = ROOT / 'wifi-config.json'
    if not path.exists():
        return None
    if path.is_symlink():
        raise RuntimeError('WiFi configuration is a symlink')
    cfg = json.loads(path.read_text())
    if cfg.get('data') != str(data):
        raise RuntimeError('WiFi configuration belongs to different node data')
    return cfg.get('country')


def profile_preflight(data):
    return hardware.inspect(fallback_country=saved_country(data))

WIFI_STATE = ROOT / 'wifi-host-state.json'
WIFI_RETRY = {'failed': 6 * 3600, 'unsupported': 24 * 3600}

def wifi_host(d, collector, node, now=None, installer=None):
    """Server-requested WLAN host install for nodes >= 0.5.31; node code untouched.

    Returns True when this run acted (installed or recorded a failure)."""
    now = int(time.time()) if now is None else now
    if (ROOT / 'wifi-config.json').exists():
        return False
    try:
        previous = json.loads(WIFI_STATE.read_text())
    except (OSError, ValueError):
        previous = {}
    wait = WIFI_RETRY.get(previous.get('phase'))
    if wait and now - int(previous.get('at', 0)) < wait:
        return False
    reason = eligibility()
    if reason:
        core.atomic_json(WIFI_STATE, {'schema': 1, 'phase': 'unsupported', 'at': now, 'cid': d['Id'], 'detail': reason[:300]})
        print('WLAN host unsupported: ' + reason)
        return True
    try:
        if installer:
            installer()
        else:
            subprocess.run([sys.executable, str(PACKAGE / 'install-wifi-host.py'), '--apply', '--ota', '--source', d['Id']],
                           check=True, timeout=1200)
    except Exception as error:
        core.atomic_json(WIFI_STATE, {'schema': 1, 'phase': 'failed', 'at': now, 'cid': d['Id'], 'detail': str(error)[:300]})
        print('WLAN host installation failed; retry later: ' + str(error)[:300])
        return True
    core.atomic_json(WIFI_STATE, {'schema': 1, 'phase': 'done', 'at': now, 'cid': d['Id'], 'detail': ''})
    print('WLAN host installed; node code unchanged')
    return True

def main(destination,check_only=False):
    if os.geteuid()!=0:raise RuntimeError('Run as root')
    docker=core.Docker()
    d=core.source_node(docker)
    data,unused=core.validate_source(d)
    node=(data/'node-id').read_text().strip()
    collector=collector_transport.canonical(core.env_dict(d).get('COLLECTOR_URL',''))
    url=urllib.parse.urlsplit(collector)
    transport=collector_transport.verify_host_route(collector)
    if not transport:
        raise RuntimeError('Host control requires HTTPS, localhost, or routed Tailscale HTTP')
    # PAUL_GNSS_HEAL_V1: restart a stuck PAUL GNSS bridge (installed hosts only, max every 6 h)
    # and report its state with the update check (visible to the PAUL server).
    gnss='check-only' if check_only else gnss_heal.heal(state_file=ROOT/'gnss-heal.json')
    query=urllib.parse.urlencode({'node':node,'version':(data/'version').read_text().strip(),'updater_version':HOST_VERSION,'gnss':gnss})
    update=json.loads(fetch(collector+'/v1/update/check?'+query))
    if check_only:
        print(json.dumps({'node':node,'host_version':HOST_VERSION,'container_id':d['Id'],
            'check_only':True,'eligibility':eligibility(),'advertised_version':update.get('latest_version')},indent=2))
        return
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (ROOT/'central-worker.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        update['_collector']=collector
        if self_update(update,destination):return
        # PAUL_WIFI_HOST_OTA_V1: host-only WLAN service for nodes >= 0.5.31.
        if update.get('wifi_host_required') is True and not update.get('host_ota_required'):
            if wifi_host(d,collector,node):return
        if update.get('latest_version') != VERSION or not update.get('host_ota_required'):
            if update.get('update_available') is True:
                # Keep ordinary OTA available after the coordinated Pi release.
                core.check_update(docker,core.Lifecycle(docker))
            else:print('No targeted update offered')
            return
        state=read_state(node,d['Id'],data)
        if state:
            if state['phase'] == 'unsupported':
                try:
                    reason = eligibility()
                    if reason:
                        raise RuntimeError(reason)
                    profile_preflight(data)
                except RuntimeError as error:
                    state['detail'] = 'Capability preflight: ' + str(error)[:270]
                    core.atomic_json(STATE, state)
                    report(d,collector,node,'unsupported',state['token'],state['detail'])
                    return
                archive_state(state)
                state = None
        if state:
            if state['phase']=='running':
                state['phase']='failed';state['detail']='Interrupted installation; recovery journal requires review'
                core.atomic_json(STATE,state)
            report(d,collector,node,state['phase'],state['token'],state['detail']);return
        reason=eligibility()
        if reason:
            report(d,collector,node,'unsupported',detail=reason);print(reason);return
        # Extend the unit for the NEXT timer run before any lengthy install.
        if prepare_timeout():
            print('Host OTA timeout prepared; installation on next timer run');return
        answer=report(d,collector,node,'ready')
        if answer.get('work') is not True:
            print('Waiting for serial rollout slot: '+str(answer.get('phase')));return
        token=answer.get('token')
        if not isinstance(token,str) or not re.fullmatch('[0-9a-f]{32}',token):raise RuntimeError('Invalid work grant')
        state={'node':node,'cid':d['Id'],'release':VERSION,'phase':'running','token':token,'detail':''}
        core.atomic_json(STATE,state)
        try:
            report(d,collector,node,'running',token)
            dependencies()
            # Capability checks finish before any app/WLAN transaction. An
            # unsupported signed receipt may release this slot safely; an
            # application failure still blocks it until explicit recovery.
            try:
                profile = profile_preflight(data)
            except RuntimeError as error:
                if any((ROOT / name).exists() for name in ('wifi-install-pending.json','code-transaction.json','transaction.json')):
                    raise RuntimeError('Capability failure with unresolved recovery journal')
                raise UnsupportedCapability('Capability preflight: '+str(error)[:270])
            subprocess.run([sys.executable,str(PACKAGE/'install-pi.py'),'--apply','--ota','--source',d['Id'],
                            '--country',profile['country']],check=True,timeout=1200)
            now=docker.inspect(d['Id'])
            if not now or now['Id']!=d['Id'] or (data/'version').read_text().strip()!=VERSION:
                raise RuntimeError('Same-container application verification failed')
            state['phase']='done';state['detail']='Pi WLAN host and application installed; container ID retained'
        except UnsupportedCapability as error:
            state['phase']='unsupported';state['detail']=str(error)[:300]
        except Exception as error:
            state['phase']='failed';state['detail']=str(error)[:300]
        core.atomic_json(STATE,state)
        report(d,collector,node,state['phase'],token,state['detail'])
        if state['phase']=='failed':raise RuntimeError(state['detail'])

"""Recovered 4.2.11 behavior, with the missing _apt permissions corrected.

Constants and fallback contract come from the 7 October build conversation.
This implementation is newly reconstructed; it is not the byte-identical 4.2.11.
"""
HOSTAPD_BULLSEYE_VERSION = '2:2.9.0-21+deb11u3'
HOSTAPD_BULLSEYE_SHA256 = '36314d6fab3d055c7de9dbf988d47042076485a825aa6c31a64b7b9ae7ce44a0'
HOSTAPD_BULLSEYE_URL = ('https://snapshot.debian.org/archive/debian-security/'
                        '20260831T235959Z/pool/updates/main/w/wpa/'
                        'hostapd_2.9.0-21%2bdeb11u3_arm64.deb')


def direct_bullseye_hostapd(env):
    if os_codename() != 'bullseye':
        return False
    architecture = subprocess.check_output(['dpkg', '--print-architecture'],
                                            universal_newlines=True, timeout=15).strip()
    if architecture != 'arm64':
        return False
    with tempfile.TemporaryDirectory(prefix='paul-hostapd-direct-') as folder:
        root = Path(folder)
        deb = root / 'hostapd.deb'
        with urllib.request.urlopen(HOSTAPD_BULLSEYE_URL, timeout=30) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != HOSTAPD_BULLSEYE_SHA256:
            raise RuntimeError('Pinned hostapd package checksum/size mismatch')
        deb.write_bytes(raw)
        fields = subprocess.check_output(['dpkg-deb', '-f', str(deb), 'Package', 'Version', 'Architecture'],
                                          universal_newlines=True, timeout=15)
        metadata = dict(line.split(': ', 1) for line in fields.strip().splitlines())
        if metadata != {'Package': 'hostapd', 'Version': HOSTAPD_BULLSEYE_VERSION, 'Architecture': 'arm64'}:
            raise RuntimeError('Pinned hostapd package metadata mismatch')
        # _apt must traverse the temporary directory and read the checked file.
        root.chmod(0o755)
        deb.chmod(0o644)
        policy = Path('/usr/sbin/policy-rc.d')
        fd = os.open(str(policy), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
        policy_stat = os.fstat(fd)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(SNAPSHOT_POLICY)
                os.fchmod(stream.fileno(), 0o755)
            result = apt_run(['install', '-y', '--no-remove', '--no-install-recommends', str(deb)], env)
            if result.returncode:
                raise RuntimeError('Pinned hostapd installation failed')
            installed = subprocess.check_output(['dpkg-query', '-W', '-f=${Status}|${Version}|${Architecture}', 'hostapd'],
                                                 universal_newlines=True, timeout=15).strip()
            if installed != 'install ok installed|' + HOSTAPD_BULLSEYE_VERSION + '|arm64':
                raise RuntimeError('Installed hostapd version/status mismatch')
        finally:
            if not policy.is_symlink() and policy.exists():
                current = policy.stat()
                if (current.st_dev, current.st_ino) == (policy_stat.st_dev, policy_stat.st_ino) and policy.read_text() == SNAPSHOT_POLICY:
                    policy.unlink()
        return True
