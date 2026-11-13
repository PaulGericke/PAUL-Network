#!/usr/bin/python3
"""Pi local five-minute router Internet watchdog; systemd owns child processes."""
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from controller import Policy
from paul_node import atomic_json

ROOT = Path('/opt/paul-node')
CONFIG = ROOT / 'wifi-config.json'
UPLINK = ROOT / 'wifi-uplink.json'


def cmd(args, check=True, timeout=20):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args[:2]))
    return result


def internet(interface):
    # Bind explicitly to the router interface: Tailscale/default-route changes
    # must not hide an outage. TLS and expected content reject captive portals.
    targets = [('https://www.gstatic.com/generate_204', '204', None),
               ('https://www.cloudflare.com/cdn-cgi/trace', '200', '\nip=')]
    for url, expected, marker in targets:
        try:
            result = cmd(['curl', '--interface', interface, '--noproxy', '*',
                          '--silent', '--show-error', '--max-time', '4',
                          '--max-filesize', '65536', '--write-out', '\nPAUL_CODE:%{http_code}', url], False, 6)
            body, _, code = result.stdout.rpartition('\nPAUL_CODE:')
            if not result.returncode and code == expected and (marker is None or marker in '\n' + body):
                return True
        except (OSError, subprocess.TimeoutExpired):
            pass
    return False


class AP:
    def __init__(self, cfg):
        self.cfg, self.process, self.retry_at = cfg, None, 0
        self.restore_pending = False

    def restore(self):
        if not UPLINK.exists():
            return
        state = json.loads(UPLINK.read_text())
        if state.get('schema') != 1 or state.get('original') != self.cfg['original_profile']:
            raise RuntimeError('Uplink recovery journal does not match this host')
        if state.get('guard'):
            cmd(['systemctl', 'stop', state['guard'] + '.timer'], False)
        # Active switching is allowed only after an intentional temporary clone.
        cmd(['nmcli', '--wait', '45', 'connection', 'up', 'uuid', state['original'], 'ifname', self.cfg.get('ap_interface', 'wlan0')], timeout=50)
        if state.get('clone'):
            cmd(['nmcli', 'connection', 'delete', 'uuid', state['clone']], False)
        UPLINK.unlink()
        self.restore_pending = False

    def prepare_channel(self):
        link = cmd(['iw', 'dev', self.cfg.get('ap_interface', 'wlan0'), 'link']).stdout
        match = re.search(r'freq:\s*(\d+)', link)
        if not match or int(match.group(1)) < 3000:
            return
        if not self.cfg.get('original_profile'):
            raise RuntimeError('5-GHz station has no saved router profile')
        # The existing pilot cannot run on the 5-GHz station channel. Select
        # the same saved router's 2.4-GHz BSSID, not any neighbouring network.
        expected_ssid = cmd(['nmcli', '-g', '802-11-wireless.ssid', 'connection', 'show',
                             'uuid', self.cfg['original_profile']]).stdout.strip()
        scan = cmd(['nmcli', '--escape', 'no', '-t', '-f', 'BSSID,SSID,FREQ',
                    'device', 'wifi', 'list', 'ifname', self.cfg.get('ap_interface', 'wlan0'), '--rescan', 'yes']).stdout
        choices = []
        for line in scan.splitlines():
            bssid, rest = line[:17], line[18:]
            if ':' not in rest:
                continue
            ssid, frequency = rest.rsplit(':', 1)
            number = re.search(r'\d+', frequency)
            if ssid == expected_ssid and number and 2412 <= int(number.group()) <= 2462:
                choices.append(bssid)
        if not choices:
            raise RuntimeError('Router uses 5 GHz and its matching 2.4-GHz BSSID is unavailable')
        # Journal before modifying the uplink. A separate 2-minute guard restores
        # it even if the supervisor crashes during activation/AP startup.
        state = {'schema': 1, 'original': self.cfg['original_profile'], 'clone': None,
                 'guard': 'paul-wifi-channel-guard-' + str(int(time.time()))}
        atomic_json(UPLINK, state)
        name = 'paul-wifi-auto1-uplink'
        if cmd(['nmcli', '-g', 'connection.uuid', 'connection', 'show', name], False).returncode == 0:
            raise RuntimeError('Reserved temporary uplink profile already exists')
        cmd(['nmcli', 'connection', 'clone', '--temporary', 'uuid', state['original'], name])
        state['clone'] = cmd(['nmcli', '-g', 'connection.uuid', 'connection', 'show', name]).stdout.strip()
        atomic_json(UPLINK, state)
        mac = Path('/sys/class/net/' + self.cfg.get('ap_interface', 'wlan0') + '/address').read_text().strip()
        cmd(['nmcli', 'connection', 'modify', '--temporary', 'uuid', state['clone'],
             'connection.autoconnect', 'no', '802-11-wireless.band', '',
             '802-11-wireless.channel', '', '802-11-wireless.bssid', choices[0],
             '802-11-wireless.cloned-mac-address', mac])
        cmd(['systemd-run', '--collect', '--unit=' + state['guard'], '--on-active=120s',
             '/bin/systemctl', 'restart', 'paul-wifi-auto.service'])
        cmd(['nmcli', '--wait', '45', 'connection', 'up', 'uuid', state['clone'], 'ifname', self.cfg.get('ap_interface', 'wlan0')], timeout=50)
        linked = cmd(['iw', 'dev', self.cfg.get('ap_interface', 'wlan0'), 'link']).stdout
        if not re.search(r'freq:\s*24\d\d', linked):
            raise RuntimeError('Temporary 2.4-GHz uplink did not activate')

    def enabled(self):
        if not self.process or self.process.poll() is not None:
            return False
        status = cmd(['hostapd_cli', '-p', '/run/paul-wifi-auto1/ctrl',
                      '-i', 'paul-ap0', 'status'], False).stdout
        return 'state=ENABLED' in status

    def start(self):
        if self.process and self.process.poll() is None:
            return
        if time.monotonic() < self.retry_at:
            return
        if self.restore_pending:
            self.restore()
        self.retry_at = time.monotonic() + 60
        try:
            self.prepare_channel()
            self.process = subprocess.Popen([sys.executable, str(ROOT / 'ap_backend.py'), 'run'])
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                if self.enabled():
                    if UPLINK.exists():
                        guard = json.loads(UPLINK.read_text()).get('guard')
                        if guard:
                            cmd(['systemctl', 'stop', guard + '.timer'], False)
                    return
                if self.process.poll() is not None:
                    break
                time.sleep(0.5)
            raise RuntimeError('AP backend did not become ready')
        except Exception:
            self.stop()
            raise

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process = None
        cmd([sys.executable, str(ROOT / 'ap_backend.py'), 'cleanup'], False)
        self.restore_pending = UPLINK.exists()
        if self.restore_pending:
            self.restore()


def run():
    cfg = json.loads(CONFIG.read_text())
    data = Path(cfg['data'])
    stop = []
    signal.signal(signal.SIGTERM, lambda *args: stop.append(True))
    signal.signal(signal.SIGINT, lambda *args: stop.append(True))
    policy, ap = Policy(cfg['outage_seconds'], cfg['recovery_seconds']), AP(cfg)
    try:
        ap.stop()  # Recover owned resources and a temporary station after crash.
        while not stop:
            desired_ssid = cfg['ssid']
            try:
                control = json.loads((data / 'wifi-control.json').read_text())
                if control.get('node') != (data / 'node-id').read_text().strip():
                    raise ValueError('Node identity mismatch')
                mode, revision = control['mode'], control['revision']
                desired_ssid = control.get('ssid', cfg['ssid'])
                if not isinstance(desired_ssid, str) or not 1 <= len(desired_ssid.encode()) <= 32 or not all(c.isprintable() for c in desired_ssid):
                    raise ValueError('Invalid SSID')
                if mode not in ('auto', 'on', 'off') or type(revision) is not int:
                    raise ValueError('Invalid desired state')
            except FileNotFoundError:
                mode, revision = 'off', 0
            except (ValueError, KeyError, TypeError, OSError):
                # Keep a running supervisor, fail closed on malformed settings.
                mode, revision = 'off', -1
            online = internet(cfg['uplink'])
            wanted = policy.step(mode, online, time.monotonic())
            error = None
            try:
                if desired_ssid != cfg['ssid'] and revision >= 0:
                    if ap.process or UPLINK.exists():
                        ap.stop()
                    cfg['ssid'] = desired_ssid
                    atomic_json(CONFIG, cfg)
                    ap.retry_at = 0
                if wanted:
                    ap.start()
                elif ap.process or UPLINK.exists():
                    ap.stop()
            except Exception as problem:
                error = str(problem)
            actual = ap.enabled()
            atomic_json(data / 'wifi-status.json', {'schema': 1, 'supported': True,
                'mode': mode, 'revision': revision, 'ap_active': actual,
                'internet': online, 'ssid': cfg['ssid'], 'url': 'http://10.77.64.1:47863/',
                'updated_at': int(time.time()), 'error': error[:300] if error else None,
                'profile': cfg.get('profile')})
            for _ in range(10):
                if stop:
                    break
                time.sleep(1)
    finally:
        ap.stop()
        atomic_json(data / 'wifi-status.json', {'schema': 1, 'supported': False,
            'mode': 'off', 'revision': -1, 'ap_active': False, 'internet': False,
            'ssid': cfg['ssid'], 'url': 'http://10.77.64.1:47863/',
            'updated_at': int(time.time()), 'error': 'Host service stopped', 'profile': cfg.get('profile')})


if __name__ == '__main__':
    os.umask(0o077)
    with open('/run/paul-wifi-auto1-supervisor.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if len(sys.argv) > 1 and sys.argv[1] == 'recover':
            AP(json.loads(CONFIG.read_text())).stop()
        else:
            run()
