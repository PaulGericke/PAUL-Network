#!/usr/bin/python3
"""Managed Pi AP backend; uplink policy belongs to wifi_service.py."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

AP = 'paul-ap0'
TAG = 'PAUL WiFi auto1'
ADDRESS = '10.77.64.1/24'
SSID = 'PAUL-Pi'
TABLE = 'paul_wifi_auto1'
RUN = Path('/run/paul-wifi-auto1')
STATE = RUN / 'state.json'
NM = Path('/run/NetworkManager/conf.d/99-paul-wifi-auto1.conf')
NM_TEXT = '[device-paul-wifi-auto1]\nmatch-device=interface-name:paul-ap0\nmanaged=0\n'
CONFIG = json.loads(Path('/opt/paul-node/wifi-config.json').read_text())
KEY = Path(CONFIG['data']) / 'messenger-web.key'
SSID = CONFIG['ssid']
RADIO = CONFIG.get('ap_interface', 'wlan0')
COUNTRY = CONFIG.get('country', 'DE')


def cmd(args, check=True, text=None):
    p = subprocess.run(args, input=text, text=True, capture_output=True, timeout=12)
    if check and p.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args) + '\n' + p.stderr.strip())
    return p


def channel():
    if 'Connected to ' not in cmd(['iw', 'dev', RADIO, 'link']).stdout:
        return 1  # Standalone fallback while the router is unavailable
    m = re.search(r'channel (\d+) \((\d+) MHz\)', cmd(['iw', 'dev', RADIO, 'info']).stdout)
    if not m or not 1 <= int(m[1]) <= 11:
        raise RuntimeError('This Pi backend requires a 2.4 GHz channel from 1 to 11')
    return int(m[1])


def protected_messenger(host):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://' + host + ':47863/', timeout=4) as r:
        if b'paul-messenger-token' not in r.read(200000):
            raise RuntimeError('PAUL Messenger UI missing')
    try:
        opener.open('http://' + host + ':47863/api/state', timeout=4)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return
        raise
    raise RuntimeError('Messenger API is not access-code protected')


def firewall():
    return f'''table inet {TABLE} {{
 chain input {{
  type filter hook input priority -10; policy accept;
  iifname "{AP}" udp sport 68 udp dport 67 accept
  iifname "{AP}" tcp dport 47863 accept
  iifname "{AP}" ip protocol icmp accept
  iifname "{AP}" drop
 }}
 chain forward {{
  type filter hook forward priority -10; policy accept;
  iifname "{AP}" drop
  oifname "{AP}" drop
 }}
}}\n'''


def hostapd_config(code, ch):
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,63}', code):
        raise RuntimeError('Existing Messenger code is unsuitable for WPA2; no code changed')
    psk = hashlib.pbkdf2_hmac('sha1', code.encode(), SSID.encode(), 4096, 32).hex()
    return f'''interface={AP}
driver=nl80211
ctrl_interface={RUN}/ctrl
ssid={SSID}
country_code={COUNTRY}
ieee80211d=1
hw_mode=g
channel={ch}
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_psk={psk}
ap_isolate=1
max_num_sta=8
'''


def preflight():
    for b in ('iw', 'ip', 'nft', 'nmcli', 'hostapd', 'hostapd_cli', 'dnsmasq'):
        if not shutil.which(b):
            raise RuntimeError('Missing dependency: ' + b)
    if STATE.exists() or NM.exists() or NM.is_symlink():
        raise RuntimeError('Pilot resources already exist; stop the pilot before retrying')
    if cmd(['ip', 'link', 'show', AP], False).returncode == 0:
        raise RuntimeError('Reserved AP interface already exists')
    if cmd(['nft', 'list', 'table', 'inet', TABLE], False).returncode == 0:
        raise RuntimeError('Reserved firewall table already exists')
    net = ipaddress.IPv4Interface(ADDRESS).network
    for r in json.loads(cmd(['ip', '-j', '-4', 'route', 'show', 'table', 'all']).stdout):
        if r.get('dst', 'default') != 'default' and net.overlaps(ipaddress.IPv4Network(r['dst'], strict=False)):
            raise RuntimeError('AP subnet overlaps an existing route')
    from hardware import has_ap, concurrent_ap
    info = cmd(['iw', 'dev', RADIO, 'info']).stdout
    phy = re.search(r'wiphy\s+(\d+)', info)
    if not phy:
        raise RuntimeError('WLAN physical device missing')
    mode = cmd(['iw', 'phy', 'phy' + phy.group(1), 'info']).stdout
    if not has_ap(mode):
        raise RuntimeError('AP mode not advertised')
    connected = 'Connected to ' in cmd(['iw', 'dev', RADIO, 'link']).stdout
    if connected and not concurrent_ap(mode):
        raise RuntimeError('Simultaneous managed/AP combination not advertised')
    ch = channel()
    protected_messenger('127.0.0.1')
    code = KEY.read_text().strip()
    hostapd_config(code, ch)
    cmd(['nft', '--check', '--file', '-'], text=firewall())
    print(f'PASS: AP+station, channel {ch}, subnet free, existing Messenger code usable', flush=True)
    return ch, code


def save(state):
    RUN.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = STATE.with_suffix('.tmp')
    tmp.write_text(json.dumps(state))
    tmp.chmod(0o600)
    tmp.replace(STATE)


def cleanup():
    if not STATE.exists():
        return
    s = json.loads(STATE.read_text())
    if s.get('tag') != TAG:
        raise RuntimeError('Unknown ownership; cleanup refused')
    if s.get('ap'):
        p = cmd(['ip', '-j', 'link', 'show', AP], False)
        if p.returncode == 0:
            if json.loads(p.stdout)[0].get('ifalias') != TAG:
                raise RuntimeError('AP ownership changed; cleanup refused')
            cmd(['iw', 'dev', AP, 'del'])
    if s.get('table') and cmd(['nft', 'list', 'table', 'inet', TABLE], False).returncode == 0:
        cmd(['nft', 'delete', 'table', 'inet', TABLE])
    if s.get('nm') and NM.exists():
        if NM.read_text() != NM_TEXT:
            raise RuntimeError('NM snippet ownership changed; cleanup refused')
        NM.unlink()
        cmd(['nmcli', 'general', 'reload', 'conf'])
    for name in ('hostapd.conf', 'leases'):
        if (RUN / name).exists():
            (RUN / name).unlink()
    STATE.unlink()
    print('Pilot cleaned up; wlan0 connection profile was not changed', flush=True)


def run(ch, code):
    s = {'tag': TAG, 'nm': False, 'table': False, 'ap': False}
    children = []
    stopped = []
    signal.signal(signal.SIGTERM, lambda *a: stopped.append(True))
    signal.signal(signal.SIGINT, lambda *a: stopped.append(True))
    try:
        save(s)
        NM.parent.mkdir(parents=True, exist_ok=True)
        # Only this new virtual device is excluded from NM; no service restart.
        with NM.open('x') as f:
            f.write(NM_TEXT)
        s['nm'] = True
        save(s)
        cmd(['nmcli', 'general', 'reload', 'conf'])
        cmd(['nft', '--file', '-'], text=firewall())
        s['table'] = True
        save(s)
        cmd(['iw', 'dev', RADIO, 'interface', 'add', AP, 'type', '__ap'])
        try:
            sta = json.loads(cmd(['ip', '-j', 'link', 'show', RADIO]).stdout)[0]['address']
            mac = bytearray.fromhex(sta.replace(':', ''))
            mac[0] = (mac[0] | 2) & 254
            mac[5] ^= 128
            ap_address = ':'.join(f'{b:02x}' for b in mac)
            cmd(['ip', 'link', 'set', AP, 'address', ap_address])
            cmd(['ip', 'link', 'set', AP, 'alias', TAG])
        except Exception:
            cmd(['iw', 'dev', AP, 'del'])
            raise
        s['ap'] = True
        save(s)
        cmd(['ip', 'address', 'add', ADDRESS, 'dev', AP])
        path = RUN / 'hostapd.conf'
        with path.open('x') as f:
            f.write(hostapd_config(code, ch))
        path.chmod(0o600)
        children.append(subprocess.Popen(['hostapd', str(path)]))
        deadline = time.monotonic() + 20
        while not stopped:
            if children[0].poll() is not None:
                raise RuntimeError('hostapd failed to start')
            status = cmd(['hostapd_cli', '-p', str(RUN / 'ctrl'), '-i', AP, 'status'], False)
            if 'state=ENABLED' in status.stdout:
                break
            if time.monotonic() > deadline:
                raise RuntimeError('AP did not become ready within 20 seconds')
            time.sleep(0.5)
        if stopped:
            return
        protected_messenger('10.77.64.1')
        children.append(subprocess.Popen(['dnsmasq', '--keep-in-foreground',
            '--conf-file=/dev/null', '--port=0', '--interface=' + AP,
            '--bind-dynamic', '--except-interface=lo',
            '--dhcp-range=10.77.64.10,10.77.64.30,255.255.255.0,1h',
            '--dhcp-option=3', '--dhcp-option=6', '--dhcp-authoritative',
            '--dhcp-leasefile=' + str(RUN / 'leases'), '--pid-file=']))
        print('WIFI READY: ' + SSID + ' / http://10.77.64.1:47863 / existing Messenger device code', flush=True)
        failures = 0
        while not stopped:
            if any(p.poll() is not None for p in children):
                raise RuntimeError('AP/DHCP process stopped')
            try:
                if channel() != ch:
                    raise RuntimeError('Router channel changed')
                failures = 0
            except RuntimeError:
                failures += 1
                if failures >= 3:
                    raise RuntimeError('Uplink lost or channel changed; removing the AP pilot')
            time.sleep(2)
    finally:
        for p in children:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
        cleanup()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['check', 'run', 'cleanup'])
    a = p.parse_args()
    if os.geteuid() != 0:
        p.error('Run as root on Pi')
    os.umask(0o077)
    with open('/run/paul-wifi-auto1.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if a.action == 'cleanup':
            cleanup()
        else:
            ch, code = preflight()
            if a.action == 'run':
                run(ch, code)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('PAUL WiFi pilot stopped: ' + str(e), file=sys.stderr)
        sys.exit(1)
