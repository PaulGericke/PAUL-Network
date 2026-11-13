"""Read-only Pi/WLAN capability inspection. Family labels never authorize hardware."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

FAMILIES = ('raspberry-pi', 'rak-v2-mntd', 'sensecap-m1', 'finestra')

def cmd(args):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=20)
    if p.returncode:
        raise RuntimeError('Capability check failed: ' + ' '.join(args[:2]))
    return p.stdout

def supported_board(model):
    return bool(re.match(r'^Raspberry Pi (?:3 Model [AB]|4 Model B|5 Model B|Zero 2 W|Compute Module [345])\b', model))

def has_ap(text):
    return bool(re.search(r'^\s*\* AP\s*$', text, re.M))

def concurrent_ap(text):
    # Restrict matching to each single advertised combination, not across phys
    # or across independent combinations. Combined managed/AP limit=1 is invalid.
    section = text.split('valid interface combinations:', 1)
    if len(section) != 2:
        return False
    for block in re.split(r'\n\s*\* ', section[1]):
        if '#{' not in block:
            continue
        groups = [(set(x.strip() for x in names.split(',')), int(limit))
                  for names, limit in re.findall(r'#\{\s*([^}]+)\}\s*<=\s*(\d+)', block)]
        total = re.search(r'total\s*<=\s*(\d+)', block)
        if not total or int(total.group(1)) < 2:
            continue
        for i, (names, limit) in enumerate(groups):
            if 'managed' not in names:
                continue
            for j, (others, other_limit) in enumerate(groups):
                if 'AP' in others and limit >= 1 and other_limit >= 1 and (i != j or limit >= 2):
                    return True
    return False

def inspect(interface='wlan0', uplink=None, family='raspberry-pi', country=None, fallback_country=None):
    if sys.version_info < (3, 7):
        raise RuntimeError('WiFi host package requires Python 3.7 or newer')
    if family not in FAMILIES:
        raise RuntimeError('Unknown device family')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface):
        raise RuntimeError('Invalid WLAN interface')
    model = Path('/proc/device-tree/model').read_text().strip('\x00\n')
    if not supported_board(model):
        raise RuntimeError('Actual board is not a supported Raspberry Pi: ' + model)
    os_release = Path('/etc/os-release').read_text()
    if re.search(r'(?im)^(?:ID|NAME)=.*balena', os_release):
        raise RuntimeError('BalenaOS requires a supervisor-managed host release; this installer cannot manage it')
    if not Path('/run/systemd/system').is_dir():
        raise RuntimeError('systemd host required')
    for tool in ('curl', 'iw', 'ip', 'nmcli', 'nft', 'hostapd', 'hostapd_cli', 'dnsmasq', 'docker'):
        if not shutil.which(tool):
            raise RuntimeError('Missing dependency: ' + tool)
    cmd(['nmcli', 'general', 'status'])
    info = cmd(['iw', 'dev', interface, 'info'])
    match = re.search(r'wiphy\s+(\d+)', info)
    if not match:
        raise RuntimeError('Cannot resolve WLAN physical device')
    phy = 'phy' + match.group(1)
    capabilities = cmd(['iw', 'phy', phy, 'info'])
    if not has_ap(capabilities):
        raise RuntimeError('Selected WLAN radio does not advertise AP mode')
    link = cmd(['iw', 'dev', interface, 'link'])
    associated = 'Connected to ' in link
    concurrent = concurrent_ap(capabilities)
    if associated and not concurrent:
        raise RuntimeError('Selected radio cannot advertise station and AP simultaneously; use a second WLAN adapter')
    routes = json.loads(cmd(['ip', '-j', '-4', 'route', 'show', 'default']))
    physical = [r for r in routes if r.get('dev') and not r['dev'].startswith(('tailscale', 'tun', 'wg', 'docker', 'veth', 'br-'))]
    if uplink is None:
        if not physical:
            raise RuntimeError('Cannot determine physical router uplink; specify --uplink')
        uplink = min(physical, key=lambda r: r.get('metric', 0))['dev']
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', uplink) or not Path('/sys/class/net', uplink).is_dir():
        raise RuntimeError('Invalid/missing router uplink interface')
    if uplink.startswith(('tailscale', 'tun', 'wg', 'docker', 'veth', 'br-')):
        raise RuntimeError('Router uplink must be a physical interface')
    if uplink == interface and not concurrent:
        raise RuntimeError('WLAN uplink requires concurrent station/AP support')
    profiles = []
    for line in cmd(['nmcli', '-t', '-f', 'UUID,DEVICE', 'connection', 'show', '--active']).splitlines():
        if line.endswith(':' + interface):
            profiles.append(line.split(':')[0])
    if len(profiles) > 1 or (associated and len(profiles) != 1):
        raise RuntimeError('Router WLAN is not managed by one saved NetworkManager profile')
    if country is None:
        countries = re.findall(r'country ([A-Z]{2}):', cmd(['iw', 'reg', 'get']))
        countries = set(c for c in countries if c != '00')
        if len(countries) == 1:
            country = countries.pop()
        elif not countries and fallback_country:
            country = fallback_country
    if not country or not re.fullmatch(r'[A-Z]{2}', country) or country in ('00', 'XX'):
        raise RuntimeError('Valid local regulatory country required; use --country (e.g. DE)')
    return {'schema': 1, 'board': model, 'family': family, 'ap_interface': interface,
            'uplink': uplink, 'original_profile': profiles[0] if profiles else None,
            'country': country, 'phy': phy, 'concurrent': concurrent,
            'backend': 'systemd-networkmanager-hostapd', 'host_version': 'wifi-pi-v3'}
