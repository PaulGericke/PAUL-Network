"""PAUL host updater 4.2.17: GNSS bridge self-heal (PAUL_GNSS_HEAL_V1 + PAUL_GNSS_HEAL_ZERO2_V1).

Narrow host step, runs on every updater run:
- only acts if a PAUL GNSS bridge service is installed: paul-gps-bridge (USB
  receivers) or, on Pi Zero 2 builds, paul-gpsd-bridge (UART receiver via gpsd);
  it never installs anything new;
- checks that the service is active AND that TCP 127.0.0.1:29996 actually
  delivers NMEA ($G...) within a few seconds;
- if not, restarts the service, at most once per HEAL_INTERVAL;
- returns a short status token that the updater appends to its update check
  (gnss=...), so the server can see what is wrong without access to the device.
"""
import glob
import json
import os
from pathlib import Path
import socket
import subprocess
import time

SERVICE = 'paul-gps-bridge.service'
UNIT_FILE = Path('/etc/systemd/system/' + SERVICE)
# PAUL_GNSS_HEAL_ZERO2_V1: Zero2 builds run gpsd + paul-gpsd-bridge, same NMEA port 29996
ZERO2_SERVICE = 'paul-gpsd-bridge.service'
ZERO2_UNIT_FILE = Path('/etc/systemd/system/' + ZERO2_SERVICE)
PORT = 29996
HEAL_INTERVAL = 6 * 3600
STATE_FILE = Path('/var/lib/paul-host/gnss-heal.json')
DEVICE_PATTERNS = ('/dev/serial/by-id/*u-blox*', '/dev/serial/by-id/*U-Blox*',
                   '/dev/serial/by-id/*GNSS*', '/dev/serial/by-id/*GPS*')
ZERO2_DEVICE_PATTERNS = ('/dev/serial0', '/dev/ttyS0', '/dev/ttyAMA0') + DEVICE_PATTERNS


def detect(unit_file=UNIT_FILE, zero2_unit_file=ZERO2_UNIT_FILE):
    """(service, device patterns) of the installed PAUL GNSS bridge, or None."""
    if Path(unit_file).exists():
        return SERVICE, DEVICE_PATTERNS
    if Path(zero2_unit_file).exists():
        return ZERO2_SERVICE, ZERO2_DEVICE_PATTERNS
    return None


def _systemctl(*args):
    return subprocess.run(['systemctl'] + list(args), capture_output=True, text=True, timeout=30)


def nmea_flowing(port=PORT, timeout=4.0):
    """True if the TCP source delivers at least one NMEA sentence quickly."""
    deadline = time.time() + timeout
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=2) as s:
            s.settimeout(1.0)
            buf = b''
            while time.time() < deadline:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    return False
                buf += chunk
                if b'$G' in buf or b'$B' in buf:
                    return True
    except OSError:
        return False
    return False


def device_present(patterns=DEVICE_PATTERNS):
    return any(glob.glob(p) for p in patterns)


def _read_state(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def _write_state(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, sort_keys=True))
    os.replace(str(tmp), str(path))


def heal(now=None, unit_file=UNIT_FILE, state_file=STATE_FILE, systemctl=_systemctl,
         flowing=nmea_flowing, device=None, zero2_unit_file=ZERO2_UNIT_FILE):
    """Check/heal the GNSS bridge. Returns a status token (no exceptions)."""
    now = time.time() if now is None else now
    try:
        found = detect(unit_file, zero2_unit_file)
        if found is None:
            return 'none'                       # no PAUL GNSS bridge on this host
        service, patterns = found
        if device is None:
            device = lambda: device_present(patterns)
        active = systemctl('is-active', service).stdout.strip() == 'active'
        if active and flowing():
            return 'ok'
        cause = 'inactive' if not active else 'nodata'
        if not device():
            cause += '-nodevice'
        state = _read_state(state_file)
        if now - float(state.get('restarted_at', 0)) < HEAL_INTERVAL:
            return cause + '-wait'
        systemctl('restart', service)          # Zero2: Wants=gpsd.service pulls gpsd up too
        state.update(restarted_at=now, cause=cause, service=service)
        _write_state(state_file, state)
        time.sleep(3)
        ok = systemctl('is-active', service).stdout.strip() == 'active' and flowing(timeout=8.0)
        state.update(result='ok' if ok else 'still-failing')
        _write_state(state_file, state)
        return cause + ('-healed' if ok else '-restarted')
    except Exception as error:                  # never break the updater run
        return 'error-' + type(error).__name__
