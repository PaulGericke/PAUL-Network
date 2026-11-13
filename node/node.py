import base64
import hashlib
import json
import os
import secrets
import shutil
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from protocol import (
    BEACON_SIZE,
    LEGACY_MAGIC,
    MAGIC,
    canonical_bytes,
    make_beacon,
    node_id_from_public,
    public_key_bytes,
    verify_beacon,
    witness_signing_body,
)
from rtk import RtkReader
import messenger
import messenger_web
import mesh  # PAUL_MESH_V1


VERSION = "1.0.4"
FREQUENCY = float(os.environ.get("FREQUENCY", "868.3"))
DATARATE = os.environ.get("DATARATE", "SF12BW125")
BEACON_DATARATE = os.environ.get("BEACON_DATARATE", "SF12BW125").strip() or "SF12BW125"
POWER = int(os.environ.get("POWER", "0"))
# PAUL_TX_POWER_V1: the collector answers every registration with the legal
# maximum for this gateway's antenna (EU868: 25 mW ERP). The node only ever
# LOWERS its configured POWER to that limit, never raises it. Without a
# configured POWER (0) it uses that limit, at most 14 dBm (node 1.0.4).
TX_POWER_LIMIT = None
INTERVAL = 3600
PAUL_FIXED_SLOT = os.environ.get("PAUL_FIXED_SLOT", "").strip()
GATEWAY_EUI = os.environ["GATEWAY_EUI"].lower()
# REGION env: EU868 | US915 | AUTO (default). The active policy lives in RADIO.
RADIO = None
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
PUBLIC_COLLECTOR_URL = "https://node.paulnetwork.io"
# Old private collector addresses that are rewritten to the public collector (comma-separated, optional).
LEGACY_COLLECTOR_URLS = {u.strip().rstrip("/") for u in os.environ.get("PAUL_LEGACY_COLLECTORS", "").split(",") if u.strip()}

UNSET_POWER_CAP = 14   # "no POWER configured" never goes above 14 dBm (also in US915)


def tx_power():
    """Effective TX power in dBm.

    POWER > 0: configured value, capped by the collector limit (never raised).
    POWER <= 0 (not configured, old installs): the collector's legal limit for
    this antenna, at most 14 dBm; 0 until the first collector answer arrived.
    """
    limit = TX_POWER_LIMIT
    if POWER <= 0:
        return 0 if limit is None else max(0, min(UNSET_POWER_CAP, limit))
    return POWER if limit is None else min(POWER, limit)


def load_tx_power_limit():
    global TX_POWER_LIMIT
    try:
        value = json.loads((DATA_DIR / "tx-power.json").read_text())
        limit = value.get("max_tx_power_dbm")
        if isinstance(limit, int) and -10 <= limit <= 30:
            TX_POWER_LIMIT = limit
    except (OSError, ValueError, AttributeError):
        pass


def apply_tx_power_limit(radio):
    """Store a collector-provided limit; returns True when it changed."""
    global TX_POWER_LIMIT
    if not isinstance(radio, dict):
        return False
    limit = radio.get("max_tx_power_dbm")
    if not isinstance(limit, int) or isinstance(limit, bool) or not -10 <= limit <= 30:
        return False
    if limit == TX_POWER_LIMIT:
        return False
    TX_POWER_LIMIT = limit
    try:
        tmp = DATA_DIR / "tx-power.tmp"
        tmp.write_text(json.dumps({"max_tx_power_dbm": limit,
                                   "antenna_gain_dbi": radio.get("antenna_gain_dbi"),
                                   "assumed_gain": bool(radio.get("assumed_gain"))}))
        tmp.replace(DATA_DIR / "tx-power.json")
    except OSError:
        pass
    return True


def canonical_collector_url(value):
    value = str(value or "").rstrip("/")
    return PUBLIC_COLLECTOR_URL if value in LEGACY_COLLECTOR_URLS else value

COLLECTOR_URL = canonical_collector_url(os.environ.get("COLLECTOR_URL", ""))
COLLECTOR_TIMEOUT = float(os.environ.get("COLLECTOR_TIMEOUT", "4"))
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "300"))
MAX_CLOCK_SKEW = int(os.environ.get("MAX_CLOCK_SKEW", "300"))
OUTBOX_DB = DATA_DIR / "outbox.sqlite3"
RTK_HOST = os.environ.get("RTK_HOST", "127.0.0.1")
RTK_PORT = int(os.environ.get("RTK_PORT", "29996"))
RTK_REPORT_INTERVAL = int(os.environ.get("RTK_REPORT_INTERVAL", "60"))
PRINT_LOCK = threading.Lock()
TELEMETRY_INTERVAL = max(30, int(os.environ.get("TELEMETRY_INTERVAL", "60")))
PROCESS_STARTED = time.monotonic()
LAST_COLLECTOR_SUCCESS = None
NODE_ID_FOR_MESH = ""
TRACKER_DEVADDRS = {
    value.strip().upper()
    for value in os.environ.get(
        "TRACKER_DEVADDRS",
        "480008A3,480008A4",
    ).split(",")
    if value.strip()
}
TRACKER_RADIO_DISCOVERY = (
    os.environ.get(
        "TRACKER_RADIO_DISCOVERY",
        "0",
    ).strip().lower()
    in {"1", "true", "yes", "on"}
)
ENROLLMENT_FILE = DATA_DIR / "enrollment-token"
ENROLLED_FILE = DATA_DIR / "enrolled"
CLAIM_FILE = DATA_DIR / "claim-token"
CLAIM_PROVISIONED_FILE = DATA_DIR / "claim-provisioned"

PI_WIFI_FAMILIES = ("raspberry-pi", "rak-v2-mntd", "sensecap-m1", "finestra")
PI_WIFI_BACKEND = "systemd-networkmanager-hostapd"
PI_WIFI_HOST_VERSION = "wifi-pi-v3"
LOCAL_MESSENGER_URL = "http://10.77.64.1:47863/"


def wifi_messenger_profile(data_dir=DATA_DIR):
    """Trust only the Pi host service's /data capability status."""
    try:
        value = json.loads((Path(data_dir) / "wifi-status.json").read_text())
    except (FileNotFoundError, OSError, ValueError, TypeError):
        return None
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("supported") is not True:
        return None
    profile = value.get("profile")
    if not isinstance(profile, dict) or profile.get("schema") != 1:
        return None
    if profile.get("family") not in PI_WIFI_FAMILIES:
        return None
    if profile.get("backend") != PI_WIFI_BACKEND or profile.get("host_version") != PI_WIFI_HOST_VERSION:
        return None
    if not str(profile.get("board") or "").startswith("Raspberry Pi "):
        return None
    if value.get("url") != LOCAL_MESSENGER_URL:
        return None
    return profile


def wifi_messenger_enabled(data_dir=DATA_DIR):
    return wifi_messenger_profile(data_dir) is not None


def enrollment_token():
    if ENROLLED_FILE.exists():
        return ""
    value = os.environ.get("ENROLLMENT_TOKEN", "").strip()
    if value:
        return value
    try:
        return ENROLLMENT_FILE.read_text().strip()
    except FileNotFoundError:
        return ""



def claim_token():
    try:
        return CLAIM_FILE.read_text().strip()
    except FileNotFoundError:
        return ""


def utc_iso(value=None):
    return datetime.fromtimestamp(value or time.time(), timezone.utc).isoformat()


def emit(event, **fields):
    with PRINT_LOCK:
        print(json.dumps({"type": event, "time": utc_iso(), **fields}), flush=True)


def load_or_create_key():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    key_path = DATA_DIR / "ed25519-private.key"
    if key_path.exists():
        private = Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
    else:
        private = Ed25519PrivateKey.generate()
        raw = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        key_path.write_bytes(raw)
        os.chmod(key_path, 0o600)
    public_raw = public_key_bytes(private)
    return private, public_raw, node_id_from_public(public_raw)


def read_sequence():
    try:
        return max(1, int((DATA_DIR / "sequence.txt").read_text().strip()))
    except (FileNotFoundError, ValueError):
        return 1


def save_sequence(value):
    temporary = DATA_DIR / "sequence.tmp"
    temporary.write_text(str(value))
    temporary.replace(DATA_DIR / "sequence.txt")


def load_replay_state():
    try:
        return json.loads((DATA_DIR / "replay.json").read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_replay_state(state):
    temporary = DATA_DIR / "replay.tmp"
    temporary.write_text(json.dumps(state, sort_keys=True))
    temporary.replace(DATA_DIR / "replay.json")


def init_outbox():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(OUTBOX_DB) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute(
            "CREATE TABLE IF NOT EXISTS outbox ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint TEXT NOT NULL, "
            "payload TEXT NOT NULL, created_at INTEGER NOT NULL)"
        )


def queue_for_collector(endpoint, payload):
    if not COLLECTOR_URL:
        return
    with sqlite3.connect(OUTBOX_DB, timeout=10) as db:
        if endpoint in ("/v1/register", "/v1/rtk", "/v1/telemetry"):
            db.execute("DELETE FROM outbox WHERE endpoint = ?", (endpoint,))
        db.execute(
            "INSERT INTO outbox(endpoint, payload, created_at) VALUES (?, ?, ?)",
            (endpoint, json.dumps(payload, separators=(",", ":")), int(time.time())),
        )


def collector_worker():
    global LAST_COLLECTOR_SUCCESS
    while True:
        if mesh.force_offline_until(DATA_DIR):  # PAUL_MESH_V1 test switch: behave as offline
            time.sleep(5)
            continue
        try:
            with sqlite3.connect(OUTBOX_DB, timeout=10) as db:
                row = db.execute(
                    "SELECT id, endpoint, payload FROM outbox ORDER BY id LIMIT 1"
                ).fetchone()
            if row is None:
                time.sleep(2)
                continue
            item_id, endpoint, payload = row
            if endpoint == mesh.CARRY_ENDPOINT:  # PAUL_MESH_V2: carried report -> its real endpoint
                try:
                    endpoint, payload = mesh.carry_to_upload(payload, NODE_ID_FOR_MESH)
                except (ValueError, KeyError, TypeError) as error:
                    with sqlite3.connect(OUTBOX_DB, timeout=10) as db:
                        db.execute("DELETE FROM outbox WHERE id = ?", (item_id,))
                    emit("MESH_CARRY_DROPPED", error=str(error)[:80])
                    continue
            request = urllib.request.Request(
                COLLECTOR_URL + endpoint,
                data=payload.encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=COLLECTOR_TIMEOUT) as response:
                result = json.loads(response.read().decode())
                if response.status not in (200, 201):
                    raise RuntimeError(f"collector status {response.status}")
            with sqlite3.connect(OUTBOX_DB, timeout=10) as db:
                db.execute("DELETE FROM outbox WHERE id = ?", (item_id,))
            emit("COLLECTOR_ACCEPTED", endpoint=endpoint, duplicate=result.get("duplicate", False))
            if endpoint == "/v1/register" and apply_tx_power_limit(result.get("radio")):
                emit("TX_POWER_LIMIT", configured=POWER, limit=TX_POWER_LIMIT, effective=tx_power(),
                     antenna_gain_dbi=(result.get("radio") or {}).get("antenna_gain_dbi"),
                     assumed_gain=bool((result.get("radio") or {}).get("assumed_gain")))
            if endpoint == "/v1/register" and result.get("enrolled"):
                ENROLLED_FILE.write_text(str(int(time.time())))
                os.chmod(ENROLLED_FILE, 0o600)
                try:
                    ENROLLMENT_FILE.unlink()
                except FileNotFoundError:
                    pass

                if result.get("claim_registered"):
                    CLAIM_PROVISIONED_FILE.write_text(str(int(time.time())))
                    os.chmod(CLAIM_PROVISIONED_FILE, 0o600)

                    try:
                        CLAIM_FILE.unlink()
                    except FileNotFoundError:
                        pass
            LAST_COLLECTOR_SUCCESS = int(time.time())
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")
            if 400 <= error.code < 500:
                with sqlite3.connect(OUTBOX_DB, timeout=10) as db:
                    db.execute("DELETE FROM outbox WHERE id = ?", (item_id,))
                emit(
                    "COLLECTOR_REJECTED",
                    endpoint=endpoint,
                    status=error.code,
                    error=detail,
                )
                continue
            emit("COLLECTOR_RETRY", status=error.code, error=detail)
            time.sleep(15)
        except (OSError, ValueError, RuntimeError, urllib.error.URLError) as error:
            emit("COLLECTOR_RETRY", error=str(error))
            time.sleep(15)


def signed_telemetry(private, public_raw, node_id):
    metrics = {"process_uptime_s": int(time.monotonic() - PROCESS_STARTED),
               "last_collector_success_at": LAST_COLLECTOR_SUCCESS,
               "cpu_temperature_c": None, "memory_total_bytes": None,
               "memory_available_bytes": None, "data_disk_total_bytes": None,
               "data_disk_free_bytes": None, "system_uptime_s": None}
    # Read-only, best effort. Missing host sensors are reported as unavailable.
    try:
        for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
            kind = (zone / "type").read_text().lower()
            if not any(label in kind for label in ("cpu", "soc", "package")):
                continue
            value = float((zone / "temp").read_text()) / 1000
            if -40 <= value <= 150:
                metrics["cpu_temperature_c"] = round(value, 1)
                break
    except (OSError, ValueError):
        pass
    try:
        info = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        metrics["memory_total_bytes"] = int(info["MemTotal"].split()[0]) * 1024
        metrics["memory_available_bytes"] = int(info["MemAvailable"].split()[0]) * 1024
    except (OSError, ValueError, KeyError):
        pass
    try:
        usage = shutil.disk_usage(DATA_DIR)
        metrics["data_disk_total_bytes"], metrics["data_disk_free_bytes"] = usage.total, usage.free
        metrics["system_uptime_s"] = int(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        pass
    body = {"schema": "paulnet-telemetry-v1", "kind": "system_status", "version": VERSION,
            "node": node_id, "gateway": GATEWAY_EUI,
            "public_key": base64.b64encode(public_raw).decode(),
            "timestamp": int(time.time()), "nonce": secrets.token_hex(16), "metrics": metrics}
    body["signature"] = base64.b64encode(private.sign(canonical_bytes(body))).decode()
    return body



def signed_tracker_radio_observation(
    private,
    public_raw,
    node_id,
    observed_at,
    raw,
    packet,
):
    if len(raw) < 12:
        raise ValueError("LoRaWAN packet too short")

    mtype = (raw[0] >> 5) & 0x07

    if mtype not in (2, 4):
        raise ValueError("not a LoRaWAN data uplink")

    devaddr = raw[1:5][::-1].hex().upper()
    frame_counter = int.from_bytes(
        raw[6:8],
        "little",
    )

    body = {
        "schema": "paulnet-tracker-radio-v1",
        "kind": "tracker_radio_observation",
        "version": VERSION,
        "node": node_id,
        "gateway": GATEWAY_EUI,
        "public_key": base64.b64encode(
            public_raw
        ).decode(),
        "timestamp": int(time.time()),
        "observed_at": int(observed_at),
        "nonce": secrets.token_hex(16),
        "mtype": mtype,
        "fingerprint": hashlib.sha256(
            raw
        ).hexdigest()[:16],
        "packet_bytes": len(raw),
        "devaddr": devaddr,
        "frame_counter": frame_counter,
        "frequency": float(packet["freq"]),
        "datr": str(packet["datr"]),
        "rssi": float(packet["rssi"]),
        "snr": float(packet["lsnr"]),
    }

    body["signature"] = base64.b64encode(
        private.sign(canonical_bytes(body))
    ).decode()

    return body


def signed_registration(private, public_raw, node_id, invite=None):
    body = {
        "schema": "paulnet-node-v1",
        "kind": "node_registration",
        "version": VERSION,
        "node": node_id,
        "gateway": GATEWAY_EUI,
        "public_key": base64.b64encode(public_raw).decode(),
        "timestamp": int(time.time()),
        "nonce": secrets.token_hex(8),
    }
    # The collector accepts EU868/US915/AU915 only. While a fresh install is
    # still detecting its band the field is omitted; the node re-registers
    # as soon as REGION_DETECTED fires.
    if RADIO is not None and RADIO.name in messenger.REGION_SUPPORTED:
        body["region"] = RADIO.name
    invite = enrollment_token() if invite is None else str(invite).strip()
    if invite:
        body["invite"] = invite

    claim = claim_token()
    if claim:
        body["claim"] = claim

    # Every Node exposes its local Messenger through its normal LAN address.
    # A supported Pi may additionally offer its own optional Wi-Fi AP.
    body["messenger"] = messenger_web.registration_info(DATA_DIR)

    body["signature"] = base64.b64encode(private.sign(canonical_bytes(body))).decode()
    return body


def region_name():
    return (RADIO.name if RADIO is not None else None) or "AUTO"


def radio_label():
    """Short channel text for the local messenger page (EU868 unchanged)."""
    if RADIO is None or RADIO.name is None:
        return "?"
    channels = RADIO.channels()
    if RADIO.name == "EU868":
        return channels[0]
    return "%s · %s–%s" % (RADIO.name, min(channels), max(channels))


def signed_beacon_report(private, public_raw, node_id, beacon_info, frequency=None, datr=None):
    body = {
        "schema": "paulnet-beacon-tx-v1",
        "kind": "beacon_tx",
        "version": VERSION,
        "node": node_id,
        "gateway": GATEWAY_EUI,
        "public_key": base64.b64encode(public_raw).decode(),
        "timestamp": int(time.time()),
        "sequence": int(beacon_info["sequence"]),
        "beacon_timestamp": int(beacon_info["timestamp"]),
        "nonce": beacon_info["nonce"],
        "frequency": FREQUENCY if frequency is None else frequency,
        "datr": BEACON_DATARATE if datr is None else datr,
        "power": tx_power(),
    }
    body["signature"] = base64.b64encode(
        private.sign(canonical_bytes(body))
    ).decode()
    return body


def signed_rtk_report(private, public_raw, node_id, rtk):
    body = {
        "schema": "paulnet-rtk-v1",
        "kind": "rtk_status",
        "version": VERSION,
        "node": node_id,
        "gateway": GATEWAY_EUI,
        "public_key": base64.b64encode(public_raw).decode(),
        "timestamp": int(time.time()),
        "observed_at": int(rtk["observed_at"]),
        "nonce": secrets.token_hex(8),
        "fix_quality": int(rtk["fix_quality"]),
        "satellites": int(rtk["satellites"]),
        "latitude": float(rtk["latitude"]),
        "longitude": float(rtk["longitude"]),
        "altitude_m": float(rtk["altitude_m"]),
        "hdop": rtk.get("hdop"),
        "rtk_age": rtk.get("rtk_age"),
        "reference_station": rtk.get("reference_station"),
        "gps_satellites": int(rtk.get("gps_satellites", 0)),
        "glonass_satellites": int(rtk.get("glonass_satellites", 0)),
        "galileo_satellites": int(rtk.get("galileo_satellites", 0)),
        "beidou_satellites": int(rtk.get("beidou_satellites", 0)),
        "sky_view": rtk.get("sky_view", []),
    }
    body["signature"] = base64.b64encode(private.sign(canonical_bytes(body))).decode()
    return body


def signed_witness(private, public_raw, node_id, beacon, packet, raw_beacon):
    report = {
        "receiver_node": node_id,
        "receiver_gateway": GATEWAY_EUI,
        "sender_node": beacon["node_id"],
        "sender_gateway": beacon["gateway_eui"],
        "sequence": beacon["sequence"],
        "beacon_timestamp": beacon["timestamp"],
        "nonce": beacon["nonce"],
        "received_at": int(time.time()),
        "frequency": packet.get("freq"),
        "datr": packet.get("datr"),
        "rssi": packet.get("rssi"),
        "snr": packet.get("lsnr"),
        "frequency_offset": packet.get("foff"),
        "beacon": base64.b64encode(raw_beacon).decode(),
    }
    report["receiver_public_key"] = base64.b64encode(public_raw).decode()
    report["witness_signature"] = base64.b64encode(
        private.sign(canonical_bytes(witness_signing_body(report)))
    ).decode()
    return report



def beacon_slot(node_id, period_start):
    """
    Calculate the transmit slot for one PAUL node for one interval.

    The slot changes every interval but is deterministic for the
    same node + interval. This prevents two nodes from remaining
    permanently synchronized after installation or reboot.

    Legacy SLOT environment variables are intentionally ignored.
    PAUL_FIXED_SLOT exists only as an explicit diagnostic override.
    """

    if PAUL_FIXED_SLOT:
        try:
            fixed = int(PAUL_FIXED_SLOT)
        except ValueError:
            fixed = -1

        if 0 <= fixed < INTERVAL:
            return fixed

    period_index = int(period_start // INTERVAL)

    seed = (
        str(node_id)
        + ":"
        + str(period_index)
    ).encode()

    digest = hashlib.sha256(seed).digest()

    # Keep a small margin away from exact interval boundaries.
    margin = 15
    usable = INTERVAL - (margin * 2)

    value = int.from_bytes(
        digest[:8],
        "big",
    )

    return margin + (value % usable)


def next_beacon_time(now, node_id):
    """
    Return the next deterministic rolling beacon time.
    """

    period_start = int(now // INTERVAL) * INTERVAL

    for offset in range(3):
        start = period_start + (offset * INTERVAL)

        candidate = (
            start
            + beacon_slot(node_id, start)
        )

        if candidate > now + 1:
            return candidate

    # Defensive fallback; normally unreachable.
    start = period_start + INTERVAL

    return (
        start
        + beacon_slot(node_id, start)
    )


def main():
    global RADIO
    private, public_raw, node_id = load_or_create_key()
    RADIO = messenger.RadioRegion(DATA_DIR, emit=emit)
    load_tx_power_limit()
    (DATA_DIR / "node-id").write_text(node_id)
    (DATA_DIR / "version").write_text(VERSION)
    sequence = read_sequence()
    replay = load_replay_state()
    gateway_address = None
    protocol_version = 2
    pending_tx_tokens = {}
    messenger.migrate(DATA_DIR)
    radio_gate = messenger.RadioGate(DATA_DIR)
    radio_state = {"last_pull": 0, "loop_at": time.time(), "next_at": radio_gate.next_at,
                   "frequency": radio_label(), "datr": DATARATE,
                   "beacon_datr": RADIO.beacon_datr(BEACON_SIZE, messenger.lora_airtime), "power": tx_power(),
                   "version": VERSION, "ack_pending": False, "region": RADIO.status()}

    # The local web UI is available on the device's ordinary LAN address on
    # every platform. Pi-only Wi-Fi control is a separate optional feature.
    # Fail before NODE_STARTED when the port cannot bind, so the in-place
    # updater detects an unhealthy candidate and restores the previous code.
    messenger_web.start(DATA_DIR, node_id, radio_state)
    emit("LOCAL_MESSENGER_WEB_STARTED", node=node_id)

    # A Pi host may complete its Wi-Fi capability setup after the Node starts.
    local_wifi_started = threading.Event()
    def local_wifi_watcher():
        while not local_wifi_started.is_set():
            if wifi_messenger_enabled(DATA_DIR):
                import wifi_agent
                wifi_agent.start(DATA_DIR, COLLECTOR_URL, private, public_raw, node_id, GATEWAY_EUI, emit)
                local_wifi_started.set()
                emit("LOCAL_WIFI_FEATURES_STARTED", node=node_id)
                return
            time.sleep(10)
    threading.Thread(target=local_wifi_watcher, daemon=True, name="paul-local-wifi-gate").start()
    rtk_reader = RtkReader(RTK_HOST, RTK_PORT)
    rtk_reader.start()

    init_outbox()
    global NODE_ID_FOR_MESH
    NODE_ID_FOR_MESH = node_id
    mesh_state = mesh.Mesh(DATA_DIR, OUTBOX_DB, node_id, emit=emit)  # PAUL_MESH_V1
    if COLLECTOR_URL:
        threading.Thread(target=collector_worker, daemon=True).start()
    queue_for_collector("/v1/register", signed_registration(private, public_raw, node_id))
    next_heartbeat = time.time() + HEARTBEAT_INTERVAL
    next_rtk_report = time.time()
    next_telemetry = time.time()

    now = time.time()
    next_tx = next_beacon_time(now, node_id)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", int(os.getenv("PAUL_UDP_PORT", "1701"))))
    sock.settimeout(0.25)

    emit(
        "NODE_STARTED",
        version=VERSION,
        node=node_id,
        gateway=GATEWAY_EUI,
        region=region_name(),
        region_status=RADIO.status(),
        public_key=base64.b64encode(public_raw).decode(),
        signed=True,
        beacon_bytes=BEACON_SIZE,
        frequency=FREQUENCY if RADIO.name == "EU868" else list(RADIO.channels()),
        datr=radio_state["beacon_datr"],
        beacon_datr=radio_state["beacon_datr"],
        power=tx_power(),
        interval=INTERVAL,
        collector=COLLECTOR_URL or None,
        rtk_source=f"{RTK_HOST}:{RTK_PORT}",
        rtk_report_interval=RTK_REPORT_INTERVAL,
        next_beacon=utc_iso(next_tx),
        slot_mode=(
            "fixed"
            if PAUL_FIXED_SLOT
            else "rolling_hash"
        ),
        beacon_slot=int(next_tx % INTERVAL),
        mesh=mesh.MESH_VERSION,
    )

    while True:
        try:
            data, address = sock.recvfrom(65535)
            if len(data) < 4:
                continue
            protocol_version = data[0]
            token = data[1:3]
            packet_type = data[3]
            gateway = data[4:12].hex() if len(data) >= 12 else "unknown"

            if packet_type == 0:
                sock.sendto(bytes([protocol_version]) + token + bytes([1]), address)
                try:
                    message = json.loads(data[12:].decode())
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                for packet in message.get("rxpk", []):
                    region_before = RADIO.name
                    if RADIO.observe(packet.get("freq")):
                        radio_state.update(region=RADIO.status(), frequency=radio_label(),
                                           beacon_datr=RADIO.beacon_datr(BEACON_SIZE, messenger.lora_airtime))
                        if RADIO.name != region_before:
                            queue_for_collector("/v1/register",
                                                signed_registration(private, public_raw, node_id))
                    try:
                        raw = base64.b64decode(packet.get("data", ""), validate=True)
                    except Exception:
                        continue
                    if mesh.is_frame(raw):  # PAUL_MESH_V1
                        try:
                            mframe = mesh.parse(raw)
                            if mframe["kind"] == "report":  # PAUL_MESH_V23 receive report
                                m_updated = mesh_state.on_report(mframe, snr=packet.get("lsnr"))
                                emit("MESH_RX", kind="report", relay=mframe.get("relay"), sender=mframe.get("sender"),
                                     reported_snr=mframe.get("snr"), dist=mframe.get("dist"),
                                     entries=[{"item": e["item"].hex(), "total": e["total"], "have": sorted(e["have"])}
                                              for e in mframe.get("entries", [])],
                                     updated=m_updated, compact=mframe.get("compact"), rssi=packet.get("rssi"), snr=packet.get("lsnr"),
                                     datr=packet.get("datr"), freq=packet.get("freq"))
                            elif mframe["kind"] == "ack":
                                mesh_state.on_ack(mframe, snr=packet.get("lsnr"))
                                emit("MESH_RX", kind="ack", relay=mframe.get("relay"), origin=mframe.get("origin"),  # PAUL_MESH_RXLOG_V1
                                     items=len(mframe.get("items", [])), dist=mframe.get("dist"),
                                     rssi=packet.get("rssi"), snr=packet.get("lsnr"), datr=packet.get("datr"), freq=packet.get("freq"))
                            else:
                                done = mesh_state.on_data(mframe, LAST_COLLECTOR_SUCCESS, snr=packet.get("lsnr"))
                                emit("MESH_RX", kind="data", origin=mframe.get("origin"), sender=mframe.get("sender"),  # PAUL_MESH_RXLOG_V1
                                     index=mframe.get("index"), total=mframe.get("total"), dist=mframe.get("dist"),
                                     result=(done[0] if done else mesh_state.last_rx_note or "none"),
                                     rssi=packet.get("rssi"), snr=packet.get("lsnr"), datr=packet.get("datr"), freq=packet.get("freq"))
                                if done and done[0] == "upload":
                                    _, m_endpoint, m_payload, m_origin, m_hops = done
                                    queue_for_collector(m_endpoint + "?relay=" + node_id + "&hops=" + str(m_hops),
                                                        m_payload)
                                    emit("MESH_RELAYED", origin=m_origin, endpoint=m_endpoint, hops=m_hops,
                                         rssi=packet.get("rssi"), snr=packet.get("lsnr"))
                                elif done and done[0] == "carry":  # PAUL_MESH_V2: offline too -> take custody
                                    _, m_record, m_origin, m_hops = done
                                    queue_for_collector(mesh.CARRY_ENDPOINT, m_record)
                                    emit("MESH_CARRIED", origin=m_origin, hops=m_hops,
                                         rssi=packet.get("rssi"), snr=packet.get("lsnr"))
                        except ValueError as error:
                            emit("MESH_REJECTED", reason=str(error)[:80])
                        continue
                    if messenger.is_frame(raw):
                        try:
                            msg = messenger.parse_frame(raw, node_id, DATA_DIR, private=private)
                            if msg is not None:
                                messenger.remember_peer_key(DATA_DIR, msg["sender"], msg["public_raw"])
                                if not msg.get("encrypted"):
                                    # Signed legacy frame: keep the learned key, drop the plaintext.
                                    emit("MESSAGE_REJECTED", reason="PlaintextFrame", sender=msg["sender"], wire=msg.get("wire"))
                                    continue
                                outcome = messenger.receive(DATA_DIR, msg)
                                emit("MESSAGE_RX", sender=msg["sender"], message_id=msg["id"], outcome=outcome, wire=msg.get("wire"))
                                if msg["kind"] == 1:
                                    messenger.ack_queue(DATA_DIR, msg["id"], msg["sender"], msg.get("wire", "full"))
                        except (ValueError, UnicodeDecodeError, InvalidSignature) as error:
                            emit("MESSAGE_REJECTED", reason=type(error).__name__)
                        continue
                    is_paul_packet = (
                        raw.startswith(MAGIC)
                        or raw.startswith(LEGACY_MAGIC)
                    )

                    if not is_paul_packet:
                        mtype = (
                            (raw[0] >> 5) & 0x07
                            if raw
                            else -1
                        )

                        if mtype in (2, 4) and len(raw) >= 12:
                            devaddr = (
                                raw[1:5][::-1]
                                .hex()
                                .upper()
                            )

                            if (
                                TRACKER_RADIO_DISCOVERY
                                or devaddr in TRACKER_DEVADDRS
                            ):
                                try:
                                    observation = (
                                        signed_tracker_radio_observation(
                                            private,
                                            public_raw,
                                            node_id,
                                            int(time.time()),
                                            raw,
                                            packet,
                                        )
                                    )
                                except (
                                    KeyError,
                                    TypeError,
                                    ValueError,
                                ) as error:
                                    emit(
                                        "TRACKER_RADIO_SKIPPED",
                                        devaddr=devaddr,
                                        error=str(error),
                                    )
                                else:
                                    queue_for_collector(
                                        "/v1/tracker-radio",
                                        observation,
                                    )
                                    emit(
                                        "TRACKER_RADIO_QUEUED",
                                        devaddr=devaddr,
                                        fingerprint=observation[
                                            "fingerprint"
                                        ],
                                        rssi=observation["rssi"],
                                        snr=observation["snr"],
                                        datr=observation["datr"],
                                    )

                        continue

                    try:
                        beacon = verify_beacon(raw)
                        messenger.remember_peer_key(DATA_DIR, beacon["node_id"], beacon["public_raw"])
                    except InvalidSignature:
                        emit("INVALID_SIGNATURE", gateway=GATEWAY_EUI)
                        continue
                    except ValueError as error:
                        emit("INVALID_BEACON", gateway=GATEWAY_EUI, error=str(error))
                        continue

                    if abs(int(time.time()) - beacon["timestamp"]) > MAX_CLOCK_SKEW:
                        emit("TIME_REJECTED", sender=beacon["node_id"], sequence=beacon["sequence"])
                        continue
                    if beacon["node_id"] == node_id:
                        emit(
                            "SELF_RX",
                            node=node_id,
                            sequence=beacon["sequence"],
                            verified=True,
                            rssi=packet.get("rssi"),
                            snr=packet.get("lsnr"),
                        )
                        continue
                    if beacon["sequence"] <= int(replay.get(beacon["node_id"], 0)):
                        emit("REPLAY_REJECTED", sender=beacon["node_id"], sequence=beacon["sequence"])
                        continue

                    replay[beacon["node_id"]] = beacon["sequence"]
                    save_replay_state(replay)
                    report = signed_witness(private, public_raw, node_id, beacon, packet, raw)
                    emit("WITNESS", verified=True, **report)
                    queue_for_collector("/v1/witnesses", report)

            elif packet_type == 2:
                sock.sendto(bytes([protocol_version]) + token + bytes([4]), address)
                if gateway_address is None:
                    emit("GATEWAY_CONNECTED", node=node_id, gateway=gateway)
                gateway_address = address
                radio_state["last_pull"] = time.time()

            elif packet_type == 5 and token in pending_tx_tokens:
                tx_info = pending_tx_tokens.pop(token, None)
                result_text = data[12:].decode(errors="replace")
                emit("TX_ACK", node=node_id, result=result_text)
                if isinstance(tx_info, tuple):
                    _, message_id, peer, kind, wire, datr = tx_info
                    try:
                        result = json.loads(result_text) if result_text.strip() else {"txpk_ack": {"error": "NONE"}}
                        error = result.get("txpk_ack", {}).get("error", "UNKNOWN")
                    except (ValueError, AttributeError):
                        error = "INVALID_TX_ACK"
                    if kind == "message":
                        messenger.tx_result(DATA_DIR, message_id, peer, str(error))
                    elif kind == "ack":
                        messenger.ack_status(DATA_DIR, message_id, peer, "accepted" if error == "NONE" else "failed")
                    elif kind in ("mesh_data", "mesh_ack", "mesh_hello", "mesh_report") and error != "NONE":
                        emit("MESH_TX_REJECTED", kind=kind, error=str(error))

        except socket.timeout:
            pass

        now = time.time()
        pending_tx_tokens = {
            token: created for token, created in pending_tx_tokens.items()
            if now - (created[0] if isinstance(created, tuple) else created) < 120
        }
        radio_state.update(loop_at=now, next_at=radio_gate.next_at,
                           ack_pending=bool(messenger.ack_pending(DATA_DIR)))
        messenger.auto_retry(DATA_DIR)
        if gateway_address is not None and now - radio_state["last_pull"] < 120 and RADIO.tx_allowed:
            frame = None
            tx_id = None
            tx_peer = None
            wire = None
            datr = None
            kind = None
            ready = now
            beacon_datr = RADIO.beacon_datr(BEACON_SIZE, messenger.lora_airtime)
            beacon_reserve = messenger.lora_airtime(BEACON_SIZE, beacon_datr)
            tx_freq = RADIO.next_frequency()
            ack_item = messenger.ack_pending(DATA_DIR)
            if ack_item:
                tx_id, tx_peer, ack_wire, _ack_count = ack_item
                try:
                    candidate, candidate_wire, candidate_datr = messenger.build_ack_frame(
                        private, public_raw, tx_peer, tx_id, ack_wire, int(now), DATA_DIR
                    )
                except LookupError:
                    messenger.ack_status(DATA_DIR, tx_id, tx_peer, "no_key")
                    candidate = None
                if candidate is not None:
                    candidate_datr = RADIO.fit_datr(len(candidate), candidate_datr, messenger.lora_airtime)
                    ready, _, _ = radio_gate.ready_at(
                        len(candidate), candidate_datr, tx_freq, reserve_airtime=beacon_reserve, now=now
                    )
                if candidate is not None and ready <= now + 0.001:
                    frame, wire, datr = candidate, candidate_wire, candidate_datr
                    messenger.ack_submitted(DATA_DIR, tx_id, tx_peer)
                    kind = "ack"
            else:
                item = messenger.pending(DATA_DIR)
                if item:
                    tx_id, tx_peer, _, msg_text, _, _ = item
                    attempt = messenger.peek_attempt(DATA_DIR, tx_id, tx_peer)
                    if attempt:
                        candidate, candidate_wire, candidate_datr = messenger.build_message_frame(
                            private, public_raw, tx_peer, tx_id, msg_text, attempt, int(now), DATA_DIR
                        )
                        candidate_datr = RADIO.fit_datr(len(candidate), candidate_datr, messenger.lora_airtime)
                        ready, _, _ = radio_gate.ready_at(
                            len(candidate), candidate_datr, tx_freq, reserve_airtime=beacon_reserve, now=now
                        )
                        if ready <= now + 0.001:
                            claimed = messenger.begin_attempt(DATA_DIR, tx_id, tx_peer)
                            if claimed == attempt:
                                frame, wire, datr = candidate, candidate_wire, candidate_datr
                                messenger.record_transport(DATA_DIR, tx_id, tx_peer, wire, datr)
                                kind = "message"
            mesh_ack_origin = None
            if frame is None and mesh_state.tx_ready(now):  # PAUL_MESH_V1: relay ACKs first, then own reports while offline
                mesh_kind, mesh_frame = None, None
                ack_item = mesh_state.next_ack_frame(LAST_COLLECTOR_SUCCESS, now)
                report_item = None if ack_item else mesh_state.next_report_frame(LAST_COLLECTOR_SUCCESS, now)
                hello = None if ack_item or report_item else mesh_state.next_hello_frame(LAST_COLLECTOR_SUCCESS, now)
                if ack_item:
                    mesh_kind, (mesh_ack_origin, mesh_frame) = "mesh_ack", ack_item
                elif report_item:
                    mesh_kind, (mesh_ack_origin, mesh_frame) = "mesh_report", report_item
                elif hello:
                    mesh_kind, mesh_frame = "mesh_hello", hello
                else:
                    mesh_frame = mesh_state.next_origin_frame(LAST_COLLECTOR_SUCCESS, now)
                    mesh_kind = "mesh_data" if mesh_frame else None
                if mesh_frame:
                    wanted = mesh.ACK_DATARATE if mesh_kind in ("mesh_ack", "mesh_hello", "mesh_report") else mesh_state.current_datr()
                    try:
                        mesh_datr = RADIO.fit_datr(len(mesh_frame), wanted, messenger.lora_airtime)
                    except ValueError:
                        mesh_datr = None
                    if mesh_datr and mesh_state.airtime_left(now) >= messenger.lora_airtime(len(mesh_frame), mesh_datr):
                        ready, _, _ = radio_gate.ready_at(
                            len(mesh_frame), mesh_datr, tx_freq, reserve_airtime=beacon_reserve, now=now
                        )
                        if ready <= now + 0.001:
                            frame, wire, datr, kind = mesh_frame, "mesh", mesh_datr, mesh_kind
                            tx_peer = mesh_ack_origin
            radio_state["mesh"] = mesh_state.status()
            radio_state["next_at"] = max(now, ready)
            if frame is not None:
                tx = {"txpk": {"imme": True, "freq": tx_freq, "rfch": 0,
                       "powe": tx_power(), "modu": "LORA", "datr": datr,
                       "codr": "4/5", "ipol": False, "prea": 8,
                       "size": len(frame), "data": base64.b64encode(frame).decode()}}
                tx_token = secrets.token_bytes(2)
                while tx_token in pending_tx_tokens:
                    tx_token = secrets.token_bytes(2)
                airtime, duty = radio_gate.reserve(
                    len(frame), datr, tx_freq, reserve_airtime=beacon_reserve, now=now
                )
                try:
                    sock.sendto(bytes([protocol_version]) + tx_token + bytes([3])
                                + json.dumps(tx, separators=(",", ":")).encode(), gateway_address)
                    pending_tx_tokens[tx_token] = (now, tx_id, tx_peer, kind, wire, datr)
                    if kind in ("mesh_data", "mesh_ack", "mesh_hello", "mesh_report"):
                        mesh_state.spent(now, airtime)
                        if kind == "mesh_data":
                            mesh_state.origin_frame_sent(now)
                        elif kind == "mesh_hello":
                            mesh_state.hello_sent(now)
                        elif kind == "mesh_report":
                            mesh_state.report_sent(tx_peer)
                        else:
                            mesh_state.ack_sent(tx_peer, frame)
                        emit("MESH_TX", kind=kind, datr=datr, frequency=tx_freq, bytes=len(frame),
                             airtime_ms=round(airtime * 1000, 1), duty_cycle=duty)
                    else:
                        emit("MESSAGE_TX", peer=tx_peer, message_id=tx_id, kind=kind,
                             wire=wire, datr=datr, frequency=tx_freq, bytes=len(frame), airtime_ms=round(airtime * 1000, 1),
                             duty_cycle=duty)
                except OSError as exc:
                    if kind in ("mesh_data", "mesh_ack", "mesh_hello", "mesh_report"):
                        pass
                    elif kind == "message":
                        messenger.tx_result(DATA_DIR, tx_id, tx_peer, "UDP_SEND_FAILED")
                    else:
                        messenger.ack_status(DATA_DIR, tx_id, tx_peer, "failed")
                    emit("MESSAGE_TX_FAILED", message_id=tx_id, reason=str(exc))
                radio_state.update(next_at=radio_gate.next_at, datr=datr,
                                   message_wire=wire, message_duty_cycle=duty)



        if now >= next_heartbeat:
            queue_for_collector("/v1/register", signed_registration(private, public_raw, node_id))
            next_heartbeat = now + HEARTBEAT_INTERVAL

        if now >= next_rtk_report:
            rtk = rtk_reader.snapshot()
            if rtk.get("valid"):
                queue_for_collector(
                    "/v1/rtk", signed_rtk_report(private, public_raw, node_id, rtk)
                )
                emit(
                    "RTK_REPORT_QUEUED",
                    node=node_id,
                    fix_quality=rtk["fix_quality"],
                    satellites=rtk["satellites"],
                    gps=rtk.get("gps_satellites", 0),
                    glonass=rtk.get("glonass_satellites", 0),
                    galileo=rtk.get("galileo_satellites", 0),
                    beidou=rtk.get("beidou_satellites", 0),
                    hdop=rtk.get("hdop"),
                    rtk_age=rtk.get("rtk_age"),
                    observed_at=int(rtk["observed_at"]),
                )
            next_rtk_report = now + RTK_REPORT_INTERVAL

        if now >= next_telemetry:
            queue_for_collector("/v1/telemetry", signed_telemetry(private, public_raw, node_id))
            next_telemetry = now + TELEMETRY_INTERVAL

        if (gateway_address is not None and now >= next_tx and now - radio_state["last_pull"] < 120
                and RADIO.tx_allowed):
            rtk = rtk_reader.snapshot()
            beacon = make_beacon(private, public_raw, GATEWAY_EUI, sequence, int(now))
            beacon_datr = RADIO.beacon_datr(len(beacon), messenger.lora_airtime)
            beacon_freq = RADIO.next_frequency()
            beacon_ready, _, _ = radio_gate.ready_at(
                len(beacon), beacon_datr, beacon_freq, now=now
            )
            if beacon_ready > now + 0.001:
                radio_state["next_at"] = beacon_ready
                continue
            tx = {"txpk": {
                "imme": True,
                "freq": beacon_freq,
                "rfch": 0,
                "powe": tx_power(),
                "modu": "LORA",
                "datr": beacon_datr,
                "codr": "4/5",
                "ipol": False,
                "prea": 8,
                "size": len(beacon),
                "data": base64.b64encode(beacon).decode(),
            }}
            tx_token = secrets.token_bytes(2)
            response = (
                bytes([protocol_version])
                + tx_token
                + bytes([3])
                + json.dumps(tx, separators=(",", ":")).encode()
            )
            pending_tx_tokens[tx_token] = now
            beacon_airtime, beacon_duty = radio_gate.reserve(len(beacon), beacon_datr, beacon_freq, now=now)
            radio_state["next_at"] = radio_gate.next_at
            sock.sendto(response, gateway_address)

            beacon_info = verify_beacon(beacon)
            queue_for_collector(
                "/v1/beacons",
                signed_beacon_report(private, public_raw, node_id, beacon_info, beacon_freq, beacon_datr),
            )

            emit(
                "BEACON_SENT",
                node=node_id,
                gateway=GATEWAY_EUI,
                sequence=sequence,
                signed=True,
                beacon_bytes=len(beacon),
                region=RADIO.name,
                frequency=beacon_freq,
                datr=beacon_datr,
                power=tx_power(),
                airtime_ms=round(beacon_airtime * 1000, 1),
                duty_cycle=beacon_duty,
                rtk={"valid": False, "privacy": "collector_only"},
            )
            sequence += 1
            save_sequence(sequence)
            next_tx = next_beacon_time(
                time.time() + 1,
                node_id,
            )


if __name__ == "__main__":
    main()
