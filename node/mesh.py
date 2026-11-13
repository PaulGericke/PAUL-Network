"""PAUL mesh relay v2 (MESH_VERSION "mesh-v2"): multi-hop store-and-forward.

A node that cannot reach the collector hands its signed reports to a
neighbouring PAUL node over LoRa. The neighbour
  * uploads them unchanged when it is online itself, or
  * takes custody when it is offline too and passes them on later
    (at most MAX_HOPS radio hops; when its own Internet returns it uploads them).
Every hop acknowledges over LoRa; the sender deletes the report only then.
Reports keep the origin's Ed25519 signature, so no relay can forge or alter
them - the collector verifies them as if the origin had sent them.

Routing: every node knows its distance to the Internet in hops (online = 0,
otherwise 1 + the smallest distance announced in ACKs it heard during the
last hour, 255 = unknown). DATA and ACK frames carry the sender's distance.
A node takes custody only when it is strictly closer to the Internet than the
sender, so reports always flow towards an online node, never sideways.
HELLO = an ACK frame without items: every node that knows a route (distance
< 255) announces it every HELLO_INTERVAL, so neighbours learn routes without a
successful transfer first. A node without a known route sends reports only as
a rare probe (every PROBE_INTERVAL) instead of wasting airtime.

A node never takes custody from the neighbour its own route goes through
(its "parent"), so two nodes cannot pass a report back and forth.

Frames start with 0xE1 (LoRaWAN MType 7 = proprietary):
  DATA  E1 'P' 'R' 05 | origin(8) | sender(8) | item(4) | hops(1) | dist(1) | index(1) | total(1) | chunk
  DATA  E1 'P' 'R' 03 | origin(8) | item(4) | hops(1) | dist(1) | index(1) | total(1) | chunk  (v2.0)
  DATA  E1 'P' 'R' 01 | origin(8) | item(4) | index(1) | total(1) | chunk          (v1)
  ACK   E1 'P' 'R' 04 | relay(8)  | origin(8) | dist(1) | count(1) | item(4) * count
  ACK   E1 'P' 'R' 02 | relay(8)  | origin(8) | count(1) | item(4) * count          (v1)
  RPT   E1 'P' 'R' 06 | reporter(8) | sender(8) | dist(1) | snr(1, int8 half-dB) | n(1)
                      | (item(4) | total(1) | have-bitmap(2, LE)) * n                 (v2.3)

item = first 4 bytes of SHA-256 over the blob; blob = zlib(JSON {"e","p"}).

v2.3 (PAUL_MESH_V23) - link adaptation for weak links:
  * RPT = receive report: a receiver that holds an incomplete item tells the
    sender (after REPORT_QUIET s without further fragments) which fragments it
    has and at what SNR it hears the sender. The sender then resends ONLY the
    missing fragments, right away instead of after RETRY_AFTER.
  * Start datarate per link: lowest SF whose demodulation floor + SNR_MARGIN
    lies below the SNR the parent reported for us (fallback: SNR we hear the
    parent at). A round that loses more than half its frames, or a timeout
    without any report, moves one SF slower.
  * Fragment size depends on the SF the item was first planned with (CHUNK_BY_SF);
    an item keeps its fragmentation so receive reports stay valid. Receivers
    reassemble per (origin, item, total) and keep partials for REASSEMBLY_TTL.
  * Retries go before new items of the same priority; while offline only the
    newest telemetry report is offered (older ones wait for the Internet).
Old nodes ignore RPT frames (unknown kind); DATA/ACK formats are unchanged.
"""
import base64
import contextlib
import hashlib
import json
import os
import sqlite3
import time
import zlib
from pathlib import Path

MESH_VERSION = "mesh-v2.6"  # v2.6 = v2.5 + neighbours below MIN_ROUTE_SNR are ignored for routing (PAUL_MESH_V26)
# v2.5 = v2.4 + reported link SNR kept 6 h, parent ties prefer capable neighbours (PAUL_MESH_V25)
# v2.4 = v2.3 + dictionary blobs, 8 dB margin, 30 s/h, telemetry every 30 min
MAGIC = b"\xe1PR"
KIND_DATA_V1 = 1
KIND_ACK = 2
KIND_DATA = 3
KIND_ACK_V2 = 4
KIND_DATA_V21 = 5
KIND_REPORT = 6
KIND_REPORT_V24 = 7          # same layout as 6; sender learns: reporter decodes dictionary blobs
REPORT_HEADER = 3 + 1 + 8 + 8 + 1 + 1 + 1
REPORT_ENTRY = 4 + 1 + 2
MAX_REPORT_ITEMS = 6
SNR_UNKNOWN = 127
# LoRa demodulation floor (dB SNR) per spreading factor
SNR_FLOOR = {7: -7.5, 8: -10.0, 9: -12.5, 10: -15.0, 11: -17.5, 12: -20.0}
SNR_MARGIN = float(os.environ.get("MESH_SNR_MARGIN", "8"))
CHUNK_BY_SF = {7: 180, 8: 180, 9: 180, 10: 150, 11: 125, 12: 80}
REPORT_QUIET = float(os.environ.get("MESH_REPORT_QUIET", "15"))
LINK_TTL = 3600
MIN_ROUTE_SNR = float(os.environ.get("MESH_MIN_ROUTE_SNR", "-15"))  # PAUL_MESH_V26: SF11 limit -17.5 dB + margin
REPORTED_LINK_TTL = 6 * 3600  # PAUL_MESH_V25: reports are rare (airtime), keep what the neighbour told us longer
MAX_PARTS = 64
UNKNOWN_DIST = 255
DIST_TTL = 3600
DATA_HEADER = 3 + 1 + 8 + 4 + 1 + 1 + 1 + 1
DATA_HEADER_V21 = DATA_HEADER + 8
DATA_HEADER_V1 = 3 + 1 + 8 + 4 + 1 + 1
ACK_HEADER = 3 + 1 + 8 + 8 + 1
ACK_HEADER_V2 = ACK_HEADER + 1
CHUNK = int(os.environ.get("MESH_CHUNK", "180"))
MAX_FRAGMENTS = 12
MAX_BLOB = CHUNK * MAX_FRAGMENTS
MAX_ACK_IDS = 12
MAX_HOPS = int(os.environ.get("MESH_MAX_HOPS", "3"))
MAX_CARRY = int(os.environ.get("MESH_MAX_CARRY", "300"))
DATA_DATARATES = tuple(x.strip() for x in os.environ.get(
    "MESH_DATARATES", "SF9BW125,SF10BW125,SF11BW125").split(",") if x.strip()) or ("SF9BW125",)
DATARATE = DATA_DATARATES[0]
ACK_DATARATE = os.environ.get("MESH_ACK_DATARATE", "SF11BW125")
OFFLINE_AFTER = int(os.environ.get("MESH_OFFLINE_AFTER", "600"))
ONLINE_WITHIN = int(os.environ.get("MESH_ONLINE_WITHIN", "300"))
RETRY_AFTER = int(os.environ.get("MESH_RETRY_AFTER", "600"))
MAX_ATTEMPTS = int(os.environ.get("MESH_MAX_ATTEMPTS", "8"))
AIRTIME_PER_HOUR = float(os.environ.get("MESH_AIRTIME_PER_HOUR", "30"))   # s; EU868 1 % = 36 s/h
FRAME_GAP = float(os.environ.get("MESH_FRAME_GAP", "1.0"))
REASSEMBLY_TTL = 3 * 3600
DONE_TTL = 6 * 3600
HELLO_INTERVAL = int(os.environ.get("MESH_HELLO_INTERVAL", "900"))
PROBE_INTERVAL = int(os.environ.get("MESH_PROBE_INTERVAL", "1800"))
TELEMETRY_MESH_INTERVAL = int(os.environ.get("MESH_TELEMETRY_INTERVAL", "1800"))
CAPS_TTL = 24 * 3600
FORCE_OFFLINE_FILE = "mesh-force-offline"
CARRY_ENDPOINT = "/mesh/carry"
# Priority: own beacon reports keep the node "online" for the network.
ENDPOINTS = {"/v1/beacons": 0, "/v1/telemetry": 1, CARRY_ENDPOINT: 1, "/v1/witnesses": 2}
REPORT_ENDPOINTS = ("/v1/beacons", "/v1/telemetry", "/v1/witnesses")
ORIGIN_FIELD = {"/v1/beacons": "node", "/v1/telemetry": "node", "/v1/witnesses": "receiver_node"}


def _db(path):
    """sqlite connection that is committed AND closed (the Pi runs this for weeks)."""
    @contextlib.contextmanager
    def manager():
        connection = sqlite3.connect(path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()
    return manager()


def is_frame(raw):
    return len(raw) >= 4 and raw[:3] == MAGIC and raw[3] in (KIND_DATA_V1, KIND_ACK, KIND_DATA, KIND_ACK_V2,
                                                             KIND_DATA_V21, KIND_REPORT, KIND_REPORT_V24)


def sf_of(datr):
    try:
        return int(str(datr).upper().split("SF")[1].split("BW")[0])
    except (IndexError, ValueError):
        return 9


def chunk_for(datr):
    return CHUNK_BY_SF.get(sf_of(datr), CHUNK)


def link_index(snr, datarates=None):
    """Index into datarates of the fastest SF that still has SNR_MARGIN dB headroom at this SNR."""
    datarates = datarates or DATA_DATARATES
    if snr is None:
        return len(datarates) - 1        # PAUL_MESH_V24: unknown link -> most robust SF
    for i, datr in enumerate(datarates):
        if snr - SNR_MARGIN >= SNR_FLOOR.get(sf_of(datr), -12.5):
            return i
    return len(datarates) - 1


def _snr_byte(snr):
    if snr is None:
        return SNR_UNKNOWN
    return max(-128, min(126, int(round(float(snr) * 2)))) & 0xFF


def _snr_value(byte):
    if byte == SNR_UNKNOWN:
        return None
    return (byte - 256 if byte > 127 else byte) / 2.0


def make_report(reporter, sender, entries, dist=UNKNOWN_DIST, snr=None):
    """entries: [(item(4 bytes), total, set of received indices)]"""
    entries = list(entries)[:MAX_REPORT_ITEMS]
    body = b""
    for item, total, have in entries:
        bits = 0
        for i in have:
            bits |= 1 << i
        body += item + bytes([total]) + bits.to_bytes(2, "little")
    return (MAGIC + bytes([KIND_REPORT_V24]) + _id_bytes(reporter) + _id_bytes(sender)
            + bytes([dist, _snr_byte(snr), len(entries)]) + body)


def _id_bytes(node_id):
    raw = bytes.fromhex(node_id)
    if len(raw) != 8:
        raise ValueError("node id must be 16 hex")
    return raw


# PAUL_MESH_V24: preset deflate dictionary (identical on every node; never change DICT 1,
# add a new id instead). Built from the canonical JSON of the relayable reports.
BLOB_DICT_MAGIC = 0xD1
_T = {"e": "/v1/telemetry", "p": {"gateway": "", "kind": "system_status", "metrics": {
    "cpu_temperature_c": 0, "data_disk_free_bytes": 0, "data_disk_total_bytes": 0, "last_collector_success_at": 0,
    "memory_available_bytes": 0, "memory_total_bytes": 0, "process_uptime_s": 0, "system_uptime_s": 0},
    "node": "", "nonce": "", "public_key": "", "schema": "paulnet-telemetry-v1", "signature": "",
    "timestamp": 1794580000, "version": "1.0.4"}}
_W = {"e": "/v1/witnesses", "p": {"beacon": "", "beacon_timestamp": 1794580000, "datr": "SF9BW125",
    "frequency": 868.3, "frequency_offset": 0, "nonce": "", "receiver_gateway": "", "receiver_node": "",
    "receiver_public_key": "", "received_at": 1794580000, "rssi": -110, "sender_gateway": "", "sender_node": "",
    "sequence": 0, "snr": -5.0, "witness_signature": ""}}
_B = {"e": "/v1/beacons", "p": {"beacon_timestamp": 1794580000, "datr": "SF9BW125", "frequency": 868.3,
    "gateway": "", "kind": "beacon_tx", "node": "", "nonce": "", "power": 14, "public_key": "",
    "schema": "paulnet-beacon-tx-v1", "sequence": 0, "signature": "", "timestamp": 1794580000, "version": "1.0.4"}}
BLOB_DICTS = {1: b"".join(json.dumps(x, separators=(",", ":"), sort_keys=True).encode() for x in (_W, _T, _B))}
BLOB_DICTS[2] = BLOB_DICTS[1]
BLOB_DICT_ID = 2
# id 2: top-level base64/hex fields travel as raw bytes in front of the deflate stream
BIN_FIELDS = ("public_key", "signature", "nonce", "witness_signature", "receiver_public_key", "beacon")


def _pack_fields(payload):
    payload = dict(payload)
    out = b""
    count = 0
    for idx, key in enumerate(BIN_FIELDS):
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            continue
        raw = kind = None
        try:
            b = base64.b64decode(value, validate=True)
            if base64.b64encode(b).decode() == value:
                raw, kind = b, 1
        except (ValueError, TypeError):
            pass
        if raw is None and len(value) % 2 == 0:
            try:
                b = bytes.fromhex(value)
                if b.hex() == value:
                    raw, kind = b, 2
            except ValueError:
                pass
        if raw is None or len(raw) > 255:
            continue
        payload[key] = ""
        out += bytes([idx, kind, len(raw)]) + raw
        count += 1
    return payload, bytes([count]) + out


def _unpack_fields(data):
    count, pos, fields = data[0], 1, {}
    for _ in range(count):
        idx, kind, n = data[pos], data[pos + 1], data[pos + 2]
        raw = data[pos + 3:pos + 3 + n]
        if idx >= len(BIN_FIELDS) or kind not in (1, 2) or len(raw) != n:
            raise ValueError("bad packed field")
        fields[BIN_FIELDS[idx]] = base64.b64encode(raw).decode() if kind == 1 else raw.hex()
        pos += 3 + n
    return fields, data[pos:]


def make_blob(endpoint, payload, compact=False):
    if endpoint not in REPORT_ENDPOINTS:
        raise ValueError("endpoint not relayable")
    if compact:
        slim, packed = _pack_fields(payload)
        raw = json.dumps({"e": endpoint, "p": slim}, separators=(",", ":"), sort_keys=True).encode()
        c = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_DEFAULT_STRATEGY, zdict=BLOB_DICTS[BLOB_DICT_ID])
        blob = bytes([BLOB_DICT_MAGIC, BLOB_DICT_ID]) + packed + c.compress(raw) + c.flush()
    else:
        raw = json.dumps({"e": endpoint, "p": payload}, separators=(",", ":"), sort_keys=True).encode()
        blob = zlib.compress(raw, 9)
    if len(blob) > MAX_BLOB:
        raise ValueError("report too large for mesh")
    return blob


def item_id(blob):
    return hashlib.sha256(blob).digest()[:4]


def fragments(origin, blob, hops=0, dist=UNKNOWN_DIST, sender=None, chunk=None):
    item = item_id(blob)
    chunk = max(chunk or CHUNK, -(-len(blob) // MAX_FRAGMENTS))
    chunks = [blob[i:i + chunk] for i in range(0, len(blob), chunk)] or [b""]
    total = len(chunks)
    sender_raw = _id_bytes(sender or origin)
    return item, [MAGIC + bytes([KIND_DATA_V21]) + _id_bytes(origin) + sender_raw + item
                  + bytes([hops, dist, i, total]) + c for i, c in enumerate(chunks)]


def make_ack(relay, origin, items, dist=UNKNOWN_DIST):
    items = list(items)[:MAX_ACK_IDS]
    return (MAGIC + bytes([KIND_ACK_V2]) + _id_bytes(relay) + _id_bytes(origin) + bytes([dist, len(items)])
            + b"".join(items))


def parse(raw):
    if not is_frame(raw):
        raise ValueError("not a mesh frame")
    kind = raw[3]
    if kind in (KIND_REPORT, KIND_REPORT_V24):
        if len(raw) < REPORT_HEADER:
            raise ValueError("short report frame")
        n = raw[REPORT_HEADER - 1]
        if n > MAX_REPORT_ITEMS or len(raw) != REPORT_HEADER + REPORT_ENTRY * n:
            raise ValueError("bad report length")
        entries = []
        for k in range(n):
            e = raw[REPORT_HEADER + REPORT_ENTRY * k:REPORT_HEADER + REPORT_ENTRY * (k + 1)]
            bits = int.from_bytes(e[5:7], "little")
            entries.append({"item": e[:4], "total": e[4], "have": {i for i in range(16) if bits >> i & 1}})
        return {"kind": "report", "relay": raw[4:12].hex(), "sender": raw[12:20].hex(), "dist": raw[20],
                "snr": _snr_value(raw[21]), "entries": entries, "compact": kind == KIND_REPORT_V24}
    if kind == KIND_DATA_V21:
        if len(raw) < DATA_HEADER_V21:
            raise ValueError("short data frame")
        hops, dist, index, total = raw[24], raw[25], raw[26], raw[27]
        if total < 1 or total > MAX_FRAGMENTS or index >= total or hops > MAX_HOPS:
            raise ValueError("bad fragment header")
        return {"kind": "data", "origin": raw[4:12].hex(), "sender": raw[12:20].hex(), "item": raw[20:24],
                "hops": hops, "dist": dist, "index": index, "total": total, "chunk": raw[DATA_HEADER_V21:]}
    if kind in (KIND_DATA, KIND_DATA_V1):
        v2 = kind == KIND_DATA
        header = DATA_HEADER if v2 else DATA_HEADER_V1
        if len(raw) < header:
            raise ValueError("short data frame")
        hops = raw[16] if v2 else 0
        dist = raw[17] if v2 else UNKNOWN_DIST
        index, total = raw[header - 2], raw[header - 1]
        if total < 1 or total > MAX_FRAGMENTS or index >= total or hops > MAX_HOPS:
            raise ValueError("bad fragment header")
        return {"kind": "data", "origin": raw[4:12].hex(), "sender": None, "item": raw[12:16], "hops": hops,
                "dist": dist, "index": index, "total": total, "chunk": raw[header:]}
    v2 = kind == KIND_ACK_V2
    header = ACK_HEADER_V2 if v2 else ACK_HEADER
    if len(raw) < header:
        raise ValueError("short ack frame")
    count = raw[header - 1]
    if count > MAX_ACK_IDS or len(raw) != header + 4 * count:
        raise ValueError("bad ack length")
    return {"kind": "ack", "relay": raw[4:12].hex(), "origin": raw[12:20].hex(),
            "dist": raw[20] if v2 else UNKNOWN_DIST,
            "items": [raw[header + 4 * i:header + 4 + 4 * i] for i in range(count)]}


def unpack_blob(blob):
    if blob[:1] == bytes([BLOB_DICT_MAGIC]):
        zdict = BLOB_DICTS.get(blob[1] if len(blob) > 1 else -1)
        if zdict is None:
            raise ValueError("unknown blob dictionary")
        fields, rest = ({}, blob[2:]) if blob[1] == 1 else _unpack_fields(blob[2:])
        data = zlib.decompressobj(-15, zdict=zdict).decompress(rest, 16384)
    else:
        fields = {}
        data = zlib.decompressobj().decompress(blob, 16384)
    value = json.loads(data.decode("utf-8"))
    endpoint, payload = value.get("e"), value.get("p")
    if endpoint not in REPORT_ENDPOINTS or not isinstance(payload, dict):
        raise ValueError("bad mesh payload")
    payload.update(fields)
    return endpoint, payload


def carry_record(origin, hops, blob):
    return {"o": origin, "h": int(hops), "b": base64.b64encode(blob).decode()}


def carry_to_upload(payload_text, relay_id):
    """Outbox row of CARRY_ENDPOINT -> (endpoint?relay=..&hops=.., payload JSON text) for upload."""
    record = json.loads(payload_text)
    endpoint, payload = unpack_blob(base64.b64decode(record["b"]))
    return (endpoint + "?relay=" + relay_id + "&hops=" + str(int(record.get("h", 1))),
            json.dumps(payload, separators=(",", ":")))


def force_offline_until(data_dir):
    """Test switch: /data/mesh-force-offline holds a unix expiry time."""
    try:
        until = int(Path(data_dir, FORCE_OFFLINE_FILE).read_text().strip())
    except (OSError, ValueError):
        return 0
    return until if until > time.time() else 0


class Mesh:
    def __init__(self, data_dir, outbox_db, node_id, emit=None, started=None):
        self.data_dir = Path(data_dir)
        self.outbox_db = outbox_db
        self.node_id = node_id
        self.emit = emit or (lambda *a, **k: None)
        self.started = started if started is not None else time.time()
        self.sending = None          # current round: {"row", "item", "frames": [(index, frame)], "next", ...}
        self.waiting = {}            # item -> {"row", "sent", "attempts", "origin", "blob", "chunk", "total", ...}
        self.parts = {}              # (origin, item, total) -> {"total", "chunks", "first", "last", "sender"}
        self.done = {}               # (origin, item) -> time handled (uploaded, carried or handed over)
        self.acks = {}               # origin -> [item, ...]
        self.reports = {}            # sender -> time the receive report is due (PAUL_MESH_V23)
        self.rx_link = {}            # neighbour -> (SNR we hear it at, EWMA, time)
        self.tx_link = {}            # neighbour -> (SNR it reports hearing us at, time)
        self.compact_peers = {}      # neighbour -> time it proved it decodes dictionary blobs (PAUL_MESH_V24)
        self.last_telemetry_acked = 0.0
        self.announce = {}           # sender -> time a capability RPT is due (it still sends classic blobs)
        self.announced = {}          # sender -> last capability RPT sent
        self.airtime_log = []        # (time, seconds)
        self.next_tx_at = 0.0        # one frame at a time on the concentrator
        self._offline_cache = (0.0, False)
        self.neighbours = {}         # relay id -> (announced distance, time heard)
        self.last_hello = 0.0
        self.last_probe = 0.0
        self.last_rx_note = ""
        self.stats = {"tx_frames": 0, "relayed_items": 0, "carried_items": 0, "acked_items": 0, "rx_frames": 0,
                      "reports_sent": 0, "reports_rx": 0, "resent_fragments": 0}

    # ---------------------------------------------------------------- state
    def _relayable_backlog_since(self):
        try:
            with _db(self.outbox_db) as db:
                marks = ",".join("?" * len(ENDPOINTS))
                return db.execute(f"SELECT MIN(created_at) FROM outbox WHERE endpoint IN ({marks})",
                                  tuple(ENDPOINTS)).fetchone()[0]
        except sqlite3.Error:
            return None

    def offline(self, last_success, now=None):
        """Offline = reports are piling up: no upload for OFFLINE_AFTER and the
        oldest relayable report has waited that long (an idle node is not offline)."""
        now = time.time() if now is None else now
        if force_offline_until(self.data_dir):
            return True
        reference = last_success if last_success else self.started
        if now - reference <= OFFLINE_AFTER or now - self.started <= OFFLINE_AFTER:
            return False
        cached_at, cached = self._offline_cache
        if 0 <= now - cached_at < 5:
            return cached
        oldest = self._relayable_backlog_since()
        value = oldest is not None and now - oldest > OFFLINE_AFTER
        self._offline_cache = (now, value)
        return value

    def online(self, last_success, now=None):
        now = time.time() if now is None else now
        return bool(last_success) and now - last_success <= ONLINE_WITHIN and not force_offline_until(self.data_dir)

    def distance(self, last_success, now=None):
        """Hops to the Internet: 0 online, 1 + best neighbour heard within DIST_TTL, else 255."""
        now = time.time() if now is None else now
        if self.online(last_success, now):
            return 0
        best = min((d for _, d in self._route_neighbours(now)), default=None)
        return UNKNOWN_DIST if best is None else min(best + 1, UNKNOWN_DIST - 1)

    def link_snr(self, node, now):
        """Best estimate of how well `node` hears us: its own report, else how well we hear it."""
        tx = self.tx_link.get(node)
        if tx and now - tx[1] < REPORTED_LINK_TTL:
            return tx[0]
        rx = self.rx_link.get(node)
        if rx and now - rx[1] < LINK_TTL:
            return rx[0]
        return None

    def parent(self, now):
        """Neighbour with the smallest announced distance (our next hop towards the Internet);
        ties go to the neighbour with the better link."""
        best = None
        for node, d in self._route_neighbours(now):
            if True:
                snr = self.link_snr(node, now)
                seen = self.compact_peers.get(node)  # PAUL_MESH_V25: prefer neighbours that send reports + decode dict blobs
                capable = 0 if seen and now - seen < CAPS_TTL else 1
                key = (d, capable, -(snr if snr is not None else -99.0))
                if best is None or key < best[1]:
                    best = (node, key)
        return best[0] if best else None

    def route_known(self, now):
        return any(True for _ in self._route_neighbours(now))

    def _route_neighbours(self, now):
        """(node, dist) of fresh neighbours with a usable link (PAUL_MESH_V26): a neighbour we
        barely hear (e.g. -17 dB at SF11) must not make us look closer to the Internet than we are."""
        fresh = [(node, d) for node, (d, t) in self.neighbours.items() if now - t < DIST_TTL and d < UNKNOWN_DIST]
        good = [(node, d) for node, d in fresh
                if self.link_snr(node, now) is None or self.link_snr(node, now) >= MIN_ROUTE_SNR]
        return good or fresh                            # only weak neighbours: keep the v2.5 behaviour

    def heard(self, node, snr, now=None):
        """Remember the SNR of any mesh frame received from a neighbour (EWMA)."""
        if not node or node == self.node_id or snr is None:
            return
        now = time.time() if now is None else now
        try:
            snr = float(snr)
        except (TypeError, ValueError):
            return
        old = self.rx_link.get(node)
        if old and now - old[1] < LINK_TTL:
            snr = 0.7 * old[0] + 0.3 * snr
        self.rx_link[node] = (round(snr, 2), now)

    def next_hello_frame(self, last_success, now=None):
        """Route announcement (empty ACK) when due; None otherwise."""
        now = time.time() if now is None else now
        dist = self.distance(last_success, now)
        if dist >= UNKNOWN_DIST or now - self.last_hello < HELLO_INTERVAL:
            return None
        return make_ack(self.node_id, self.node_id, [], dist)

    def hello_sent(self, now=None):
        self.last_hello = time.time() if now is None else now

    def heard_ack(self, frame, now=None):
        """Learn a neighbour's distance from any ACK it transmits (to us or to others)."""
        now = time.time() if now is None else now
        if frame["relay"] != self.node_id:
            self.neighbours[frame["relay"]] = (frame.get("dist", UNKNOWN_DIST), now)

    def airtime_left(self, now):
        self.airtime_log = [(t, s) for t, s in self.airtime_log if now - t < 3600]
        return AIRTIME_PER_HOUR - sum(s for _, s in self.airtime_log)

    def spent(self, now, seconds):
        self.airtime_log.append((now, seconds))
        self.stats["tx_frames"] += 1
        self.next_tx_at = now + seconds + FRAME_GAP

    def tx_ready(self, now):
        return now >= self.next_tx_at

    def _carry_count(self):
        try:
            with _db(self.outbox_db) as db:
                return db.execute("SELECT COUNT(*) FROM outbox WHERE endpoint=?", (CARRY_ENDPOINT,)).fetchone()[0]
        except sqlite3.Error:
            return MAX_CARRY

    # --------------------------------------------------------------- sender
    def _retry_due(self, w, now):
        if w["attempts"] >= MAX_ATTEMPTS:
            return False
        if w.get("missing") and w.get("reported_at", 0) >= w["sent"]:
            return True                                   # receiver told us what is missing: resend now
        return now - w["sent"] >= RETRY_AFTER

    def _candidates(self, now):
        """-> (row_id, endpoint, payload, waiting item or None); retries first within a priority,
        only the newest telemetry report (plus telemetry already in flight)."""
        by_row = {w["row"]: item for item, w in self.waiting.items()}
        rows = {}
        with _db(self.outbox_db) as db:
            for row_id, endpoint, payload in db.execute(
                    "SELECT id, endpoint, payload FROM outbox WHERE endpoint != '/v1/telemetry' ORDER BY id LIMIT 500"):
                rows[row_id] = (endpoint, payload)
            for row_id, endpoint, payload in db.execute(
                    "SELECT id, endpoint, payload FROM outbox WHERE endpoint = '/v1/telemetry' ORDER BY id DESC LIMIT 1"):
                rows[row_id] = (endpoint, payload)
            ids = [r for r in by_row if isinstance(r, int) and r not in rows]
            for start in range(0, len(ids), 200):
                chunk = ids[start:start + 200]
                for row_id, endpoint, payload in db.execute(
                        "SELECT id, endpoint, payload FROM outbox WHERE id IN (%s)" % ",".join("?" * len(chunk)),
                        chunk):
                    rows[row_id] = (endpoint, payload)
        tele_in_flight = any(rows[r][0] == "/v1/telemetry" for r in by_row if r in rows
                             and self.waiting[by_row[r]].get("attempts", 0) < MAX_ATTEMPTS)
        ordered = []
        for row_id, (endpoint, payload) in rows.items():
            if endpoint not in ENDPOINTS:
                continue
            item = by_row.get(row_id)
            if item is not None:
                if not self._retry_due(self.waiting[item], now):
                    continue
                ordered.append((ENDPOINTS[endpoint], 0, row_id, row_id, endpoint, payload, item))
            else:
                if endpoint == "/v1/telemetry" and (
                        tele_in_flight or now - self.last_telemetry_acked < TELEMETRY_MESH_INTERVAL):
                    continue                            # PAUL_MESH_V24: airtime goes to beacons first
                ordered.append((ENDPOINTS[endpoint], 1, row_id, row_id, endpoint, payload, None))
        ordered.sort(key=lambda r: r[:3])
        for _, _, _, row_id, endpoint, payload, item in ordered:
            yield row_id, endpoint, payload, item

    def compact_ok(self, now):
        parent = self.parent(now)
        seen = self.compact_peers.get(parent) if parent else None
        return bool(seen and now - seen < CAPS_TTL)

    def _build(self, endpoint, payload_text, now=None):
        """-> (origin, hops, blob) for an outbox row."""
        if endpoint == CARRY_ENDPOINT:
            record = json.loads(payload_text)
            return str(record["o"]), int(record["h"]), base64.b64decode(record["b"])
        now = time.time() if now is None else now
        return self.node_id, 0, make_blob(endpoint, json.loads(payload_text), compact=self.compact_ok(now))

    def link_index(self, now):
        parent = self.parent(now)
        return link_index(self.link_snr(parent, now) if parent else None)

    def current_datr(self):
        """Datarate for the frame returned by next_origin_frame."""
        return self.sending["datr"] if self.sending else DATARATE

    def next_origin_frame(self, last_success, now=None):
        now = time.time() if now is None else now
        if not self.offline(last_success, now):
            self.sending = None
            return None
        if self.sending is None:
            if not self.route_known(now):
                if now - self.last_probe < PROBE_INTERVAL:
                    return None                         # no known route: only a rare probe
                self.last_probe = now
            dist = self.distance(last_success, now)
            base = self.link_index(now)
            last = len(DATA_DATARATES) - 1
            for row_id, endpoint, payload, item in self._candidates(now):
                if item is not None:                    # retry of an item already sent
                    w = self.waiting[item]
                    if not (w.get("missing") and w.get("reported_at", 0) >= w["sent"]):
                        w["stalls"] = w.get("stalls", 0) + 1      # timed out without any report
                    datr = DATA_DATARATES[min(base + w.get("stalls", 0), last)]
                    _, frames = fragments(w["origin"], w["blob"], w["hops"], dist, self.node_id, w["chunk"])
                    wanted = sorted(w["missing"]) if w.get("missing") else range(len(frames))
                    self.sending = {"row": row_id, "item": item, "frames": [(i, frames[i]) for i in wanted
                                                                            if i < len(frames)],
                                    "next": 0, "endpoint": endpoint, "origin": w["origin"], "hops": w["hops"],
                                    "datr": datr, "blob": w["blob"], "chunk": w["chunk"], "total": len(frames),
                                    "stalls": w.get("stalls", 0), "resend": True}
                    break
                try:
                    origin, hops, blob = self._build(endpoint, payload, now)
                except (ValueError, TypeError, KeyError) as error:
                    self.emit("MESH_SKIP", row=row_id, endpoint=endpoint, reason=str(error)[:80])
                    self.waiting[b"skip%d" % row_id] = {"row": row_id, "sent": now, "attempts": MAX_ATTEMPTS,
                                                        "origin": None}
                    continue
                datr = DATA_DATARATES[min(base, last)]
                chunk = chunk_for(datr)
                item, frames = fragments(origin, blob, hops, dist, self.node_id, chunk)
                if item in self.waiting and self.waiting[item]["row"] != row_id:
                    continue                            # same report queued twice: one copy is enough
                self.sending = {"row": row_id, "item": item, "frames": list(enumerate(frames)), "next": 0,
                                "endpoint": endpoint, "origin": origin, "hops": hops, "datr": datr, "blob": blob,
                                "chunk": chunk, "total": len(frames), "stalls": 0, "resend": False}
                break
        if self.sending is None or not self.sending["frames"]:
            self.sending = None
            return None
        return self.sending["frames"][self.sending["next"]][1]

    def origin_frame_sent(self, now=None):
        now = time.time() if now is None else now
        s = self.sending
        if s is None:
            return
        s["next"] += 1
        if s["resend"]:
            self.stats["resent_fragments"] += 1
        if s["next"] >= len(s["frames"]):
            prev = self.waiting.get(s["item"], {"attempts": 0})
            self.waiting[s["item"]] = {"row": s["row"], "sent": now, "attempts": prev["attempts"] + 1,
                                       "endpoint": s["endpoint"],
                                       "origin": s["origin"], "hops": s["hops"], "blob": s["blob"],
                                       "chunk": s["chunk"], "total": s["total"], "stalls": s["stalls"],
                                       "missing": prev.get("missing"), "reported_at": 0.0,
                                       "round": {i for i, _ in s["frames"]}}
            self.emit("MESH_ITEM_SENT", item=s["item"].hex(), row=s["row"], endpoint=s["endpoint"],
                      origin=s["origin"], hops=s["hops"], fragments=len(s["frames"]), total=s["total"],
                      attempt=prev["attempts"] + 1, datr=s["datr"], resend=s["resend"],
                      blob_bytes=len(s["blob"]), compact=s["blob"][:1] == bytes([BLOB_DICT_MAGIC]))
            self.sending = None

    def on_ack(self, frame, now=None, snr=None):
        """ACKs are addressed to the origin id of the item; a carrier listens for those too."""
        now = time.time() if now is None else now
        self.heard(frame["relay"], snr, now)
        self.heard_ack(frame, now)
        removed = 0
        with _db(self.outbox_db) as db:
            for item in frame["items"]:
                waiting = self.waiting.get(item)
                if waiting is None or waiting.get("origin") != frame["origin"]:
                    continue
                self.waiting.pop(item, None)
                if waiting.get("endpoint") == "/v1/telemetry":
                    self.last_telemetry_acked = now
                if self.sending and self.sending["item"] == item:
                    self.sending = None                 # delivered meanwhile: stop the round
                db.execute("DELETE FROM outbox WHERE id = ?", (waiting["row"],))
                self.done[(frame["origin"], item)] = now      # never take it back (no ping-pong)
                removed += 1
        if removed:
            self.stats["acked_items"] += removed
            self.emit("MESH_ACKED", relay=frame["relay"], origin=frame["origin"], items=removed)
        return removed

    def on_report(self, frame, now=None, snr=None):
        """Receive report (PAUL_MESH_V23): learn the forward link and which fragments are missing."""
        now = time.time() if now is None else now
        relay = frame["relay"]
        if relay == self.node_id:
            return 0
        self.heard(relay, snr, now)
        self.neighbours[relay] = (frame.get("dist", UNKNOWN_DIST), now)
        if frame.get("compact"):
            self.compact_peers[relay] = now
        if frame["sender"] != self.node_id:
            return 0
        self.stats["reports_rx"] += 1
        if frame.get("snr") is not None:
            self.tx_link[relay] = (frame["snr"], now)
        if relay != self.parent(now):
            return 0                                    # only our next hop steers resends
        updated = 0
        for entry in frame["entries"]:
            w = self.waiting.get(entry["item"])
            if not w or w.get("total") != entry["total"]:
                continue
            missing = set(range(entry["total"])) - entry["have"]
            if not missing:
                continue                                # complete there; its ACK is on the way
            sent = w.get("round") or set()
            if sent and len(sent & entry["have"]) * 2 < len(sent):
                w["stalls"] = w.get("stalls", 0) + 1     # lost more than half of the round: slower SF
            w["round"] = set()
            w["missing"] = missing
            w["reported_at"] = now
            updated += 1
        return updated

    # --------------------------------------------------------------- receiver
    def _drop(self, note):  # PAUL_MESH_RXLOG_V1
        self.last_rx_note = note
        return None

    def _would_take(self, sender, sender_dist, last_success, now):
        if self.online(last_success, now):
            return True
        mine = self.distance(last_success, now)
        return mine < UNKNOWN_DIST and mine < sender_dist and (sender is None or sender != self.parent(now))

    def on_data(self, frame, last_success, now=None, snr=None):
        """Complete item -> ("upload", endpoint, payload, origin, hops) when online,
        ("carry", record, origin, hops) when offline, else None. Both get ACKed."""
        now = time.time() if now is None else now
        self.stats["rx_frames"] += 1
        self.last_rx_note = ""
        origin = frame["origin"]
        sender = frame.get("sender")
        self.heard(sender or origin, snr, now)
        if sender and sender != self.node_id and frame.get("dist", UNKNOWN_DIST) < UNKNOWN_DIST:
            self.neighbours[sender] = (frame["dist"], now)     # data frames announce routes too
        if origin == self.node_id or sender == self.node_id:
            return self._drop('own frame')
        key = (origin, frame["item"])
        self.parts = {k: v for k, v in self.parts.items() if now - v["first"] < REASSEMBLY_TTL}
        self.done = {k: t for k, t in self.done.items() if now - t < DONE_TTL}
        if key in self.done:
            if frame["item"] not in self.waiting:
                self._queue_ack(origin, frame["item"])   # already handled here; sender missed our ACK
            return self._drop('duplicate (re-ACK)')
        if frame["item"] in self.waiting:              # we are carrying it ourselves right now
            return self._drop('item is ours in flight')
        if frame["index"] == 0 and frame["chunk"][:1] != bytes([BLOB_DICT_MAGIC]):
            peer = sender or origin
            if now - self.announced.get(peer, 0) > CAPS_TTL / 4:
                self.announce.setdefault(peer, now + REPORT_QUIET)   # PAUL_MESH_V24: tell it we decode dict blobs
        pkey = (origin, frame["item"], frame["total"])
        if pkey not in self.parts and len(self.parts) >= MAX_PARTS:
            oldest = min(self.parts, key=lambda k: self.parts[k]["last"])
            self.parts.pop(oldest, None)
        entry = self.parts.setdefault(pkey, {"total": frame["total"], "chunks": {}, "first": now})
        entry["last"] = now
        entry["sender"] = sender or origin
        entry["chunks"][frame["index"]] = frame["chunk"]
        sender_dist = frame.get("dist", UNKNOWN_DIST)
        if sender in self.neighbours and now - self.neighbours[sender][1] < DIST_TTL:
            sender_dist = min(sender_dist, self.neighbours[sender][0])
        if len(entry["chunks"]) < entry["total"]:
            if self._would_take(sender, sender_dist, last_success, now):
                self.reports[entry["sender"]] = now + REPORT_QUIET   # report once the sender pauses
            return self._drop('partial %d/%d' % (len(entry["chunks"]), entry["total"]))
        self.parts.pop(pkey, None)
        for other in [k for k in self.parts if k[:2] == key]:
            self.parts.pop(other, None)
        blob = b"".join(entry["chunks"][i] for i in range(entry["total"]))
        if item_id(blob) != frame["item"]:
            self.emit("MESH_REJECTED", origin=origin, reason="item hash mismatch")
            return self._drop("rejected")
        try:
            endpoint, payload = unpack_blob(blob)
        except (ValueError, zlib.error, UnicodeDecodeError) as error:
            self.emit("MESH_REJECTED", origin=origin, reason=str(error)[:80])
            return self._drop("rejected")
        if str(payload.get(ORIGIN_FIELD[endpoint], "")).lower() != origin:
            self.emit("MESH_REJECTED", origin=origin, reason="payload not signed by origin")
            return self._drop("rejected")
        hops = frame["hops"] + 1
        if self.online(last_success, now):
            self.done[key] = now
            self._queue_ack(origin, frame["item"])
            self.stats["relayed_items"] += 1
            return "upload", endpoint, payload, origin, hops
        mine = self.distance(last_success, now)
        if mine >= UNKNOWN_DIST or mine >= sender_dist:
            return self._drop('not closer')                                 # not closer to the Internet: no custody (no sideways)
        if sender is not None and sender == self.parent(now):
            return self._drop('sender is our parent')                                 # our route goes through the sender: never take back
        if hops >= MAX_HOPS or self._carry_count() >= MAX_CARRY:
            return self._drop('hop limit / carry full')                                 # cannot help; no ACK, sender keeps it
        self.done[key] = now
        self._queue_ack(origin, frame["item"])
        self.stats["carried_items"] += 1
        return "carry", carry_record(origin, hops, blob), origin, hops

    def _queue_ack(self, origin, item):
        pending = self.acks.setdefault(origin, [])
        if item not in pending:
            pending.append(item)

    def next_ack_frame(self, last_success=None, now=None):
        for origin, items in list(self.acks.items()):
            if items:
                return origin, make_ack(self.node_id, origin, items[:MAX_ACK_IDS],
                                        self.distance(last_success, now))
        return None

    def ack_sent(self, origin, frame):
        sent = parse(frame)["items"]
        self.acks[origin] = [i for i in self.acks.get(origin, []) if i not in sent]
        if not self.acks[origin]:
            self.acks.pop(origin, None)

    def next_report_frame(self, last_success=None, now=None):
        """-> (sender, RPT frame) once a sender with incomplete items has paused for REPORT_QUIET."""
        now = time.time() if now is None else now
        for sender, due in sorted(self.reports.items(), key=lambda kv: kv[1]):
            if due > now:
                continue
            entries = [(k[1], v["total"], set(v["chunks"]))
                       for k, v in sorted(self.parts.items(), key=lambda kv: -kv[1]["last"])
                       if v.get("sender") == sender and (k[0], k[1]) not in self.done]
            if not entries:
                self.reports.pop(sender, None)
                continue
            rx = self.rx_link.get(sender)
            return sender, make_report(self.node_id, sender, entries, self.distance(last_success, now),
                                       rx[0] if rx else None)
        for sender, due in sorted(self.announce.items(), key=lambda kv: kv[1]):
            if due <= now:                      # empty RPT kind 7 = capability + link SNR, no entries
                rx = self.rx_link.get(sender)
                return sender, make_report(self.node_id, sender, [], self.distance(last_success, now),
                                           rx[0] if rx else None)
        return None

    def report_sent(self, sender, now=None):
        now = time.time() if now is None else now
        self.reports.pop(sender, None)
        if self.announce.pop(sender, None) is not None or sender not in self.announced:
            self.announced[sender] = now        # any RPT also announces the capability
        self.stats["reports_sent"] += 1

    def status(self):
        now = time.time()
        links = {}
        for node in set(self.rx_link) | set(self.tx_link):
            rx, tx = self.rx_link.get(node), self.tx_link.get(node)
            links[node] = {"rx_snr": rx[0] if rx and now - rx[1] < LINK_TTL else None,
                           "tx_snr": tx[0] if tx and now - tx[1] < LINK_TTL else None}
        return dict(self.stats, version=MESH_VERSION, sending=bool(self.sending),
                    neighbours={k: v[0] for k, v in self.neighbours.items()}, links=links,
                    compact_peers=sorted(k for k, t in self.compact_peers.items() if now - t < CAPS_TTL),
                    parent=self.parent(now), start_datr=DATA_DATARATES[min(self.link_index(now),
                                                                          len(DATA_DATARATES) - 1)],
                    waiting=len(self.waiting), pending_acks=sum(len(v) for v in self.acks.values()),
                    partial_items=len(self.parts),
                    force_offline_until=force_offline_until(self.data_dir) or None)
