"""PAUL direct LoRa messenger v5 (node 1.0.2: EU868 + US915 radio budget).

All messages and ACKs are sent as PM3 frames: end-to-end encrypted and
authenticated with ChaCha20-Poly1305. The key for a node pair is derived
offline via X25519 from the existing Ed25519 node identities (the same
conversion libsodium uses). Peer public keys arrive over radio in signed
ON5 beacons, so neither sending nor decrypting needs the Internet.

Legacy PM1/PM2 frames (signed plaintext, node <= 0.5.32) are still parsed so
a signed PM1 can teach the sender's key, but their content is not accepted.
"""
import argparse
import contextlib
import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import struct
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"PM1"             # v3/full public-key frame
COMPACT_MAGIC = b"PM2"     # v4/known-peer compact frame
SECURE_MAGIC = b"PM3"      # v5/encrypted frame (node 1.0.1)
SECURE_HEADER = 32         # magic, kind, sender, dest, message ID, timestamp
SECURE_TAG = 16
SECURE_OVERHEAD = SECURE_HEADER + SECURE_TAG
_CURVE_P = 2 ** 255 - 19
MAX_TEXT = 120
FAST_MAX = 32
MAX_ATTEMPTS = 3
MAX_AGE = 86400
DB_NAME = "messages.sqlite3"
CONTACTS_FILE = 'messenger-contacts.json'
MESSAGE_DATARATES = tuple(
    x.strip() for x in os.environ.get("MESSENGER_DATARATES", "SF7BW125,SF8BW125,SF9BW125").split(",") if x.strip()
)[:MAX_ATTEMPTS]
if len(MESSAGE_DATARATES) < MAX_ATTEMPTS:
    MESSAGE_DATARATES = ("SF7BW125", "SF8BW125", "SF9BW125")
RETRY_WAIT = max(5.0, float(os.environ.get("MESSENGER_RETRY_WAIT", "35")))
FAILED_RETRY_WAIT = max(1.0, float(os.environ.get("MESSENGER_FAILED_RETRY_WAIT", "5")))
FINAL_WAIT = max(10.0, float(os.environ.get("MESSENGER_FINAL_WAIT", "45")))
ACK_RETRY_WAIT = max(1.0, float(os.environ.get("MESSENGER_ACK_RETRY_WAIT", "5")))


def db_path(data_dir):
    return Path(data_dir) / DB_NAME


def connection(data_dir):
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(db_path(data_dir), timeout=10)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""CREATE TABLE IF NOT EXISTS messages (
        id TEXT NOT NULL, peer TEXT NOT NULL, direction TEXT NOT NULL,
        text TEXT NOT NULL, status TEXT NOT NULL, created INTEGER NOT NULL,
        updated INTEGER NOT NULL, PRIMARY KEY (id, peer, direction))""")
    return db


_original_connection = connection
@contextlib.contextmanager
def database(data_dir):
    with contextlib.closing(_original_connection(data_dir)) as db, db:
        yield db


def _columns(db, table):
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


def _add_column(db, table, definition):
    name = definition.split()[0]
    if name not in _columns(db, table):
        db.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


def migrate(data_dir):
    with database(data_dir) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS attempts (
            id TEXT, peer TEXT, count INTEGER, sent_at INTEGER, error TEXT,
            PRIMARY KEY(id,peer))''')
        _add_column(db, 'attempts', "mode TEXT")
        _add_column(db, 'attempts', "datr TEXT")
        db.execute('''CREATE TABLE IF NOT EXISTS acknowledgements (
            id TEXT, peer TEXT, status TEXT, updated INTEGER,
            PRIMARY KEY(id,peer))''')
        _add_column(db, 'acknowledgements', "wire TEXT DEFAULT 'full'")
        _add_column(db, 'acknowledgements', "count INTEGER DEFAULT 0")
        db.execute('''CREATE TABLE IF NOT EXISTS peer_keys (
            peer TEXT PRIMARY KEY, public BLOB NOT NULL, updated INTEGER NOT NULL)''')


def node_id(public_raw):
    return hashlib.sha256(public_raw).digest()[:8].hex()


def remember_peer_key(data_dir, peer, public_raw):
    if not isinstance(public_raw, (bytes, bytearray)) or len(public_raw) != 32:
        raise ValueError("invalid peer public key")
    peer = str(peer).lower()
    if node_id(bytes(public_raw)) != peer:
        raise ValueError("peer public key does not match node ID")
    with database(data_dir) as db:
        db.execute('''INSERT INTO peer_keys(peer,public,updated) VALUES(?,?,?)
            ON CONFLICT(peer) DO UPDATE SET public=excluded.public,updated=excluded.updated''',
            (peer, bytes(public_raw), int(time.time())))


def contacts(data_dir, my_id=None):
    """Return locally known messenger peers.

    Names can be supplied through /data/messenger-contacts.json or the
    MESSENGER_CONTACTS environment variable. Every peer learned from a signed
    PAUL frame/beacon or existing message history is still listed by Node-ID,
    so the messenger remains useful without Internet access.
    """
    result = {}

    def merge(value):
        if not isinstance(value, dict):
            return
        for peer, name in value.items():
            peer = str(peer).strip().lower()
            if not re.fullmatch(r"[0-9a-f]{16}", peer):
                continue
            label = str(name or peer).strip()[:80] or peer
            result[peer] = label

    try:
        merge(json.loads(os.environ.get("MESSENGER_CONTACTS", "{}")))
    except (ValueError, TypeError):
        pass

    try:
        path = Path(data_dir) / CONTACTS_FILE
        if path.exists():
            merge(json.loads(path.read_text()))
    except (OSError, ValueError, TypeError):
        pass

    try:
        with database(data_dir) as db:
            peers = {row[0] for row in db.execute("SELECT peer FROM peer_keys")}
            peers.update(row[0] for row in db.execute("SELECT DISTINCT peer FROM messages"))
        for peer in peers:
            peer = str(peer).lower()
            if re.fullmatch(r"[0-9a-f]{16}", peer):
                result.setdefault(peer, peer)
    except sqlite3.Error:
        pass

    if my_id:
        result.pop(str(my_id).lower(), None)
    return dict(sorted(result.items(), key=lambda item: (item[1].lower(), item[0])))


def save_contacts(data_dir, mapping):
    """Persist validated display names without making the messenger Internet-dependent."""
    cleaned = {}
    if isinstance(mapping, dict):
        for peer, name in mapping.items():
            peer = str(peer).strip().lower()
            if re.fullmatch(r"[0-9a-f]{16}", peer):
                cleaned[peer] = (str(name or peer).strip()[:80] or peer)
    path = Path(data_dir) / CONTACTS_FILE
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(cleaned, sort_keys=True, separators=(",", ":")))
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return cleaned


def peer_public_key(data_dir, peer):
    with database(data_dir) as db:
        row = db.execute("SELECT public FROM peer_keys WHERE peer=?", (str(peer).lower(),)).fetchone()
    return bytes(row[0]) if row else None


def is_frame(raw):
    return raw.startswith(MAGIC) or raw.startswith(COMPACT_MAGIC) or raw.startswith(SECURE_MAGIC)


def x25519_private(private):
    """Ed25519 identity -> X25519 private key (libsodium sk_to_curve25519)."""
    seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    return X25519PrivateKey.from_private_bytes(hashlib.sha512(seed).digest()[:32])


def x25519_public(public_raw):
    """Ed25519 public key -> X25519 public key (u = (1+y)/(1-y) mod p)."""
    if not isinstance(public_raw, (bytes, bytearray)) or len(public_raw) != 32:
        raise ValueError("invalid peer public key")
    y = int.from_bytes(public_raw, "little") & ((1 << 255) - 1)
    if y >= _CURVE_P or y == 1:
        raise ValueError("invalid peer public key")
    u = (1 + y) * pow((1 - y) % _CURVE_P, _CURVE_P - 2, _CURVE_P) % _CURVE_P
    return X25519PublicKey.from_public_bytes(u.to_bytes(32, "little"))


def pair_key(private, public_raw, peer_public_raw):
    """Symmetric key shared by exactly this node pair; identical on both sides."""
    shared = x25519_private(private).exchange(x25519_public(peer_public_raw))
    ids = sorted([bytes.fromhex(node_id(public_raw)), bytes.fromhex(node_id(bytes(peer_public_raw)))])
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"PAUL-PM3-v1",
                info=b"paul-messenger" + ids[0] + ids[1]).derive(shared)


def _secure_nonce(header):
    # The header (sender, receiver, message ID, kind, timestamp) is unique per
    # frame; a byte-identical retry within the same second yields the same
    # ciphertext for the same plaintext, which reveals nothing new.
    return hashlib.sha256(header).digest()[:12]


def make_secure_frame(private, public_raw, peer_public_raw, dest, message_id, timestamp, body=b"", ack=False):
    """Build PM3: 32-byte header (authenticated) + ciphertext + 16-byte tag."""
    if len(body) > MAX_TEXT or (ack and body):
        raise ValueError("message too long")
    dest_raw = bytes.fromhex(dest)
    id_raw = bytes.fromhex(message_id)
    sender_raw = bytes.fromhex(node_id(public_raw))
    if len(dest_raw) != 8 or len(id_raw) != 8:
        raise ValueError("node or message ID length")
    if node_id(bytes(peer_public_raw)) != dest:
        raise ValueError("peer public key does not match node ID")
    header = (SECURE_MAGIC + bytes([2 if ack else 1]) + sender_raw + dest_raw + id_raw
              + struct.pack(">I", timestamp))
    key = pair_key(private, public_raw, peer_public_raw)
    return header + ChaCha20Poly1305(key).encrypt(_secure_nonce(header), body, header)


def make_frame(private, public_raw, dest, message_id, timestamp, body=b"", ack=False):
    """Build a PM1 full-key frame. This remains compatible with msg3."""
    if len(body) > MAX_TEXT or (ack and body):
        raise ValueError("message too long")
    dest_raw = bytes.fromhex(dest)
    id_raw = bytes.fromhex(message_id)
    if len(dest_raw) != 8 or len(id_raw) != 8:
        raise ValueError("node or message ID length")
    signed = (MAGIC + bytes([2 if ack else 1]) + public_raw + dest_raw + id_raw
              + struct.pack(">I", timestamp) + bytes([len(body)]) + body)
    return signed + private.sign(signed)


def make_compact_frame(private, public_raw, dest, message_id, timestamp, body=b"", ack=False):
    """Build PM2. Public key is replaced by the sender's 8-byte node ID."""
    if len(body) > FAST_MAX or (ack and body):
        raise ValueError("compact message too long")
    dest_raw = bytes.fromhex(dest)
    id_raw = bytes.fromhex(message_id)
    sender_raw = bytes.fromhex(node_id(public_raw))
    if len(dest_raw) != 8 or len(id_raw) != 8 or len(sender_raw) != 8:
        raise ValueError("node or message ID length")
    signed = (COMPACT_MAGIC + bytes([2 if ack else 1]) + sender_raw + dest_raw + id_raw
              + struct.pack(">I", timestamp) + bytes([len(body)]) + body)
    return signed + private.sign(signed)


def parse_frame(raw, my_id, data_dir=None, now=None, private=None):
    """Parse PM3 (encrypted), or legacy PM1/PM2 (marked ``encrypted: False``).

    PM2 and PM3 require a previously learned sender public key; PM3 also needs
    this node's private key to decrypt.
    """
    if raw.startswith(SECURE_MAGIC):
        if len(raw) < SECURE_OVERHEAD:
            raise ValueError("not a messenger frame")
        kind = raw[3]
        if kind not in (1, 2):
            raise ValueError("unknown frame type")
        length = len(raw) - SECURE_OVERHEAD
        if length > MAX_TEXT or (kind == 2 and length):
            raise ValueError("invalid encrypted frame length")
        header = raw[:SECURE_HEADER]
        sender = raw[4:12].hex()
        dest = raw[12:20].hex()
        message_id = raw[20:28].hex()
        timestamp = struct.unpack(">I", raw[28:32])[0]
        if dest != my_id:
            return None
        current = int(time.time()) if now is None else now
        if abs(current - timestamp) > MAX_AGE:
            raise ValueError("frame timestamp out of range")
        if data_dir is None or private is None:
            raise ValueError("encrypted frame requires peer key store and private key")
        public_raw = peer_public_key(data_dir, sender)
        if public_raw is None:
            raise ValueError("unknown encrypted sender")
        my_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key = pair_key(private, my_public, public_raw)
        try:
            body = ChaCha20Poly1305(key).decrypt(_secure_nonce(header), raw[SECURE_HEADER:], header)
        except InvalidTag:
            raise ValueError("encrypted frame authentication failed") from None
        return {"kind": kind, "sender": sender, "id": message_id,
                "timestamp": timestamp, "text": body.decode("utf-8"),
                "wire": "encrypted", "encrypted": True, "public_raw": public_raw}

    if raw.startswith(MAGIC):
        if len(raw) < 121:
            raise ValueError("not a messenger frame")
        kind = raw[3]
        if kind not in (1, 2):
            raise ValueError("unknown frame type")
        public_raw = raw[4:36]
        sender = node_id(public_raw)
        dest = raw[36:44].hex()
        message_id = raw[44:52].hex()
        timestamp = struct.unpack(">I", raw[52:56])[0]
        length = raw[56]
        if length > MAX_TEXT or len(raw) != 121 + length or (kind == 2 and length):
            raise ValueError("invalid frame length")
        if dest != my_id:
            return None
        current = int(time.time()) if now is None else now
        if abs(current - timestamp) > MAX_AGE:
            raise ValueError("frame timestamp out of range")
        Ed25519PublicKey.from_public_bytes(public_raw).verify(raw[-64:], raw[:-64])
        return {"kind": kind, "sender": sender, "id": message_id,
                "timestamp": timestamp, "text": raw[57:-64].decode("utf-8"),
                "wire": "full", "encrypted": False, "public_raw": public_raw}

    if raw.startswith(COMPACT_MAGIC):
        if len(raw) < 97:
            raise ValueError("not a messenger frame")
        kind = raw[3]
        if kind not in (1, 2):
            raise ValueError("unknown frame type")
        sender = raw[4:12].hex()
        dest = raw[12:20].hex()
        message_id = raw[20:28].hex()
        timestamp = struct.unpack(">I", raw[28:32])[0]
        length = raw[32]
        if length > FAST_MAX or len(raw) != 97 + length or (kind == 2 and length):
            raise ValueError("invalid compact frame length")
        if dest != my_id:
            return None
        current = int(time.time()) if now is None else now
        if abs(current - timestamp) > MAX_AGE:
            raise ValueError("frame timestamp out of range")
        if data_dir is None:
            raise ValueError("compact frame requires peer key store")
        public_raw = peer_public_key(data_dir, sender)
        if public_raw is None:
            raise ValueError("unknown compact sender")
        Ed25519PublicKey.from_public_bytes(public_raw).verify(raw[-64:], raw[:-64])
        return {"kind": kind, "sender": sender, "id": message_id,
                "timestamp": timestamp, "text": raw[33:-64].decode("utf-8"),
                "wire": "compact", "encrypted": False, "public_raw": public_raw}

    raise ValueError("not a messenger frame")


def queue(data_dir, peer, content):
    peer = str(peer).lower()
    if len(peer) != 16:
        raise ValueError("peer must be a 16-digit node ID")
    bytes.fromhex(peer)
    body = content.encode("utf-8")
    if not body or len(body) > MAX_TEXT:
        raise ValueError(f"text must contain 1–{MAX_TEXT} UTF-8 bytes")
    mid = secrets.token_hex(8)
    now = int(time.time())
    with database(data_dir) as db:
        db.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?)",
                   (mid, peer, "out", content, "queued", now, now))
    return mid


def pending(data_dir):
    # Messages wait until the receiver's public key is known (learned from its
    # beacon), so they can always be encrypted and never block other peers.
    with database(data_dir) as db:
        return db.execute("SELECT id,peer,direction,text,status,created FROM messages "
                          "WHERE direction='out' AND status='queued' "
                          "AND peer IN (SELECT peer FROM peer_keys) "
                          "ORDER BY created,id LIMIT 1").fetchone()


def mark(data_dir, message_id, peer, direction, status):
    with database(data_dir) as db:
        db.execute("UPDATE messages SET status=?,updated=? "
                   "WHERE id=? AND peer=? AND direction=? AND status!='delivered'",
                   (status, int(time.time()), message_id, peer, direction))


def receive(data_dir, frame):
    now = int(time.time())
    if frame["kind"] == 2:
        with database(data_dir) as db:
            cur = db.execute("UPDATE messages SET status='delivered', updated=? "
                             "WHERE id=? AND peer=? AND direction='out' "
                             "AND status IN ('sent','air_accepted','queued','unconfirmed','failed','cancelled')",
                             (now, frame["id"], frame["sender"]))
            return "delivered" if cur.rowcount else "unmatched_ack"
    with database(data_dir) as db:
        cur = db.execute("INSERT OR IGNORE INTO messages VALUES (?,?,?,?,?,?,?)",
                   (frame["id"], frame["sender"], "in", frame["text"],
                    "received", now, now))
    return "received" if cur.rowcount else "duplicate"


def history(data_dir):
    with database(data_dir) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute('''SELECT m.*, COALESCE(a.count,0) AS attempts,
                a.sent_at, a.error, a.mode, a.datr, k.status AS ack_status,
                EXISTS(SELECT 1 FROM peer_keys p WHERE p.peer=m.peer) AS peer_key
                FROM messages m
                LEFT JOIN attempts a ON m.id=a.id AND m.peer=a.peer AND m.direction='out'
                LEFT JOIN acknowledgements k ON m.id=k.id AND m.peer=k.peer AND m.direction='in'
                ORDER BY m.created DESC,m.rowid DESC LIMIT 200''')][::-1]


def change_status(data_dir, mid, peer, action):
    with database(data_dir) as db:
        if action == 'retry':
            # Manual retry restarts the automatic 3-attempt cycle for an undelivered message.
            cur = db.execute("UPDATE messages SET status='queued',updated=? WHERE id=? AND peer=? AND direction='out' AND status IN ('sent','air_accepted','unconfirmed','failed','cancelled')", (int(time.time()),mid,peer))
            if cur.rowcount:
                db.execute("DELETE FROM attempts WHERE id=? AND peer=?", (mid,peer))
        elif action == 'cancel':
            cur = db.execute("UPDATE messages SET status='cancelled',updated=? WHERE id=? AND peer=? AND direction='out' AND status='queued'", (int(time.time()),mid,peer))
        else:
            raise ValueError('Unbekannte Aktion')
        return cur.rowcount > 0


def peek_attempt(data_dir, mid, peer):
    """Return the next attempt number without changing message state."""
    with database(data_dir) as db:
        row = db.execute("SELECT COALESCE(count,0) FROM attempts WHERE id=? AND peer=?", (mid,peer)).fetchone()
        count = int(row[0]) if row else 0
    return count + 1 if count < MAX_ATTEMPTS else 0


def begin_attempt(data_dir, mid, peer):
    """Atomically claim a queued message and return attempt number 1..3."""
    now = int(time.time())
    with database(data_dir) as db:
        row = db.execute("SELECT COALESCE(count,0) FROM attempts WHERE id=? AND peer=?", (mid,peer)).fetchone()
        count = int(row[0]) if row else 0
        if count >= MAX_ATTEMPTS:
            db.execute("UPDATE messages SET status='unconfirmed',updated=? WHERE id=? AND peer=? AND direction='out' AND status='queued'", (now,mid,peer))
            return 0
        cur = db.execute("UPDATE messages SET status='sent',updated=? WHERE id=? AND peer=? AND direction='out' AND status='queued'", (now,mid,peer))
        if not cur.rowcount:
            return 0
        count += 1
        db.execute('''INSERT INTO attempts(id,peer,count,sent_at,error,mode,datr)
                   VALUES(?,?,?, ?,NULL,NULL,NULL) ON CONFLICT(id,peer)
                   DO UPDATE SET count=excluded.count,sent_at=excluded.sent_at,error=NULL''',
                   (mid,peer,count,now))
        return count


def transport_for(body, attempt):
    if attempt < 1 or attempt > MAX_ATTEMPTS:
        raise ValueError("invalid attempt")
    if len(body) > MAX_TEXT:
        raise ValueError("message too long")
    return "encrypted", MESSAGE_DATARATES[attempt - 1]


def record_transport(data_dir, mid, peer, mode, datr):
    with database(data_dir) as db:
        db.execute("UPDATE attempts SET mode=?,datr=? WHERE id=? AND peer=?", (mode,datr,mid,peer))


def _required_peer_key(data_dir, peer):
    peer_public = peer_public_key(data_dir, peer) if data_dir is not None else None
    if peer_public is None:
        # Never fall back to plaintext: wait for the peer's signed beacon.
        raise LookupError("peer public key unknown; message stays queued")
    return peer_public


def build_message_frame(private, public_raw, peer, mid, text, attempt, timestamp=None, data_dir=None):
    body = text.encode("utf-8")
    mode, datr = transport_for(body, attempt)
    stamp = int(time.time()) if timestamp is None else int(timestamp)
    frame = make_secure_frame(private, public_raw, _required_peer_key(data_dir, peer), peer, mid, stamp, body)
    return frame, mode, datr


def tx_result(data_dir, mid, peer, error):
    now = int(time.time())
    with database(data_dir) as db:
        status = 'air_accepted' if error == 'NONE' else 'failed'
        db.execute("UPDATE messages SET status=?,updated=? WHERE id=? AND peer=? AND direction='out' AND status IN ('sent','unconfirmed')", (status,now,mid,peer))
        db.execute('UPDATE attempts SET error=? WHERE id=? AND peer=?', (None if error == 'NONE' else error,mid,peer))


def auto_retry(data_dir, now=None):
    """Move timed-out transmissions back to the queue, at most 3 automatic tries."""
    current = int(time.time() if now is None else now)
    with database(data_dir) as db:
        rows = db.execute('''SELECT m.id,m.peer,m.status,m.updated,COALESCE(a.count,0),COALESCE(a.sent_at,m.updated)
            FROM messages m LEFT JOIN attempts a ON m.id=a.id AND m.peer=a.peer
            WHERE m.direction='out' AND m.status IN ('sent','air_accepted','failed')''').fetchall()
        for mid,peer,status,updated,count,sent_at in rows:
            age = current - int(sent_at or updated or current)
            wait = FAILED_RETRY_WAIT if status == 'failed' else (FINAL_WAIT if int(count) >= MAX_ATTEMPTS else RETRY_WAIT)
            if age < wait:
                continue
            new = 'unconfirmed' if int(count) >= MAX_ATTEMPTS else 'queued'
            db.execute("UPDATE messages SET status=?,updated=? WHERE id=? AND peer=? AND direction='out' AND status=?",
                       (new,current,mid,peer,status))


def ack_queue(data_dir, mid, peer, wire='full'):
    now = int(time.time())
    wire = 'encrypted'
    with database(data_dir) as db:
        db.execute('''INSERT INTO acknowledgements(id,peer,status,updated,wire,count)
            VALUES(?,?,'queued',?,?,0)
            ON CONFLICT(id,peer) DO UPDATE SET status='queued',updated=excluded.updated,
            wire=excluded.wire,count=CASE WHEN acknowledgements.status='accepted' THEN 0 ELSE acknowledgements.count END''',
            (mid,peer,now,wire))


def ack_pending(data_dir):
    now = int(time.time())
    with database(data_dir) as db:
        # A failed local ACK may be retried up to 3 times after a short pause.
        db.execute("UPDATE acknowledgements SET status='queued' WHERE status='failed' AND count<? AND updated<=?",
                   (MAX_ATTEMPTS, now - int(ACK_RETRY_WAIT)))
        return db.execute("SELECT id,peer,wire,count FROM acknowledgements WHERE status='queued' AND count<? ORDER BY updated LIMIT 1",
                          (MAX_ATTEMPTS,)).fetchone()


def ack_submitted(data_dir, mid, peer):
    with database(data_dir) as db:
        db.execute("UPDATE acknowledgements SET status='submitted',updated=?,count=COALESCE(count,0)+1 WHERE id=? AND peer=?",
                   (int(time.time()),mid,peer))


def ack_status(data_dir, mid, peer, status):
    with database(data_dir) as db:
        db.execute('UPDATE acknowledgements SET status=?,updated=? WHERE id=? AND peer=?',
                   (status,int(time.time()),mid,peer))


def build_ack_frame(private, public_raw, peer, mid, wire, timestamp=None, data_dir=None):
    # ``wire`` is kept for call compatibility; every ACK is a 48-byte PM3 frame.
    stamp = int(time.time()) if timestamp is None else int(timestamp)
    frame = make_secure_frame(private, public_raw, _required_peer_key(data_dir, peer), peer, mid, stamp, ack=True)
    return frame, 'encrypted', MESSAGE_DATARATES[0]


def parse_datarate(datr):
    match = re.fullmatch(r"SF(\d+)BW(\d+)", str(datr).upper())
    if not match:
        raise ValueError("unsupported LoRa data rate")
    sf, bw_khz = map(int, match.groups())
    if sf < 5 or sf > 12 or bw_khz not in (125, 250, 500):
        raise ValueError("unsupported LoRa data rate")
    return sf, bw_khz * 1000


def lora_airtime(payload_len, datr, preamble=8, coding_rate=1, crc=True, explicit_header=True):
    """LoRa packet airtime in seconds for CR 4/(4+coding_rate)."""
    sf, bw = parse_datarate(datr)
    de = 1 if sf >= 11 and bw == 125000 else 0
    ih = 0 if explicit_header else 1
    crc_value = 1 if crc else 0
    symbol = (2 ** sf) / bw
    preamble_time = (preamble + 4.25) * symbol
    numerator = 8 * int(payload_len) - 4 * sf + 28 + 16 * crc_value - 20 * ih
    denominator = 4 * (sf - 2 * de)
    payload_symbols = 8 + max(math.ceil(numerator / denominator) * (coding_rate + 4), 0)
    return preamble_time + payload_symbols * symbol


US915_SELF_LIMIT = 0.01
US915_DWELL_LIMIT = 0.400
US915_DWELL_WINDOW = 20.0


def duty_cycle_for_frequency(freq):
    override = os.environ.get("MESSENGER_DUTY_CYCLE", "").strip()
    if override:
        value = float(override)
        if not (0 < value <= 1):
            raise ValueError("MESSENGER_DUTY_CYCLE must be >0 and <=1")
        return value
    f = float(freq)
    if 902.0 <= f <= 928.0:
        # US915 has no duty-cycle rule (dwell time is enforced separately).
        # PAUL keeps a voluntary 1 % hourly budget across all US channels.
        return US915_SELF_LIMIT
    # Conservative EU868 defaults for non-specific SRDs. The PAUL pilot uses 868.3 MHz.
    if 868.0 <= f <= 868.6:
        return 0.01
    if 868.7 <= f <= 869.2:
        return 0.001
    if 869.4 <= f <= 869.65:
        return 0.10
    if 869.7 <= f <= 870.0:
        return 0.01
    return 0.01


class RadioGate:
    """Persist a shared rolling airtime budget for all PAUL transmissions.

    Schema 5 replaces the old fixed post-TX blackout.  Every actual PAUL TX
    (beacon, message or ACK) consumes the same per-band rolling-hour budget.
    This keeps the budget shared while allowing short messenger packets after
    a long SF12 coverage beacon when budget remains.
    """
    SCHEMA = 5
    WINDOW = 3600.0
    MAX_EVENTS = 512

    def __init__(self, data_dir):
        self.path = Path(data_dir) / 'messenger-radio-window.json'
        self.events = []
        self.legacy_next_at = 0.0
        now = time.time()
        try:
            value = json.loads(self.path.read_text())
            if value.get('schema') == self.SCHEMA:
                raw = value.get('events', [])
                if not isinstance(raw, list) or len(raw) > self.MAX_EVENTS:
                    raise ValueError('invalid radio event ledger')
                for item in raw:
                    if (not isinstance(item, dict) or set(item) != {'at','airtime','band'}):
                        raise ValueError('invalid radio event')
                    at = float(item['at']); airtime = float(item['airtime']); band = str(item['band'])
                    if airtime <= 0 or not band:
                        raise ValueError('invalid radio event values')
                    self.events.append({'at': at, 'airtime': airtime, 'band': band})
            elif 'next_at' in value:
                # One-way safety migration from schema 4.  Honor an existing
                # blackout once, then continue with the rolling ledger.
                self.legacy_next_at = max(now, float(value['next_at']))
        except (FileNotFoundError, ValueError, KeyError, TypeError):
            self.events = []
            self.legacy_next_at = 0.0
        self._prune(now)
        self.next_at = max(now, self.legacy_next_at)
        self.persist()

    @staticmethod
    def _band(frequency):
        f = float(frequency)
        if 902.0 <= f <= 928.0:
            # One band per channel; the hourly budget spans all us915-* bands.
            return 'us915-%.1f' % f
        if 868.0 <= f <= 868.6:
            return 'eu868-1pct-a'
        if 868.7 <= f <= 869.2:
            return 'eu868-0.1pct'
        if 869.4 <= f <= 869.65:
            return 'eu868-10pct'
        if 869.7 <= f <= 870.0:
            return 'eu868-1pct-b'
        return 'default-1pct'

    def _prune(self, now):
        cutoff = float(now) - self.WINDOW
        self.events = [e for e in self.events if e['at'] > cutoff]
        if self.legacy_next_at <= now:
            self.legacy_next_at = 0.0

    def persist(self):
        tmp = self.path.with_suffix('.tmp')
        tmp.write_text(json.dumps({'schema': self.SCHEMA, 'events': self.events[-self.MAX_EVENTS:]}))
        tmp.replace(self.path)

    def ready_at(self, payload_len, datr, frequency, reserve_airtime=0.0, now=None):
        current = time.time() if now is None else float(now)
        self._prune(current)
        airtime = lora_airtime(payload_len, datr)
        duty = duty_cycle_for_frequency(frequency)
        capacity = self.WINDOW * duty
        requested = airtime + max(0.0, float(reserve_airtime))
        if requested > capacity:
            raise ValueError('PAUL transmission exceeds rolling airtime budget')
        band = self._band(frequency)
        ready = max(current, self.legacy_next_at)
        us915 = band.startswith('us915-')
        if us915:
            if airtime >= US915_DWELL_LIMIT:
                raise ValueError('PAUL transmission exceeds US915 dwell time')
            relevant = sorted((e for e in self.events if e['band'].startswith('us915-')),
                              key=lambda e: e['at'])
        else:
            relevant = sorted((e for e in self.events if e['band'] == band), key=lambda e: e['at'])
        used = sum(e['airtime'] for e in relevant)
        if used + requested > capacity:
            remaining = used
            for event in relevant:
                remaining -= event['airtime']
                ready = max(ready, event['at'] + self.WINDOW)
                if remaining + requested <= capacity:
                    break
        if us915:
            # FCC dwell time: <= 400 ms on one channel within any 20 s window.
            channel = sorted((e for e in self.events if e['band'] == band
                              and e['at'] > current - US915_DWELL_WINDOW), key=lambda e: e['at'])
            dwell = sum(e['airtime'] for e in channel)
            for event in channel:
                if dwell + airtime < US915_DWELL_LIMIT:
                    break
                dwell -= event['airtime']
                ready = max(ready, event['at'] + US915_DWELL_WINDOW)
        self.next_at = ready
        return ready, airtime, duty

    def reserve(self, payload_len, datr, frequency, reserve_airtime=0.0, now=None):
        current = time.time() if now is None else float(now)
        ready, airtime, duty = self.ready_at(payload_len, datr, frequency, reserve_airtime, current)
        if ready > current + 0.001:
            raise RuntimeError('PAUL radio budget not ready until %.3f' % ready)
        self.events.append({'at': current, 'airtime': airtime, 'band': self._band(frequency)})
        self._prune(current)
        self.next_at = current
        self.persist()
        return airtime, duty


# ---------------------------------------------------------------------------
# Radio regions (node 1.0.2)
#
# PAUL radio regions (node 1.0.2).
#
# EU868 stays exactly as in 1.0.1: one channel (FREQUENCY, default 868.3 MHz),
# SF12 beacons, EU duty-cycle bands.
#
# US915 (FCC part 15.247, hybrid/FHSS rules as used by LoRaWAN end devices):
# - PAUL transmits on the 125 kHz uplink channels of the gateway's sub-band
#   (default FSB2 = 903.9 ... 905.3 MHz), so every PAUL gateway on the same
#   sub-band receives it on any channel and any SF7..SF10.
# - Each transmission stays below the 400 ms dwell time; the datarate is
#   lowered (SF12 -> ... -> SF7) until the frame fits. A 142-byte ON5 beacon
#   therefore goes out at SF7BW125 (236 ms).
# - The channel hops per transmission; per channel at most 400 ms airtime in
#   any 20 s window (enforced by messenger.RadioGate).
#
# Region selection:
# - REGION=EU868 or REGION=US915: fixed. If the gateway reports packets on a
#   frequency of another band, all PAUL transmissions are blocked
#   (REGION_MISMATCH) instead of transmitting outside the radio's band.
# - REGION unset or AUTO: use the stored region (/data/radio-region.json).
#   Without one, a node that already has beacon history (sequence.txt; every
#   release before 1.0.2 was EU868-only) stays EU868 - unchanged behaviour of
#   the existing fleet. A fresh install does not transmit until the first
#   received packet (rxpk freq) reveals the band; the result is stored.
# - Bands PAUL does not support yet (e.g. AU915, AS923) block transmissions.
# ---------------------------------------------------------------------------
US915_FIRST_CHANNEL = 902.3    # channel 0, 200 kHz raster, 64 x 125 kHz
US915_DEFAULT_SUBBAND = 2      # FSB2: 903.9 ... 905.3 MHz (TTN, Helium)
REGION_STATE_FILE = "radio-region.json"
REGION_SUPPORTED = ("EU868", "US915")
DATARATE_ORDER = ("SF12BW125", "SF11BW125", "SF10BW125", "SF9BW125", "SF8BW125", "SF7BW125")


def band_for_frequency(freq):
    """Map a received (rxpk) frequency in MHz to a region name or None."""
    try:
        f = float(freq)
    except (TypeError, ValueError):
        return None
    if 863.0 <= f <= 870.0:
        return "EU868"
    if 902.0 <= f < 915.0:
        return "US915"       # US915 uplink channels 0..71
    if 915.0 <= f <= 928.0:
        return "AU915"       # AU915/AS923 uplinks; a US915 gateway never receives here
    return "UNKNOWN"


def us915_subband_channels(subband):
    subband = int(subband)
    if not 1 <= subband <= 8:
        raise ValueError("US915 sub-band must be 1..8")
    first = (subband - 1) * 8
    return tuple(round(US915_FIRST_CHANNEL + 0.2 * (first + i), 1) for i in range(8))


def us915_subband_for(freq):
    f = float(freq)
    index = round((f - US915_FIRST_CHANNEL) / 0.2)
    if 0 <= index < 64 and abs(US915_FIRST_CHANNEL + 0.2 * index - f) < 0.05:
        return index // 8 + 1
    if 903.0 <= f <= 914.2:          # 500 kHz uplink channels 64..71
        index = round((f - 903.0) / 1.6)
        if abs(903.0 + 1.6 * index - f) < 0.05:
            return index + 1
    return None


def parse_channels(value):
    channels = tuple(round(float(x), 1) for x in str(value).split(",") if x.strip())
    for f in channels:
        if band_for_frequency(f) != "US915":
            raise ValueError("PAUL_CHANNELS outside US915 uplink band: %s" % f)
    return channels


class RadioRegion:
    """Region, channel and datarate policy of one node (thread-safe enough:
    only the main radio loop mutates it)."""

    def __init__(self, data_dir, env=None, emit=None):
        env = os.environ if env is None else env
        self.path = Path(data_dir) / REGION_STATE_FILE
        self.emit = emit or (lambda *a, **k: None)
        configured = str(env.get("REGION", "") or "AUTO").strip().upper()
        self.auto = configured == "AUTO"
        self.name = None if self.auto else configured
        self.source = "env"
        self.eu_frequency = float(env.get("FREQUENCY", "868.3"))
        self.eu_beacon_datr = str(env.get("BEACON_DATARATE", "SF12BW125")).strip() or "SF12BW125"
        self.subband = None
        self.fixed_channels = None
        if str(env.get("PAUL_CHANNELS", "")).strip():
            self.fixed_channels = parse_channels(env["PAUL_CHANNELS"])
        if str(env.get("PAUL_SUBBAND", "")).strip():
            self.subband = int(env["PAUL_SUBBAND"])
            us915_subband_channels(self.subband)  # validate
        self.observed = None
        self.blocked_reason = None
        self._last_channel = None
        if self.auto:
            self._load()
            if self.name is None and (Path(data_dir) / "sequence.txt").exists():
                self.name, self.source = "EU868", "legacy"
                self._store()
            if self.name is None:
                self.source = "pending"
                self.blocked_reason = "detecting"
        elif self.name not in REGION_SUPPORTED:
            self.blocked_reason = "unsupported_region"

    # ---- persistence -------------------------------------------------
    def _load(self):
        try:
            value = json.loads(self.path.read_text())
        except (FileNotFoundError, OSError, ValueError):
            return
        if not isinstance(value, dict) or value.get("schema") != 1:
            return
        name = value.get("region")
        if name in REGION_SUPPORTED:
            self.name = name
            self.source = str(value.get("source") or "stored")
            if name == "US915" and self.subband is None and value.get("subband"):
                try:
                    us915_subband_channels(int(value["subband"]))
                    self.subband = int(value["subband"])
                except (TypeError, ValueError):
                    pass

    def _store(self):
        body = {"schema": 1, "region": self.name, "source": self.source}
        if self.name == "US915":
            body["subband"] = self.current_subband()
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(body, sort_keys=True))
        tmp.replace(self.path)

    # ---- observation -------------------------------------------------
    def observe(self, freq):
        """Feed every rxpk frequency. Returns True when the policy changed."""
        band = band_for_frequency(freq)
        if band is None:
            return False
        if band == self.observed:
            return False
        first = self.observed is None
        self.observed = band
        if self.blocked_reason in ("mismatch", "unsupported_band", "unsupported_region"):
            return True          # cleared only by a restart / reconfiguration
        if band not in REGION_SUPPORTED:
            self.blocked_reason = "unsupported_band"
            self.emit("REGION_UNSUPPORTED", observed=band, frequency=float(freq))
            return True
        if self.auto and (self.name is None or (first and band != self.name and self.source == "legacy")):
            # Fresh install, or a pre-1.0.2 node whose radio is not EU868 after all.
            previous = self.name
            self.name, self.source, self.blocked_reason = band, "rx", None
            if band == "US915" and self.subband is None:
                self.subband = us915_subband_for(freq) or US915_DEFAULT_SUBBAND
            self._store()
            self.emit("REGION_DETECTED", region=band, previous=previous, frequency=float(freq),
                      channels=list(self.channels()))
            return True
        if band != self.name:
            self.blocked_reason = "mismatch"
            self.emit("REGION_MISMATCH", configured=self.name, observed=band, frequency=float(freq))
            return True
        return True

    # ---- policy ------------------------------------------------------
    @property
    def tx_allowed(self):
        return self.blocked_reason is None and self.name in REGION_SUPPORTED

    def current_subband(self):
        return self.subband or US915_DEFAULT_SUBBAND

    def channels(self):
        if self.name == "US915":
            return self.fixed_channels or us915_subband_channels(self.current_subband())
        return (self.eu_frequency,)

    def next_frequency(self):
        """Frequency for the next transmission (US915: hop, never twice in a row)."""
        channels = self.channels()
        if len(channels) == 1:
            return channels[0]
        choices = [f for f in channels if f != self._last_channel] or list(channels)
        freq = secrets.choice(choices)
        self._last_channel = freq
        return freq

    def beacon_datr(self, payload_len, airtime):
        if self.name == "US915":
            return self.fit_datr(payload_len, "SF10BW125", airtime)
        return self.eu_beacon_datr

    def fit_datr(self, payload_len, datr, airtime):
        """Keep datr in EU868; in US915 lower the SF until airtime < 400 ms."""
        if self.name != "US915":
            return datr
        start = DATARATE_ORDER.index(datr) if datr in DATARATE_ORDER else 0
        for candidate in DATARATE_ORDER[start:]:
            if airtime(payload_len, candidate) < US915_DWELL_LIMIT:
                return candidate
        raise ValueError("frame too long for US915 dwell time")

    def status(self):
        return {"region": self.name, "source": self.source, "observed": self.observed,
                "tx_allowed": self.tx_allowed, "blocked": self.blocked_reason,
                "channels": list(self.channels()),
                "subband": self.current_subband() if self.name == "US915" else None}


def private_identity(data_dir):
    raw = (Path(data_dir) / "ed25519-private.key").read_bytes()
    private = Ed25519PrivateKey.from_private_bytes(raw)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, public, node_id(public)


def main():
    parser = argparse.ArgumentParser(description="PAUL Messenger local CLI")
    parser.add_argument("--data", default=os.getenv("DATA_DIR", "/data"))
    sub = parser.add_subparsers(dest="action", required=True)
    send = sub.add_parser("send")
    send.add_argument("peer")
    send.add_argument("text")
    sub.add_parser("list")
    retry = sub.add_parser("retry")
    retry.add_argument("message_id")
    sub.add_parser("id")
    args = parser.parse_args()
    migrate(args.data)
    if args.action == "id":
        print(private_identity(args.data)[2])
    elif args.action == "send":
        print("queued", queue(args.data, args.peer.lower(), args.text))
    elif args.action == "retry":
        with database(args.data) as db:
            row = db.execute("SELECT peer FROM messages WHERE id=? AND direction='out' AND status!='delivered'", (args.message_id.lower(),)).fetchone()
        if row and change_status(args.data, args.message_id.lower(), row[0], 'retry'):
            print("queued")
        else:
            print("no matching undelivered message")
    else:
        with database(args.data) as db:
            for row in db.execute("SELECT direction,peer,status,text,id FROM messages ORDER BY created DESC,id DESC LIMIT 30"):
                print(" | ".join(map(str, row)))


if __name__ == "__main__":
    main()
