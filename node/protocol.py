import base64
import hashlib
import json
import secrets
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MAGIC = b"ON5"
LEGACY_MAGIC = b"ON3"
BEACON_SIZE = 142
LEGACY_BEACON_SIZE = 127
WITNESS_FIELDS = (
    "receiver_node",
    "receiver_gateway",
    "sender_node",
    "sender_gateway",
    "sequence",
    "beacon_timestamp",
    "nonce",
    "received_at",
    "frequency",
    "datr",
    "rssi",
    "snr",
    "frequency_offset",
    "beacon",
)


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def public_key_bytes(private_key):
    from cryptography.hazmat.primitives import serialization

    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def node_id_from_public(public_raw):
    return hashlib.sha256(public_raw).digest()[:8].hex()


def make_beacon(private_key, public_raw, gateway_eui, sequence, timestamp, rtk=None):
    # Privacy: preserve the ON5 wire format, but never broadcast location data.
    # Exact GNSS data belongs exclusively in signed collector reports.
    rtk = {}
    valid = bool(rtk.get("valid"))
    latitude = int(round(float(rtk.get("latitude", 0)) * 10_000_000)) if valid else 0
    longitude = int(round(float(rtk.get("longitude", 0)) * 10_000_000)) if valid else 0
    altitude_mm = int(round(float(rtk.get("altitude_m", 0)) * 1000)) if valid else 0
    body = (
        MAGIC
        + public_raw
        + bytes.fromhex(gateway_eui)
        + struct.pack(">IQ", sequence, timestamp)
        + secrets.token_bytes(8)
        + struct.pack(">BiiiBB", 1 if valid else 0, latitude, longitude, altitude_mm,
                      int(rtk.get("fix_quality", 0)) if valid else 0,
                      min(255, int(rtk.get("satellites", 0))) if valid else 0)
    )
    return body + private_key.sign(body)


def verify_beacon(raw):
    is_v5 = len(raw) == BEACON_SIZE and raw.startswith(MAGIC)
    is_legacy = len(raw) == LEGACY_BEACON_SIZE and raw.startswith(LEGACY_MAGIC)
    if not (is_v5 or is_legacy):
        raise ValueError("invalid beacon format")
    body, signature = raw[:-64], raw[-64:]
    public_raw = body[3:35]
    Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, body)
    result = {
        "public_raw": public_raw,
        "public_key": base64.b64encode(public_raw).decode(),
        "node_id": node_id_from_public(public_raw),
        "gateway_eui": body[35:43].hex(),
        "sequence": struct.unpack(">I", body[43:47])[0],
        "timestamp": struct.unpack(">Q", body[47:55])[0],
        "nonce": body[55:63].hex(),
    }
    if is_v5:
        flags, latitude, longitude, altitude_mm, fix_quality, satellites = struct.unpack(
            ">BiiiBB", body[63:78]
        )
        result["rtk"] = {
            "valid": bool(flags & 1),
            "latitude": latitude / 10_000_000,
            "longitude": longitude / 10_000_000,
            "altitude_m": altitude_mm / 1000,
            "fix_quality": fix_quality,
            "satellites": satellites,
        }
    else:
        result["rtk"] = {"valid": False}
    return result


def witness_signing_body(report):
    return {key: report[key] for key in WITNESS_FIELDS}


def verify_json_signature(public_key_b64, signature_b64, body):
    public_raw = base64.b64decode(public_key_b64, validate=True)
    signature = base64.b64decode(signature_b64, validate=True)
    if len(public_raw) != 32 or len(signature) != 64:
        raise ValueError("invalid key or signature length")
    Ed25519PublicKey.from_public_bytes(public_raw).verify(
        signature, canonical_bytes(body)
    )
    return public_raw
