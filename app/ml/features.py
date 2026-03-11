"""
app/ml/features.py
==================
Converts raw network event dicts into fixed-length numeric feature vectors
that Isolation Forest can learn from.

Feature vector (10 dimensions):
  [0]  source_ip_int          — IP converted to integer (captures IP-space locality)
  [1]  dest_ip_int            — same for destination
  [2]  source_port            — 0 if missing
  [3]  dest_port              — 0 if missing
  [4]  protocol_encoded       — TCP=1 UDP=2 ICMP=3 other=0
  [5]  is_private_source      — 1 if source IP is RFC-1918 private
  [6]  is_private_dest        — 1 if destination IP is RFC-1918 private
  [7]  port_ratio             — src_port / (dest_port+1)  [avoids div-by-zero]
  [8]  dest_port_category     — 0=other 1=web 2=db 3=admin/backdoor 4=mail
  [9]  hour_of_day            — 0-23 from event timestamp (UTC)
"""

import socket
import struct
from datetime import datetime, timezone
from typing import Optional

# ── Constants ─────────────────────────────────────────────────────

PROTOCOL_MAP = {
    "tcp": 1, "udp": 2, "icmp": 3,
    "http": 4, "https": 4, "dns": 5,
}

# Destination port category buckets
# Category 1 = web (80, 443, 8080, 8443)
# Category 2 = database (1433, 1521, 3306, 5432, 6379, 27017)
# Category 3 = admin/backdoor (22, 23, 3389, 4444, 5555, 6666, 7777, 8888, 9999, 1337)
# Category 4 = mail (25, 110, 143, 465, 587, 993, 995)
# Category 0 = other

WEB_PORTS   = {80, 443, 8080, 8443, 8000, 8888}
DB_PORTS    = {1433, 1521, 3306, 5432, 5433, 6379, 27017, 9200, 9042}
ADMIN_PORTS = {22, 23, 3389, 4444, 5555, 6666, 7777, 9999, 1337, 31337, 12345}
MAIL_PORTS  = {25, 110, 143, 465, 587, 993, 995}

# RFC-1918 private ranges as (network_int, mask_int) tuples
PRIVATE_RANGES = [
    (0x0A000000, 0xFF000000),   # 10.0.0.0/8
    (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
    (0x7F000000, 0xFF000000),   # 127.0.0.0/8  (loopback)
    (0xA9FE0000, 0xFFFF0000),   # 169.254.0.0/16 (link-local)
]

# Name of each feature — used for logging and explainability
feature_names = [
    "source_ip_int",
    "dest_ip_int",
    "source_port",
    "dest_port",
    "protocol_encoded",
    "is_private_source",
    "is_private_dest",
    "port_ratio",
    "dest_port_category",
    "hour_of_day",
]


# ── Helpers ───────────────────────────────────────────────────────

def _ip_to_int(ip: Optional[str]) -> int:
    """Convert dotted-decimal IP string to 32-bit integer. Returns 0 on failure."""
    if not ip:
        return 0
    try:
        packed = socket.inet_aton(ip)
        return struct.unpack("!I", packed)[0]
    except (socket.error, struct.error):
        return 0


def _is_private(ip_int: int) -> int:
    """Return 1 if IP integer falls in a private/reserved range, else 0."""
    for net, mask in PRIVATE_RANGES:
        if ip_int & mask == net:
            return 1
    return 0


def _dest_port_category(port: Optional[int]) -> int:
    """Map destination port to category integer."""
    if port is None:
        return 0
    if port in WEB_PORTS:
        return 1
    if port in DB_PORTS:
        return 2
    if port in ADMIN_PORTS:
        return 3
    if port in MAIL_PORTS:
        return 4
    return 0


def _encode_protocol(protocol: Optional[str]) -> int:
    """Map protocol string to integer code."""
    if not protocol:
        return 0
    return PROTOCOL_MAP.get(protocol.lower().strip(), 0)


def _hour_of_day(timestamp: Optional[str]) -> int:
    """Extract hour (0-23 UTC) from ISO timestamp string. Returns 12 on failure."""
    if not timestamp:
        return 12  # neutral default
    try:
        # Handle both 'Z' suffix and '+00:00'
        ts = timestamp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(timezone.utc).hour
    except (ValueError, TypeError):
        return 12


# ── Public API ────────────────────────────────────────────────────

def extract_features(event: dict) -> list:
    """
    Convert a raw event dict into a 10-dimensional numeric feature vector.

    Parameters
    ----------
    event : dict
        Keys used: source_ip, destination_ip, source_port,
                   destination_port, protocol, timestamp

    Returns
    -------
    list of float
        Length-10 vector aligned with feature_names.
    """
    src_ip   = event.get("source_ip")
    dst_ip   = event.get("destination_ip")
    src_port = event.get("source_port") or 0
    dst_port = event.get("destination_port") or 0

    src_int  = _ip_to_int(src_ip)
    dst_int  = _ip_to_int(dst_ip)

    port_ratio = src_port / (dst_port + 1)  # +1 avoids ZeroDivisionError

    return [
        float(src_int),
        float(dst_int),
        float(src_port),
        float(dst_port),
        float(_encode_protocol(event.get("protocol"))),
        float(_is_private(src_int)),
        float(_is_private(dst_int)),
        float(round(port_ratio, 4)),
        float(_dest_port_category(dst_port if dst_port else None)),
        float(_hour_of_day(event.get("timestamp"))),
    ]


def explain_features(event: dict) -> dict:
    """
    Return a human-readable dict mapping each feature name to its value.
    Useful for debugging and API explainability output.
    """
    values = extract_features(event)
    return dict(zip(feature_names, values))
