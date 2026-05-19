"""
app/ingestion/log_checker.py
=============================
Mentor requirement: check a given log file (offline) or log stream (online)
against stored IOCs and report/alert if found, along with timestamps.
"""
import re
import os
import logging
from datetime import datetime, timezone
from typing import Iterator, List, Dict, Optional

logger = logging.getLogger(__name__)

_IPV4    = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_DOMAIN  = re.compile(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
                      r'(?:\.[a-zA-Z]{2,})+)\b')
_URL     = re.compile(r"""https?://[^\s'"<>]+""")
_MD5     = re.compile(r'\b([a-fA-F0-9]{32})\b')
_SHA256  = re.compile(r'\b([a-fA-F0-9]{64})\b')
_PRIVATE = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|::1|localhost)'
)

# SSH log pattern: extract "from <src_ip>" and optionally port
_SSH_FROM = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})')
# Generic "SRC=x.x.x.x DST=y.y.y.y" pattern (iptables/firewall logs)
_SRC_IP  = re.compile(r'(?:SRC=|src=|source[= ])(\d{1,3}(?:\.\d{1,3}){3})')
_DST_IP  = re.compile(r'(?:DST=|dst=|dest(?:ination)?[= ])(\d{1,3}(?:\.\d{1,3}){3})')


def _extract_src_dst(line: str):
    """Best-effort extraction of source and destination IPs from a log line.

    Tries several common log formats in order:
      1. SSH 'from <ip>' pattern (OpenSSH logs)
      2. iptables/firewall 'SRC=x DST=y' pattern
      3. Falls back to first two public IPs found in the line
    """
    # SSH format: "Failed password for root from 1.2.3.4 port 22"
    ssh_match = _SSH_FROM.search(line)
    if ssh_match:
        return ssh_match.group(1), None   # src known, dst is this server (local)

    # Firewall format: "SRC=1.2.3.4 DST=5.6.7.8"
    src_match = _SRC_IP.search(line)
    dst_match = _DST_IP.search(line)
    if src_match or dst_match:
        return (
            src_match.group(1) if src_match else None,
            dst_match.group(1) if dst_match else None,
        )

    # Generic fallback — first two public IPs in the line
    all_ips = [ip for ip in _IPV4.findall(line) if not _PRIVATE.match(ip)]
    src = all_ips[0] if len(all_ips) > 0 else None
    dst = all_ips[1] if len(all_ips) > 1 else None
    return src, dst


def _extract_candidates(line: str) -> List[Dict]:
    candidates = []
    for ip in _IPV4.findall(line):
        if not _PRIVATE.match(ip):
            candidates.append({"type": "ipv4-addr", "value": ip})
    for url in _URL.findall(line):
        candidates.append({"type": "url", "value": url.rstrip('.,;)"\'')})
    for sha in _SHA256.findall(line):
        candidates.append({"type": "file-hash", "value": sha.lower()})
    for md5 in _MD5.findall(line):
        candidates.append({"type": "file-hash", "value": md5.lower()})
    for dom in _DOMAIN.findall(line):
        if '.' in dom and not _PRIVATE.match(dom) and len(dom) > 4:
            candidates.append({"type": "domain-name", "value": dom.lower()})
    return candidates


def _lookup_ioc(value: str) -> Optional[Dict]:
    """Check if a value exists in the IOC database (active IOCs only).

    FIX: Import the whole db_manager module and read DB_PATH from it at
    call-time, not at import-time. This ensures that when the test fixture
    patches app.database.db_manager.DB_PATH (via temp_db), _lookup_ioc
    uses the patched temp path rather than the original hardcoded one.

    The previous code did:
        from app.database.db_manager import create_connection
        conn = create_connection()

    If create_connection() captures DB_PATH at module-load time (or if the
    import caches the function before temp_db patches the attribute), the
    lookup silently reads the wrong (empty) database and returns None for
    every IOC, causing total_hits == 0 even when IOCs are present.
    """
    try:
        import app.database.db_manager as dbm   # ← import the module, not the function
        conn = dbm.create_connection()           # ← read DB_PATH fresh on every call
        row  = conn.execute(
            """SELECT ioc_type, ioc_value, confidence, severity, source, last_seen
               FROM ioc_indicators
               WHERE ioc_value = ? AND is_active = 1 AND revoked = 0""",
            (value,)
        ).fetchone()
        conn.close()
        if row:
            return {
                "ioc_type":   row[0], "ioc_value":  row[1],
                "confidence": row[2], "severity":   row[3],
                "source":     row[4], "last_seen":  row[5],
            }
    except Exception as e:
        logger.debug("IOC lookup error: %s", e)
    return None


def _load_ioc_cache() -> Dict[str, Dict]:
    """
    Load ALL active IOCs from the database into a dict for fast O(1) lookup.
    Called once per scan — avoids opening a DB connection for every log line.
    Returns: {ioc_value: {ioc_type, confidence, severity, source, last_seen}}
    """
    try:
        import app.database.db_manager as dbm
        conn = dbm.create_connection()
        rows = conn.execute(
            """SELECT ioc_type, ioc_value, confidence, severity, source, last_seen
               FROM ioc_indicators WHERE is_active = 1 AND revoked = 0"""
        ).fetchall()
        conn.close()
        return {
            row[1]: {
                "ioc_type":   row[0], "ioc_value":  row[1],
                "confidence": row[2], "severity":   row[3],
                "source":     row[4], "last_seen":  row[5],
            }
            for row in rows
        }
    except Exception as e:
        logger.warning("IOC cache load failed, falling back to per-line lookup: %s", e)
        return {}


def _check_line(line: str, line_number: int, source_file: str,
                ioc_cache: Optional[Dict] = None) -> List[Dict]:
    hits = []
    timestamp = datetime.now(timezone.utc).isoformat()
    candidates = _extract_candidates(line)
    src_ip, dst_ip = _extract_src_dst(line)
    seen = set()
    for candidate in candidates:
        v = candidate["value"]
        if v in seen:
            continue
        seen.add(v)
        # Use cache if available, otherwise fall back to per-line DB lookup
        if ioc_cache is not None:
            match = ioc_cache.get(v)
        else:
            match = _lookup_ioc(v)
        if match:
            hits.append({
                "timestamp":      timestamp,
                "source_file":    source_file,
                "line_number":    line_number,
                "source_ip":      src_ip,
                "destination_ip": dst_ip,
                "log_line":       line.strip()[:300],
                "matched_ioc":    match,
                "severity":       match.get("severity", "unknown"),
                "alert":          True,
            })
            logger.warning("IOC HIT: %s line %d (severity=%s)", v, line_number, match.get("severity", "?"))
    return hits


def check_log_file(filepath: str, max_lines: int = 0) -> Dict:
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}", "hits": [], "total_hits": 0}
    # Load IOC cache once — avoids one DB connection per line
    ioc_cache = _load_ioc_cache()
    logger.info("check_log_file: loaded %d IOCs into cache", len(ioc_cache))
    hits = []
    checked = 0
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, start=1):
                if max_lines and line_num > max_lines:
                    break
                checked += 1
                hits.extend(_check_line(line, line_num, filepath, ioc_cache))
    except Exception as e:
        return {"error": str(e), "hits": hits, "total_hits": len(hits)}
    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for h in hits:
        sev = h.get("severity", "unknown").lower()
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
    return {
        "hits": hits, "lines_checked": checked, "total_hits": len(hits),
        "severity_breakdown": severity_breakdown,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "source_file": filepath,
    }


def stream_log_file(filepath: str, poll_interval: float = 1.0) -> Iterator[Dict]:
    import time
    if not os.path.exists(filepath):
        return
    ioc_cache = _load_ioc_cache()
    line_num = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            line_num += 1
            for hit in _check_line(line, line_num, filepath, ioc_cache):
                yield hit


def check_log_content(content: str, source_name: str = "api-upload") -> Dict:
    # Load IOC cache once — avoids one DB connection per line
    ioc_cache = _load_ioc_cache()
    logger.info("check_log_content: loaded %d IOCs into cache", len(ioc_cache))
    hits = []
    checked = 0
    for line_num, line in enumerate(content.splitlines(), start=1):
        checked += 1
        hits.extend(_check_line(line, line_num, source_name, ioc_cache))
    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for h in hits:
        sev = h.get("severity", "unknown").lower()
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
    return {
        "hits": hits, "lines_checked": checked, "total_hits": len(hits),
        "severity_breakdown": severity_breakdown,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "source_file": source_name,
    }