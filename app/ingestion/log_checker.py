"""
app/ingestion/log_checker.py
=============================
Mentor requirement: check a given log file (offline) or log stream (online)
against stored IOCs and report/alert if found, along with timestamps.

This bridges Module 1 (IOC Pipeline) and the real-world use case of
checking existing log files against the threat intelligence database.

Supports:
  - Offline: read a log file line by line
  - Online:  tail a live log file (generator-based streaming)
  - Both:    extract IPs, domains, URLs, hashes from each log line
             and correlate against stored IOCs

Usage:
    # Offline — check a log file
    from app.ingestion.log_checker import check_log_file
    results = check_log_file("/var/log/nginx/access.log")
    for hit in results["hits"]:
        print(hit)

    # Online — tail a live log
    from app.ingestion.log_checker import stream_log_file
    for alert in stream_log_file("/var/log/syslog"):
        print(alert)

    # API:  POST /logs/check  (offline)
    #       GET  /logs/stream (online — Server-Sent Events)
"""
import re
import os
import logging
from datetime import datetime, timezone
from typing import Iterator, List, Dict, Optional

logger = logging.getLogger(__name__)

# ── Regex patterns to extract IOC candidates from log lines ──────────────────
_IPV4    = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_DOMAIN  = re.compile(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
                      r'(?:\.[a-zA-Z]{2,})+)\b')
_URL     = re.compile(r'https?://[^\s\'"<>]+')
_MD5     = re.compile(r'\b([a-fA-F0-9]{32})\b')
_SHA256  = re.compile(r'\b([a-fA-F0-9]{64})\b')

# Private/loopback IPs — never match these against IOCs
_PRIVATE = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|::1|localhost)'
)


def _extract_candidates(line: str) -> List[Dict]:
    """Extract all IOC candidates (IPs, domains, URLs, hashes) from one log line."""
    candidates = []

    for ip in _IPV4.findall(line):
        if not _PRIVATE.match(ip):
            candidates.append({"type": "ipv4-addr", "value": ip})

    for url in _URL.findall(line):
        candidates.append({"type": "url", "value": url.rstrip('.,;)"\'')} )

    for sha in _SHA256.findall(line):
        candidates.append({"type": "file-hash", "value": sha.lower()})

    for md5 in _MD5.findall(line):
        candidates.append({"type": "file-hash", "value": md5.lower()})

    for dom in _DOMAIN.findall(line):
        if '.' in dom and not _PRIVATE.match(dom) and len(dom) > 4:
            candidates.append({"type": "domain-name", "value": dom.lower()})

    return candidates


def _lookup_ioc(value: str) -> Optional[Dict]:
    """Check if a value exists in the IOC database (active IOCs only)."""
    try:
        import sqlite3, sys as _sys
        # Read DB_PATH fresh from sys.modules so monkeypatch works in tests
        _dbm = _sys.modules.get("app.database.db_manager")
        db = (getattr(_dbm, "DB_PATH", None) if _dbm else None) or "database/threat_intel.db"
        conn = sqlite3.connect(db)
        row  = conn.execute(
            """SELECT ioc_type, ioc_value, confidence, severity, source, last_seen
               FROM ioc_indicators
               WHERE ioc_value = ? AND is_active = 1""",
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


def _check_line(line: str, line_number: int, source_file: str) -> List[Dict]:
    """Check a single log line against all stored IOCs. Returns list of hits."""
    hits = []
    timestamp = datetime.now(timezone.utc).isoformat()
    candidates = _extract_candidates(line)

    seen = set()  # deduplicate candidates in same line
    for candidate in candidates:
        v = candidate["value"]
        if v in seen:
            continue
        seen.add(v)

        match = _lookup_ioc(v)
        if match:
            hits.append({
                "timestamp":   timestamp,
                "source_file": source_file,
                "line_number": line_number,
                "log_line":    line.strip()[:300],  # truncate long lines
                "matched_ioc": match,
                "severity":    match.get("severity", "unknown"),
                "alert":       True,
            })
            logger.warning(
                "IOC HIT: %s found in %s line %d (severity=%s)",
                v, source_file, line_number, match.get("severity","?")
            )

    return hits


# ── Offline: check a complete log file ────────────────────────────────────────

def check_log_file(filepath: str, max_lines: int = 0) -> Dict:
    """
    Check an entire log file against stored IOCs.

    Parameters
    ----------
    filepath : str
        Path to the log file (any text format — access log, syslog, CSV, etc.)
    max_lines : int
        If > 0, only check the first N lines. 0 = check all lines.

    Returns
    -------
    dict with:
        hits       : list of matches with timestamps and IOC details
        lines_checked : int
        total_hits    : int
        severity_breakdown : {"critical": N, "high": N, ...}
        checked_at    : ISO timestamp
    """
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}", "hits": [], "total_hits": 0}

    hits    = []
    checked = 0

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, start=1):
                if max_lines and line_num > max_lines:
                    break
                checked += 1
                hits.extend(_check_line(line, line_num, filepath))
    except Exception as e:
        logger.error("check_log_file failed: %s", e)
        return {"error": str(e), "hits": hits, "total_hits": len(hits)}

    severity_breakdown = {"critical":0,"high":0,"medium":0,"low":0,"unknown":0}
    for h in hits:
        sev = h.get("severity","unknown").lower()
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    return {
        "hits":               hits,
        "lines_checked":      checked,
        "total_hits":         len(hits),
        "severity_breakdown": severity_breakdown,
        "checked_at":         datetime.now(timezone.utc).isoformat(),
        "source_file":        filepath,
    }


# ── Online: stream a live log file ────────────────────────────────────────────

def stream_log_file(filepath: str, poll_interval: float = 1.0) -> Iterator[Dict]:
    """
    Tail a live log file and yield IOC matches as they appear.
    Runs indefinitely — use in a background thread or async context.

    Parameters
    ----------
    filepath     : str   Path to the log file
    poll_interval: float Seconds between polls when no new lines (default 1s)

    Yields
    ------
    dict — same structure as a single hit from check_log_file
    """
    import time

    if not os.path.exists(filepath):
        logger.error("stream_log_file: file not found: %s", filepath)
        return

    line_num = 0
    logger.info("Streaming log file: %s", filepath)

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        # Seek to end so we only see new lines
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            line_num += 1
            for hit in _check_line(line, line_num, filepath):
                yield hit


# ── Check log content string (for API endpoint) ───────────────────────────────

def check_log_content(content: str, source_name: str = "api-upload") -> Dict:
    """
    Check log content provided as a string (e.g. uploaded via API).
    Returns same structure as check_log_file.
    """
    hits    = []
    checked = 0

    for line_num, line in enumerate(content.splitlines(), start=1):
        checked += 1
        hits.extend(_check_line(line, line_num, source_name))

    severity_breakdown = {"critical":0,"high":0,"medium":0,"low":0,"unknown":0}
    for h in hits:
        sev = h.get("severity","unknown").lower()
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    return {
        "hits":               hits,
        "lines_checked":      checked,
        "total_hits":         len(hits),
        "severity_breakdown": severity_breakdown,
        "checked_at":         datetime.now(timezone.utc).isoformat(),
        "source_file":        source_name,
    }