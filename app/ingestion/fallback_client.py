"""
app/ingestion/fallback_client.py
=================================
Internal IOC Fallback Server — 3rd data source.

Mentor requirement:
  "If live feeds fail, use this internal server as fallback.
   It only gives IPs and domains — no metadata."

Priority in scheduler:
  1. Live TAXII feeds  (taxii_client.py)
  2. ← This file →    (used ONLY if ALL live feeds return 0 results)
  3. Offline folder    (file_watcher.py  — always runs)

Configuration (.env):
  FALLBACK_IOC_URL=http://your-internal-server/api/iocs
  FALLBACK_ENABLED=true
  FALLBACK_API_KEY=          (optional, leave blank if no auth)
  FALLBACK_AUTH=none         (none | api_key | bearer)

Supported response formats from the server:
  Format A — JSON list:
    [
      {"type": "ip",     "value": "1.2.3.4"},
      {"type": "domain", "value": "malware.com"}
    ]

  Format B — Plain text (one IOC per line):
    1.2.3.4
    malware.com
    5.6.7.8
"""
import os
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def _get_config() -> Dict:
    """Read fallback server config from environment variables."""
    return {
        "enabled":  os.getenv("FALLBACK_ENABLED", "true").lower() == "true",
        "url":      os.getenv("FALLBACK_IOC_URL", "").strip(),
        "api_key":  os.getenv("FALLBACK_API_KEY", "").strip(),
        "auth":     os.getenv("FALLBACK_AUTH", "none").strip().lower(),
    }


def _build_headers(cfg: Dict) -> Dict:
    """Build HTTP headers based on auth type."""
    headers = {"Accept": "application/json, text/plain"}
    if cfg["auth"] == "api_key" and cfg["api_key"]:
        headers["X-API-Key"] = cfg["api_key"]
    elif cfg["auth"] == "bearer" and cfg["api_key"]:
        headers["Authorization"] = f"Bearer {cfg['api_key']}"
    return headers


def _parse_response(response_text: str, content_type: str) -> List[Dict]:
    """
    Parse the fallback server response into a list of normalized IOC dicts.

    Handles:
      - JSON list of {"type": ..., "value": ...}
      - Plain text with one IP/domain per line
    """
    import re
    iocs = []

    # ── Try JSON first ────────────────────────────────────────────
    if "json" in content_type.lower():
        try:
            import json
            data = json.loads(response_text)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        value = (item.get("value") or item.get("ioc") or
                                 item.get("indicator") or "").strip()
                        ioc_type = (item.get("type") or item.get("ioc_type") or "").strip().lower()
                        if value:
                            iocs.append(_make_ioc(value, ioc_type))
            elif isinstance(data, dict) and "iocs" in data:
                # Handle {"iocs": [...]} wrapper
                for item in data["iocs"]:
                    value = str(item).strip() if isinstance(item, str) else \
                            item.get("value", "").strip()
                    if value:
                        iocs.append(_make_ioc(value, ""))
            return iocs
        except Exception as e:
            logger.warning("Fallback: JSON parse failed, trying plain text: %s", e)

    # ── Plain text fallback — one IOC per line ────────────────────
    ip_pattern     = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
    domain_pattern = re.compile(
        r'^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+$'
    )

    for line in response_text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):   # skip empty lines and comments
            continue
        if ip_pattern.match(value):
            iocs.append(_make_ioc(value, "ipv4-addr"))
        elif domain_pattern.match(value):
            iocs.append(_make_ioc(value, "domain-name"))

    return iocs


def _make_ioc(value: str, ioc_type: str) -> Dict:
    """
    Build a normalized IOC dict from a bare value.
    Since the fallback server has no metadata, we set conservative defaults.
    """
    import re
    # Auto-detect type if not provided
    if not ioc_type:
        if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', value):
            ioc_type = "ipv4-addr"
        elif re.match(r'^[a-fA-F0-9]{32}$', value):
            ioc_type = "md5-hash"
        elif re.match(r'^[a-fA-F0-9]{64}$', value):
            ioc_type = "sha256-hash"
        elif value.startswith("http"):
            ioc_type = "url"
        else:
            ioc_type = "domain-name"

    return {
        "stix_id":    f"fallback--{uuid.uuid4()}",
        "ioc_type":   ioc_type,
        "ioc_value":  value,
        "confidence": 50,           # conservative — no metadata available
        "severity":   "medium",     # default — no metadata available
        "source":     "fallback_server",
        "description": "Sourced from internal fallback IOC server (no metadata)",
        # All metadata fields are None — mentor said server has no metadata
        "country":    None,
        "tags":       None,
        "kill_chain": None,
        "revoked":    False,
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "last_seen":  datetime.now(timezone.utc).isoformat(),
    }


def fetch_and_store() -> Dict:
    """
    Main entry point — called by the scheduler when ALL live feeds fail.

    Fetches IOCs from the internal fallback server and stores them in DB.
    Returns a summary dict.
    """
    import requests
    from app.database.db_manager import insert_indicators

    cfg = _get_config()

    if not cfg["enabled"]:
        logger.debug("Fallback client disabled (FALLBACK_ENABLED=false)")
        return {"enabled": False, "stored": 0}

    if not cfg["url"]:
        logger.warning("Fallback client: FALLBACK_IOC_URL is not set in .env")
        return {"enabled": True, "error": "FALLBACK_IOC_URL not configured", "stored": 0}

    logger.info("Fallback client: fetching from '%s'", cfg["url"])

    try:
        response = requests.get(
            cfg["url"],
            headers=_build_headers(cfg),
            timeout=15,
        )
        response.raise_for_status()

        content_type = response.headers.get("Content-Type", "")
        iocs = _parse_response(response.text, content_type)

        if not iocs:
            logger.warning("Fallback client: server returned 0 parseable IOCs")
            return {
                "enabled":       True,
                "url":           cfg["url"],
                "http_status":   response.status_code,
                "iocs_fetched":  0,
                "stored":        0,
                "duplicates":    0,
            }

        result = insert_indicators(iocs, source_label="fallback_server")

        logger.info(
            "Fallback client: fetched=%d stored=%d duplicates=%d",
            len(iocs), result.get("stored", 0), result.get("duplicates", 0),
        )

        return {
            "enabled":       True,
            "url":           cfg["url"],
            "http_status":   response.status_code,
            "iocs_fetched":  len(iocs),
            "stored":        result.get("stored", 0),
            "duplicates":    result.get("duplicates", 0),
            "fetched_at":    datetime.now(timezone.utc).isoformat(),
        }

    except requests.exceptions.ConnectionError:
        logger.warning("Fallback client: cannot reach '%s' (server offline?)", cfg["url"])
        return {"enabled": True, "url": cfg["url"], "error": "Connection refused", "stored": 0}
    except requests.exceptions.Timeout:
        logger.warning("Fallback client: request to '%s' timed out", cfg["url"])
        return {"enabled": True, "url": cfg["url"], "error": "Timeout", "stored": 0}
    except Exception as e:
        logger.error("Fallback client: unexpected error: %s", e)
        return {"enabled": True, "url": cfg["url"], "error": str(e), "stored": 0}
