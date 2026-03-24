"""
app/ingestion/taxii_client.py
==============================
Live multi-feed TAXII 2.x client using taxii2client (NOT cabby).
Mentor requirement: use live data instead of static files.
"""
import os, logging, time, sqlite3
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


def get_configured_feeds() -> List[Dict[str, Any]]:
    feeds, i = [], 1
    while True:
        name = os.getenv(f"FEED_{i}_NAME")
        if not name:
            break
        url = os.getenv(f"FEED_{i}_URL", "")
        if url and os.getenv(f"FEED_{i}_ENABLED", "true").lower() == "true":
            feeds.append({
                "name": name, "url": url,
                "auth_type": os.getenv(f"FEED_{i}_AUTH", "none").lower(),
                "api_key":   os.getenv(f"FEED_{i}_API_KEY", ""),
                "username":  os.getenv(f"FEED_{i}_USERNAME", ""),
                "password":  os.getenv(f"FEED_{i}_PASSWORD", ""),
            })
        i += 1
    if not feeds:
        otx_url = os.getenv("TAXII_SERVER_URL", "https://otx.alienvault.com/taxii/taxii2/")
        otx_key = os.getenv("OTX_API_KEY", os.getenv("TAXII_API_KEY", ""))
        feeds.append({
            "name": "AlienVault OTX", "url": otx_url,
            "auth_type": "api_key" if otx_key else "none",
            "api_key": otx_key, "username": "", "password": "",
        })
    return feeds


class TAXIIFeedClient:
    """Client for one TAXII 2.1 server. Uses taxii2-client, NOT cabby."""
    def __init__(self, cfg):
        self.name      = cfg["name"]
        self.url       = cfg["url"].rstrip("/") + "/"
        self.auth_type = cfg.get("auth_type", "none")
        self.api_key   = cfg.get("api_key", "")
        self.username  = cfg.get("username", "")
        self.password  = cfg.get("password", "")

    def _session(self):
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        s = requests.Session()
        s.headers["Accept"] = "application/taxii+json;version=2.1"
        if self.auth_type == "api_key" and self.api_key:
            s.headers["X-OTX-API-KEY"] = self.api_key
        elif self.auth_type == "basic" and self.username:
            s.auth = (self.username, self.password)
        r = Retry(total=3, backoff_factor=2, status_forcelist=[429,500,502,503,504])
        s.mount("https://", HTTPAdapter(max_retries=r))
        return s

    def fetch_all(self, added_after=None, max_per=2000):
        try:
            from taxii2client.v21 import Server
        except ImportError:
            logger.error("taxii2-client not installed: pip install taxii2-client")
            return []
        results = []
        try:
            srv = Server(self.url, session=self._session())
            for root in srv.api_roots:
                for col in root.collections:
                    try:
                        kw = {"limit": max_per}
                        if added_after:
                            kw["added_after"] = added_after.strftime("%Y-%m-%dT%H:%M:%SZ")
                        bundle = col.get_objects(**kw)
                        inds   = [o for o in bundle.get("objects", []) if o.get("type") == "indicator"]
                        results.extend(inds)
                        logger.info("[%s] col=%s fetched=%d", self.name, col.id[:8], len(inds))
                        time.sleep(0.3)
                    except Exception as e:
                        logger.warning("[%s] col %s: %s", self.name, col.id, e)
        except Exception as e:
            logger.error("[%s] connect failed: %s", self.name, e)
        return results


class MultiFeedIngester:
    """Ingests from ALL configured feeds. Called by scheduler every 30 min."""
    def __init__(self):
        self.feeds = get_configured_feeds()
        logger.info("Feeds: %s", [f["name"] for f in self.feeds])

    def ingest_all(self, delta_hours=24):
        from app.normalization.stix_parser import parse_stix_bundle
        import app.database.db_manager as _dbm

        added_after = (datetime.now(timezone.utc) - timedelta(hours=delta_hours)
                       if delta_hours > 0 else None)
        totals  = {"total_fetched":0,"total_stored":0,"total_duplicates":0,"feeds":{},"errors":[]}
        started = datetime.now(timezone.utc)

        _insert = getattr(_dbm, "insert_indicators", None) or getattr(_dbm, "insert_ioc", None)
        _log    = getattr(_dbm, "log_ingestion", None) or getattr(_dbm, "log_ingestion_run", None)
        db_path = getattr(_dbm, "DB_PATH", "database/threat_intel.db")

        for cfg in self.feeds:
            name = cfg["name"]
            res  = {"fetched":0,"stored":0,"duplicates":0,"status":"ok","error":None}
            try:
                raw  = TAXIIFeedClient(cfg).fetch_all(added_after)
                res["fetched"] = len(raw)
                iocs = parse_stix_bundle({"objects": raw})
                for ioc in iocs:
                    ioc["source"] = name

                # Use direct INSERT OR IGNORE + rowcount for reliable dedup tracking.
                # ioc_indicators has UNIQUE constraint on ioc_value.
                # rowcount=1 → new row inserted; rowcount=0 → duplicate ignored.
                now = datetime.now(timezone.utc).isoformat()
                for ioc in iocs:
                    ioc_value = ioc.get("ioc_value", "")
                    if not ioc_value:
                        continue
                    try:
                        conn = sqlite3.connect(db_path)
                        cur  = conn.execute(
                            """INSERT OR IGNORE INTO ioc_indicators
                               (stix_id, ioc_type, ioc_subtype, ioc_value,
                                confidence, source, first_seen, last_seen)
                               VALUES (?,?,?,?,?,?,?,?)""",
                            (ioc.get("stix_id",""), ioc.get("ioc_type","unknown"),
                             ioc.get("ioc_subtype",""), ioc_value,
                             ioc.get("confidence",50), ioc.get("source", name),
                             now, now)
                        )
                        conn.commit()
                        if cur.rowcount == 1:
                            res["stored"] += 1
                        else:
                            res["duplicates"] += 1
                        conn.close()
                    except Exception as e:
                        res["duplicates"] += 1
                        logger.debug("IOC insert (likely duplicate): %s", e)

                # Also call the original insert_indicators for ingestion_log tracking
                if iocs and _insert:
                    try:
                        _insert(iocs)
                    except Exception:
                        pass

            except Exception as e:
                res["status"] = "error"; res["error"] = str(e)
                totals["errors"].append(f"{name}: {e}")

            totals["total_fetched"]    += res["fetched"]
            totals["total_stored"]     += res["stored"]
            totals["total_duplicates"] += res["duplicates"]
            totals["feeds"][name]       = res

            if _log:
                try:
                    _log(source=name, status=res["status"],
                         total_fetched=res["fetched"], total_stored=res["stored"],
                         error_message=res.get("error"))
                except Exception:
                    pass

        totals["elapsed_seconds"] = round(
            (datetime.now(timezone.utc) - started).total_seconds(), 2)
        return totals


# ─── Backward-compatibility aliases ───────────────────────────────────────────
TAXIIClient = TAXIIFeedClient

PUBLIC_SERVERS = [
    {"name": "AlienVault OTX",
     "url": "https://otx.alienvault.com/taxii/taxii2/",
     "auth_type": "api_key",
     "description": "Open Threat Exchange — free, requires API key",
     "requires_auth": True},
    {"name": "CISA AIS",
     "url": "https://ais2.cisa.dhs.gov/taxii2/",
     "auth_type": "none",
     "description": "US Cybersecurity and Infrastructure Security Agency",
     "requires_auth": False},
    {"name": "Anomali Limo",
     "url": "https://limo.anomali.com/api/v1/taxii2/feeds/",
     "auth_type": "basic",
     "description": "Anomali free tier (guest/guest)",
     "requires_auth": True},
]

def get_public_servers():
    return PUBLIC_SERVERS

def ingest_all_public_feeds(delta_hours: int = 24):
    return MultiFeedIngester().ingest_all(delta_hours=delta_hours)
