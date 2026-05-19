import logging
from datetime import datetime, timezone
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)


# ── IOC → Event converter ─────────────────────────────────────────────────────

def ioc_to_event(ioc: dict, feed_name: str = "taxii") -> dict:
    """
    Convert a normalised IOC dict (from stix_parser) into an event dict
    compatible with extract_features() in detector.py.

    Field mapping
    -------------
    ioc_value  -> source_ip       (if ipv4-addr) or left blank
    ioc_type   -> used to set protocol and port hints
    confidence -> risk_score (0-100 scale)
    stix_id    -> event_id  (unique per IOC so IGNORE duplicate inserts work)

    The produced dict satisfies every field that extract_features() reads:
      destination_port, source_port, protocol, source_ip, destination_ip,
      timestamp, ioc_match_count, risk_score, event_id
    """
    ioc_type   = ioc.get("ioc_type", "unknown")
    ioc_value  = ioc.get("ioc_value", "")
    stix_id    = ioc.get("stix_id") or f"ioc-{ioc_value}"
    confidence = int(ioc.get("confidence", 50))

    # Map IOC type to reasonable port/protocol hints so feature extraction
    # produces meaningful numbers instead of all-zeros
    type_hints = {
        "ipv4-addr":   {"destination_port": 0,   "protocol": "TCP"},
        "domain-name": {"destination_port": 53,  "protocol": "UDP"},
        "url":         {"destination_port": 443, "protocol": "TCP"},
        "file-hash":   {"destination_port": 0,   "protocol": ""},
        "email-addr":  {"destination_port": 25,  "protocol": "TCP"},
    }
    hints = type_hints.get(ioc_type, {"destination_port": 0, "protocol": ""})

    # Use ioc_value as source_ip only when it really is an IPv4 address
    source_ip = ioc_value if ioc_type == "ipv4-addr" else "0.0.0.0"

    return {
        "event_id":         stix_id,
        "source_ip":        source_ip,
        "destination_ip":   "0.0.0.0",
        "source_port":      0,
        "destination_port": hints["destination_port"],
        "protocol":         hints["protocol"],
        "timestamp":        ioc.get("first_seen") or datetime.now(timezone.utc).isoformat(),
        "ioc_match_count":  1,           # it IS an IOC, so count = 1
        "risk_score":       confidence,  # confidence maps directly to risk
        "ioc_origin":       True,        # flag for downstream filtering
    }


# ── ML bridge ─────────────────────────────────────────────────────────────────

def _feed_iocs_to_ml(iocs: list, feed_name: str) -> int:
    """
    Pass each IOC through get_detector().analyze() so ml_events is populated.
    Returns the number of IOCs successfully analysed.

    Intentionally non-fatal: if ML models are unavailable the scheduler job
    continues normally and only logs a warning.
    """
    if not iocs:
        return 0

    analysed = 0
    try:
        from app.ml.detector import get_detector
        detector = get_detector()
        for ioc in iocs:
            try:
                event = ioc_to_event(ioc, feed_name)
                detector.analyze(event)
                analysed += 1
            except Exception as e:
                logger.debug("ML feed skipped for IOC %s: %s",
                             ioc.get("ioc_value", "?"), e)
        logger.info("ML bridge: %d/%d IOCs fed to detector from feed '%s'",
                    analysed, len(iocs), feed_name)
    except ImportError:
        logger.warning("ML bridge: scikit-learn not installed — skipping ML feed")
    except Exception as e:
        logger.warning("ML bridge failed (non-fatal): %s", e)

    return analysed


# ── Scheduler ─────────────────────────────────────────────────────────────────

class IngestionScheduler:
    def __init__(self):
        self.scheduler   = BackgroundScheduler()
        self.is_running  = False
        self.last_run    = None
        self.total_runs  = 0
        self.last_result = None

    def _job(self):
        try:
            from app.ingestion.taxii_client import MultiFeedIngester
            result = MultiFeedIngester().ingest_all(delta_hours=24)

            self.last_run    = datetime.now(timezone.utc).isoformat()
            self.total_runs += 1
            self.last_result = result

            # ── Priority 2: Fallback IOC server ──────────────────────────────
            # Triggered ONLY when ALL live TAXII feeds stored 0 IOCs.
            # "If live feeds fail, use internal server as fallback."
            try:
                live_stored = result.get("total_stored", 0)
                if live_stored == 0:
                    logger.info(
                        "Live feeds returned 0 IOCs — trying fallback server..."
                    )
                    from app.ingestion.fallback_client import fetch_and_store
                    fallback_result = fetch_and_store()
                    self.last_result["fallback"] = fallback_result
                    if fallback_result.get("stored", 0) > 0:
                        logger.info(
                            "Fallback server: stored %d IOCs",
                            fallback_result["stored"],
                        )
                    else:
                        logger.warning(
                            "Fallback server also returned 0 IOCs. Error: %s",
                            fallback_result.get("error", "none"),
                        )
                else:
                    self.last_result["fallback"] = {"skipped": True,
                                                    "reason": "live feeds succeeded"}
            except Exception as e:
                logger.warning("Fallback client failed (non-fatal): %s", e)

            #  expire outdated IOCs after every run
            try:
                from app.ingestion.ioc_manager import expire_outdated_iocs
                expiry = expire_outdated_iocs(max_age_days=30)
                self.last_result["expired_iocs"] = expiry
                logger.info("IOC expiry: %s", expiry)
            except Exception as e:
                logger.warning("IOC expiry failed (non-fatal): %s", e)

            # check offline IOC watch folder every cycle
            try:
                from app.ingestion.file_watcher import process_watch_folder
                watch_result = process_watch_folder()
                self.last_result["file_watcher"] = {
                    "files_found":     watch_result.get("files_found", 0),
                    "files_processed": watch_result.get("files_processed", 0),
                    "total_stored":    watch_result.get("total_stored", 0),
                }
                if watch_result.get("files_found", 0) > 0:
                    logger.info(
                        "File watcher: found=%d processed=%d stored=%d",
                        watch_result.get("files_found", 0),
                        watch_result.get("files_processed", 0),
                        watch_result.get("total_stored", 0),
                    )
            except Exception as e:
                logger.warning("File watcher failed (non-fatal): %s", e)

            # scan log files for IOC matches every cycle
            try:
                from app.ingestion.log_watcher import scan_configured_logs
                log_result = scan_configured_logs()
                self.last_result["log_watcher"] = {
                    "files_scanned": log_result.get("files_scanned", 0),
                    "total_hits":    log_result.get("total_hits", 0),
                    "saved_to_db":   log_result.get("saved_to_db", 0),
                }
                if log_result.get("total_hits", 0) > 0:
                    logger.info(
                        "Log watcher: scanned=%d files, hits=%d, saved=%d",
                        log_result.get("files_scanned", 0),
                        log_result.get("total_hits", 0),
                        log_result.get("saved_to_db", 0),
                    )
            except Exception as e:
                logger.warning("Log watcher failed (non-fatal): %s", e)

            # feed stored IOCs into the ML pipeline
            # Re-fetch the same delta window and pass every parsed IOC through
            # the anomaly detector so ml_events grows without manual API calls.
            try:
                from app.normalization.stix_parser import parse_stix_bundle
                from app.ingestion.taxii_client import TAXIIFeedClient, get_configured_feeds
                from datetime import timezone, timedelta

                total_ml  = 0
                added_after = datetime.now(timezone.utc) - timedelta(hours=24)

                for cfg in get_configured_feeds():
                    feed_result = result.get("feeds", {}).get(cfg["name"], {})
                    if feed_result.get("stored", 0) > 0:
                        raw    = TAXIIFeedClient(cfg).fetch_all(added_after)
                        parsed = parse_stix_bundle({"objects": raw})
                        for ioc in parsed:
                            ioc["source"] = cfg["name"]
                        total_ml += _feed_iocs_to_ml(parsed, cfg["name"])

                self.last_result["ml_events_added"] = total_ml
                logger.info("Scheduler run #%d: stored=%d ml_fed=%d",
                            self.total_runs,
                            result.get("total_stored", 0),
                            total_ml)
            except Exception as e:
                logger.warning("ML pipeline feed failed (non-fatal): %s", e)
                logger.info("Scheduler run #%d: stored=%d",
                            self.total_runs, result.get("total_stored", 0))

        except Exception as e:
            logger.error("Scheduler job failed: %s", e)

    def start(self, interval_minutes=30):
        if self.is_running:
            return
        self.scheduler.add_job(
            self._job, "interval",
            minutes=interval_minutes, id="taxii_ingest",
            max_instances=1, misfire_grace_time=60,
        )
        self.scheduler.start()
        self.is_running = True
        logger.info("Scheduler started — interval=%d min", interval_minutes)

    def stop(self):
        if self.is_running:
            self.scheduler.shutdown(wait=False)
            self.is_running = False

    def trigger_now(self):
        self.scheduler.add_job(self._job, id="manual_trigger", replace_existing=True)

    def status(self):
        next_run = None
        try:
            job = self.scheduler.get_job("taxii_ingest")
            if job:
                next_run = str(job.next_run_time)
        except Exception:
            pass
        from app.ingestion.taxii_client import get_configured_feeds
        return {
            "is_running":  self.is_running,
            "total_runs":  self.total_runs,
            "last_run":    self.last_run,
            "next_run":    next_run,
            "last_result": self.last_result,
            "feeds": [f["name"] for f in get_configured_feeds()],
        }


scheduler = IngestionScheduler()


def start_scheduler(interval_minutes: int = 30):
    scheduler.start(interval_minutes=interval_minutes)

def get_scheduler_status() -> dict:
    return scheduler.status()

def trigger_ingestion_now():
    scheduler.trigger_now()

def get_public_servers() -> list:
    from app.ingestion.taxii_client import PUBLIC_SERVERS
    return PUBLIC_SERVERS