"""
app/ingestion/scheduler.py
APScheduler background scheduler — runs MultiFeedIngester every 30 minutes.
Singleton pattern: one instance shared across the whole app.
"""
import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR

logger = logging.getLogger(__name__)

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
            self.last_run    = datetime.utcnow().isoformat()
            self.total_runs += 1
            self.last_result = result
            logger.info("Scheduler run #%d: stored=%d", self.total_runs,
                        result.get("total_stored", 0))
        except Exception as e:
            logger.error("Scheduler job failed: %s", e)

    def start(self, interval_minutes=30):
        if self.is_running:
            return
        self.scheduler.add_job(self._job, "interval",
                                minutes=interval_minutes, id="taxii_ingest",
                                max_instances=1, misfire_grace_time=60)
        self.scheduler.start()
        self.is_running = True
        logger.info("Scheduler started — interval=%d min", interval_minutes)

    def stop(self):
        if self.is_running:
            self.scheduler.shutdown(wait=False)
            self.is_running = False

    def trigger_now(self):
        """Manually trigger ingestion without waiting for the interval."""
        self.scheduler.add_job(self._job, id="manual_trigger",
                                replace_existing=True)

    def status(self):
        next_run = None
        try:
            job = self.scheduler.get_job("taxii_ingest")
            if job:
                next_run = str(job.next_run_time)
        except Exception:
            pass
        return {
            "is_running":  self.is_running,
            "total_runs":  self.total_runs,
            "last_run":    self.last_run,
            "next_run":    next_run,
            "last_result": self.last_result,
            "feeds":       [f["name"] for f in __import__(
                            "app.ingestion.taxii_client", fromlist=["get_configured_feeds"]
                            ).get_configured_feeds()],
        }


# Singleton
scheduler = IngestionScheduler()


# ─── Backward-compatibility functions ─────────────────────────────────────────
# app/ingestion/__init__.py and app/api/main.py import these names.

def start_scheduler(interval_minutes: int = 30):
    """Start the background ingestion scheduler."""
    scheduler.start(interval_minutes=interval_minutes)


def get_scheduler_status() -> dict:
    """Return scheduler status dict."""
    return scheduler.status()


def trigger_ingestion_now():
    """Manually trigger an ingestion run immediately."""
    scheduler.trigger_now()


def get_public_servers() -> list:
    """
    Return list of pre-configured public TAXII servers.
    Delegates to taxii_client where the list lives.
    Called by app/ingestion/__init__.py and the /ingest/servers API endpoint.
    """
    from app.ingestion.taxii_client import PUBLIC_SERVERS
    return PUBLIC_SERVERS