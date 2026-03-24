"""
app/ingestion/scheduler.py
APScheduler background scheduler — runs MultiFeedIngester every 30 minutes.
Also runs IOC expiry cleanup after each ingestion.
"""
import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

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

            # Mentor requirement: handle outdated IOCs after every ingestion
            try:
                from app.ingestion.ioc_manager import expire_outdated_iocs
                expiry = expire_outdated_iocs(max_age_days=30)
                self.last_result["expired_iocs"] = expiry
                logger.info("IOC expiry: %s", expiry)
            except Exception as e:
                logger.warning("IOC expiry failed (non-fatal): %s", e)

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
        self.scheduler.add_job(self._job, id="manual_trigger", replace_existing=True)

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
