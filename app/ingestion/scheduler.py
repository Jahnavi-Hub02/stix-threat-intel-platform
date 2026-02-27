"""
APScheduler for Automated TAXII Ingestion
==========================================

Runs TAXII ingestion in a background thread every 30 minutes.
- Prevents overlapping runs with max_instances=1
- Coalesces missed runs with coalesce=True
- Keeps last 50 run results in memory for status API
- Provides manual trigger capability

Usage:
    from app.ingestion.scheduler import scheduler, start_scheduler
    
    # Start scheduler on app startup
    start_scheduler()
    
    # Get status
    status = scheduler.get_status()
    
    # Trigger now
    scheduler.trigger_now()
"""

from datetime import datetime, timezone
from collections import deque
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from app.ingestion.taxii_client import TAXIIClient, PUBLIC_SERVERS
from app.utils.logger import get_logger
from app.database.db_manager import create_connection

logger = get_logger(__name__)


class TAXIIScheduler:
    """Background scheduler for TAXII ingestion."""

    def __init__(self):
        self.scheduler = BackgroundScheduler(daemon=True)
        self.run_history = deque(maxlen=50)  # Keep last 50 run results
        self.is_running = False
        self.ingest_job_id = None

    def start(self, interval_minutes: int = 30):
        """Start the background scheduler."""
        try:
            # Add TAXII ingestion job
            self.ingest_job_id = self.scheduler.add_job(
                func=self._run_taxii_ingestion,
                trigger=IntervalTrigger(minutes=interval_minutes),
                id="taxii_ingest",
                name="TAXII Ingestion",
                max_instances=1,  # Prevent overlapping
                coalesce=True,    # Only catch up once if missed
                replace_existing=True,
            )

            self.scheduler.start()
            self.is_running = True

            next_run = self.ingest_job_id.next_run_time
            logger.info(
                "Scheduler started",
                interval_minutes=interval_minutes,
                next_run=next_run,
            )

            return {
                "status": "started",
                "next_run": next_run.isoformat() if next_run else None,
            }

        except Exception as e:
            logger.error("Failed to start scheduler", error=str(e))
            raise

    def stop(self):
        """Stop the background scheduler."""
        try:
            self.scheduler.shutdown()
            self.is_running = False
            logger.info("Scheduler stopped")
        except Exception as e:
            logger.error("Failed to stop scheduler", error=str(e))

    def trigger_now(self):
        """Manually trigger ingestion immediately."""
        try:
            logger.info("Triggering ingestion manually")
            result = self._run_taxii_ingestion()
            logger.info("Manual ingestion triggered", result=result)
            return result
        except Exception as e:
            logger.error("Failed to trigger ingestion", error=str(e))
            raise

    def _run_taxii_ingestion(self):
        """Run TAXII ingestion from pre-configured servers."""
        run_info = {
            "timestamp": datetime.now(timezone.utc),
            "servers": [],
        }

        try:
            total_fetched = 0
            total_stored = 0
            total_duplicates = 0

            # Ingest from each public server
            for server_key, server_config in PUBLIC_SERVERS.items():
                try:
                    logger.info("Ingesting from server", server=server_key)

                    client = TAXIIClient(
                        server_url=server_config["url"],
                        username=server_config.get("username"),
                        password=server_config.get("password"),
                    )

                    result = client.ingest_all_collections(
                        use_delta=True, max_objects_per_collection=500
                    )

                    total_fetched += result.get("total_fetched", 0)
                    total_stored += result.get("total_stored", 0)
                    total_duplicates += result.get("duplicates", 0)

                    server_result = {
                        "name": server_key,
                        "status": "success",
                        "fetched": result.get("total_fetched", 0),
                        "stored": result.get("total_stored", 0),
                        "duplicates": result.get("duplicates", 0),
                    }

                    logger.info(
                        "Server ingestion complete",
                        server=server_key,
                        stored=result.get("total_stored"),
                    )

                except Exception as e:
                    logger.error("Server ingestion failed", server=server_key, error=str(e))
                    server_result = {
                        "name": server_key,
                        "status": "failed",
                        "error": str(e),
                    }

                run_info["servers"].append(server_result)

            # Log to database
            self._log_ingestion_to_db(
                total_fetched, total_stored, total_duplicates, "success"
            )

            run_info["status"] = "success"
            run_info["total_fetched"] = total_fetched
            run_info["total_stored"] = total_stored
            run_info["total_duplicates"] = total_duplicates

        except Exception as e:
            logger.error("TAXII ingestion error", error=str(e))
            self._log_ingestion_to_db(0, 0, 0, "failed", str(e))
            run_info["status"] = "failed"
            run_info["error"] = str(e)

        # Add to history
        self.run_history.append(run_info)

        logger.info("Ingestion run complete", status=run_info.get("status"))
        return run_info

    def _log_ingestion_to_db(
        self,
        total_fetched: int,
        total_stored: int,
        total_duplicates: int,
        status: str,
        error_message: str = None,
    ):
        """Log ingestion run to database."""
        try:
            conn = create_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO ingestion_logs
                (source_url, collection_id, status, total_fetched, total_stored, total_duplicates, error_message, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "TAXII_SCHEDULER",
                    "all_collections",
                    status,
                    total_fetched,
                    total_stored,
                    total_duplicates,
                    error_message,
                    datetime.now(timezone.utc),
                ),
            )

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error("Failed to log ingestion to DB", error=str(e))

    def get_status(self):
        """Get current scheduler status and run history."""
        next_run = None
        if self.ingest_job_id:
            next_run = self.ingest_job_id.next_run_time

        return {
            "is_running": self.is_running,
            "next_run": next_run.isoformat() if next_run else None,
            "total_runs": len(self.run_history),
            "run_history": list(self.run_history)[-10:],  # Last 10 runs
        }

    def get_servers(self):
        """Return list of pre-configured servers."""
        return [
            {
                "key": key,
                "url": config["url"],
                "username": config.get("username"),
                "description": config.get("description", ""),
            }
            for key, config in PUBLIC_SERVERS.items()
        ]


# Global scheduler instance
scheduler = TAXIIScheduler()


def start_scheduler(interval_minutes: int = 30):
    """Start the global scheduler."""
    return scheduler.start(interval_minutes)


def get_scheduler_status():
    """Get scheduler status."""
    return scheduler.get_status()


def trigger_ingestion_now():
    """Manually trigger ingestion."""
    return scheduler.trigger_now()


def get_public_servers():
    """Get list of public servers."""
    return scheduler.get_servers()
