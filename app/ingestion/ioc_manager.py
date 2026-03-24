"""
app/ingestion/ioc_manager.py
=============================
Mentor requirement: handle outdated IOCs.
Uses create_connection() for automatic test isolation.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


def expire_outdated_iocs(max_age_days: int = 30) -> dict:
    """Mark IOCs as inactive if not updated in max_age_days."""
    from app.database.db_manager import create_connection
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
    try:
        conn = create_connection()
        cur  = conn.execute(
            "UPDATE ioc_indicators SET is_active = 0 WHERE last_seen < ? AND is_active = 1",
            (cutoff,)
        )
        expired = cur.rowcount
        still_active = conn.execute(
            "SELECT COUNT(*) FROM ioc_indicators WHERE is_active = 1"
        ).fetchone()[0]
        conn.commit(); conn.close()
        logger.info("Expired %d outdated IOCs. Active: %d", expired, still_active)
        return {"expired": expired, "still_active": still_active}
    except Exception as e:
        logger.error("expire_outdated_iocs failed: %s", e)
        return {"expired": 0, "still_active": 0, "error": str(e)}


def ioc_health_summary() -> dict:
    """Return freshness statistics for stored IOCs."""
    from app.database.db_manager import create_connection
    week_ago  = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    month_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    try:
        conn = create_connection()
        total    = conn.execute("SELECT COUNT(*) FROM ioc_indicators").fetchone()[0]
        active   = conn.execute("SELECT COUNT(*) FROM ioc_indicators WHERE is_active=1").fetchone()[0]
        fresh    = conn.execute("SELECT COUNT(*) FROM ioc_indicators WHERE last_seen > ?", (week_ago,)).fetchone()[0]
        recent   = conn.execute("SELECT COUNT(*) FROM ioc_indicators WHERE last_seen > ?", (month_ago,)).fetchone()[0]
        conn.close()
        return {
            "total": total, "active": active, "inactive": total - active,
            "fresh_last_7d": fresh, "seen_last_30d": recent, "stale": total - recent,
        }
    except Exception as e:
        return {"error": str(e)}
