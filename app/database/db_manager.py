import sqlite3
import os
import pathlib
import time
import functools
from datetime import datetime, timezone
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Robust absolute path — resolves to <project_root>/database/threat_intel.db
# regardless of the current working directory.
# Tests use monkeypatch to override this, not env vars.
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
DB_PATH = str(_PROJECT_ROOT / "database" / "threat_intel.db")

# Ensure the database directory exists (SQLite only creates the file, not parent dirs)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _retry_db_write(func):
    """Retry transient SQLite lock errors with exponential backoff."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        for attempt in range(5):
            try:
                return func(*args, **kwargs)
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower():
                    raise
                if attempt == 4:
                    raise
                time.sleep(0.1 * (2 ** attempt))
    return wrapper


def create_connection():
    """Create a SQLite database connection with dict-like row access."""
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


def get_connection():
    """Context manager for safe DB connection handling.

    Usage:
        with get_connection() as conn:
            conn.execute("SELECT ...")
    """
    from contextlib import contextmanager

    @contextmanager
    def _ctx():
        conn = create_connection()
        try:
            yield conn
        finally:
            conn.close()

    return _ctx()


def create_tables():
    """Create all required database tables if they don't exist."""
    conn   = create_connection()
    cursor = conn.cursor()

    # FIX: Added `severity` column to ioc_indicators.
    # It was missing from the schema but queried by _lookup_ioc in log_checker.py:
    #   SELECT ioc_type, ioc_value, confidence, severity, source, last_seen ...
    # The missing column caused an OperationalError that was silently caught,
    # making _lookup_ioc always return None → total_hits always 0.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ioc_indicators (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        stix_id      TEXT UNIQUE,
        ioc_type     TEXT,
        ioc_subtype  TEXT,
        ioc_value    TEXT UNIQUE,
        confidence   INTEGER DEFAULT 50,
        severity     TEXT DEFAULT 'medium',
        source       TEXT,
        is_active    INTEGER DEFAULT 1,
        first_seen   TIMESTAMP,
        last_seen    TIMESTAMP,
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        -- Superset metadata columns (mentor requirement)
        country      TEXT,
        geo_lat      REAL,
        geo_lon      REAL,
        city         TEXT,
        asn          TEXT,
        revoked      INTEGER DEFAULT 0,
        tlp          TEXT DEFAULT 'GREEN',
        tags         TEXT,
        description  TEXT,
        kill_chain   TEXT,
        external_refs TEXT
    )
    """)

    # ── Migrations: safely add new columns to existing databases ──────────
    # Each ALTER TABLE is wrapped in try/except so it's skipped if column exists.
    _migrations = [
        ("ioc_indicators", "severity",      "TEXT DEFAULT 'medium'"),
        ("ioc_indicators", "country",       "TEXT"),
        ("ioc_indicators", "geo_lat",        "REAL"),
        ("ioc_indicators", "geo_lon",        "REAL"),
        ("ioc_indicators", "city",           "TEXT"),
        ("ioc_indicators", "asn",            "TEXT"),
        ("ioc_indicators", "revoked",        "INTEGER DEFAULT 0"),
        ("ioc_indicators", "tlp",            "TEXT DEFAULT 'GREEN'"),
        ("ioc_indicators", "tags",           "TEXT"),
        ("ioc_indicators", "description",   "TEXT"),
        ("ioc_indicators", "kill_chain",     "TEXT"),
        ("ioc_indicators", "external_refs",  "TEXT"),
    ]
    for table, column, col_def in _migrations:
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
            conn.commit()
            logger.debug("Migration applied: added %s.%s", table, column)
        except Exception:
            pass   # column already exists — skip silently

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS event_logs (
        event_id         TEXT PRIMARY KEY,
        source_ip        TEXT,
        destination_ip   TEXT,
        source_port      INTEGER,
        destination_port INTEGER,
        protocol         TEXT,
        timestamp        TEXT,
        is_processed     INTEGER DEFAULT 0,
        submitted_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS correlation_results (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id     TEXT,
        matched_ip   TEXT,
        match_type   TEXT,
        decision     TEXT,
        risk_score   REAL DEFAULT 0.0,
        severity     TEXT DEFAULT 'Low',
        mitre_tactic TEXT,
        source_ip    TEXT,
        detected_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(event_id, matched_ip, match_type)
    )
    """)

    # Migration: add source_ip to existing databases
    try:
        cursor.execute("ALTER TABLE correlation_results ADD COLUMN source_ip TEXT")
        conn.commit()
        logger.debug("Migration applied: added source_ip column to correlation_results")
    except Exception:
        logger.debug("Migration skip: source_ip column already exists in correlation_results")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ingestion_logs (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        source           TEXT,
        status           TEXT,
        total_fetched    INTEGER DEFAULT 0,
        total_stored     INTEGER DEFAULT 0,
        total_duplicates INTEGER DEFAULT 0,
        error_message    TEXT,
        started_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at     TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role          TEXT NOT NULL DEFAULT 'viewer',
        is_active     INTEGER NOT NULL DEFAULT 1,
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login    TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        jti        TEXT UNIQUE NOT NULL,
        user_id    INTEGER NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        revoked    INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id       TEXT NOT NULL,
        status         TEXT NOT NULL DEFAULT 'NEW',
        alert_type     TEXT NOT NULL DEFAULT 'threat_detected',
        risk_score     REAL DEFAULT 0.0,
        severity       TEXT DEFAULT 'Low',
        ioc_matches    INTEGER DEFAULT 0,
        source_ip      TEXT,
        destination_ip TEXT,
        notes          TEXT,
        assigned_to    TEXT,
        resolved_at    TEXT,
        created_at     TEXT,
        updated_at     TEXT
    )
    """)

    # Log scan results — stores matches from background log file scanning
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS log_scan_results (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        source_file    TEXT,
        line_number    INTEGER,
        timestamp      TEXT,
        log_line       TEXT,
        matched_ioc    TEXT,
        ioc_type       TEXT,
        confidence     INTEGER,
        severity       TEXT,
        source_ip      TEXT,
        destination_ip TEXT,
        scan_mode      TEXT DEFAULT 'background',
        detected_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Log file checksum tracking — avoids reprocessing unchanged log files.
    # Stores MD5 hash + file offset so the log watcher can skip files
    # that haven't changed since the last scan cycle.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS log_file_checksums (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path      TEXT UNIQUE NOT NULL,
        checksum       TEXT NOT NULL,
        file_size      INTEGER DEFAULT 0,
        last_offset    INTEGER DEFAULT 0,
        last_scanned   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()
    logger.info("Database tables created/verified")


# ── Alert CRUD ────────────────────────────────────────────────────

def create_alert(event_id: str, alert_type: str, risk_score: float,
                 severity: str, ioc_matches: int,
                 source_ip: str = None, destination_ip: str = None) -> dict:
    """Insert a new alert row. Returns the created alert as a dict."""
    conn   = create_connection()
    cursor = conn.cursor()
    now    = _now()
    cursor.execute("""
        INSERT INTO alerts
          (event_id, status, alert_type, risk_score, severity,
           ioc_matches, source_ip, destination_ip, created_at, updated_at)
        VALUES (?, 'NEW', ?, ?, ?, ?, ?, ?, ?, ?)
    """, (event_id, alert_type, risk_score, severity, ioc_matches,
          source_ip, destination_ip, now, now))
    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()
    return get_alert_by_id(alert_id)


def get_alert_by_id(alert_id: int) -> dict | None:
    """Fetch a single alert by ID, or None if not found."""
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_alerts(status_filter: str | None = None,
                   limit: int = 100, offset: int = 0) -> list:
    """Fetch alerts, optionally filtered by status."""
    conn   = create_connection()
    cursor = conn.cursor()
    if status_filter:
        cursor.execute(
            "SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (status_filter, limit, offset)
        )
    else:
        cursor.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_alert_summary() -> dict:
    """Return counts grouped by status, e.g. {"NEW": 3, "RESOLVED": 1}."""
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status, COUNT(*) as count FROM alerts GROUP BY status")
    rows = cursor.fetchall()
    conn.close()
    return {row["status"]: row["count"] for row in rows}


def update_alert(alert_id: int, new_status: str,
                 notes: str | None = None,
                 assigned_to: str | None = None,
                 resolved_at: str | None = None) -> dict | None:
    """Update alert. Returns updated alert dict or None if not found."""
    conn   = create_connection()
    cursor = conn.cursor()
    now    = _now()
    cursor.execute("""
        UPDATE alerts
        SET status      = ?,
            notes       = COALESCE(?, notes),
            assigned_to = COALESCE(?, assigned_to),
            resolved_at = COALESCE(?, resolved_at),
            updated_at  = ?
        WHERE id = ?
    """, (new_status, notes, assigned_to, resolved_at, now, alert_id))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    if not affected:
        return None
    return get_alert_by_id(alert_id)


# ── Log Scan Results ──────────────────────────────────────────────

def save_log_scan_results(hits: list, scan_mode: str = "background") -> int:
    """Save log scan hit results to the log_scan_results table. Returns count saved."""
    if not hits:
        return 0
    conn   = create_connection()
    cursor = conn.cursor()
    saved  = 0
    for h in hits:
        ioc = h.get("matched_ioc", {})
        try:
            cursor.execute("""
                INSERT INTO log_scan_results
                (source_file, line_number, timestamp, log_line,
                 matched_ioc, ioc_type, confidence, severity,
                 source_ip, destination_ip, scan_mode)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                h.get("source_file"),
                h.get("line_number"),
                h.get("timestamp"),
                h.get("log_line", "")[:500],
                ioc.get("ioc_value"),
                ioc.get("ioc_type"),
                ioc.get("confidence"),
                h.get("severity"),
                h.get("source_ip"),
                h.get("destination_ip"),
                scan_mode,
            ))
            saved += 1
        except Exception as e:
            logger.debug("save_log_scan_results: skipped row: %s", e)
    conn.commit()
    conn.close()
    return saved


def get_log_scan_results(limit: int = 100, offset: int = 0,
                         severity: str = None,
                         source_file: str = None) -> list:
    """Fetch stored log scan results with optional filters."""
    conn   = create_connection()
    cursor = conn.cursor()
    query  = "SELECT * FROM log_scan_results"
    params = []
    filters = []
    if severity:
        filters.append("severity = ?")
        params.append(severity)
    if source_file:
        filters.append("source_file = ?")
        params.append(source_file)
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY detected_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# ── Log File Checksum Tracking ────────────────────────────────────

def get_log_file_checksum(file_path: str) -> dict | None:
    """Retrieve the stored checksum record for a log file."""
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT file_path, checksum, file_size, last_offset, last_scanned "
        "FROM log_file_checksums WHERE file_path = ?",
        (file_path,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


@_retry_db_write
def upsert_log_file_checksum(file_path: str, checksum: str,
                             file_size: int, last_offset: int) -> None:
    """Insert or update the checksum record for a log file."""
    conn = create_connection()
    now = _now()
    conn.execute("""
        INSERT INTO log_file_checksums (file_path, checksum, file_size, last_offset, last_scanned, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(file_path) DO UPDATE SET
            checksum     = excluded.checksum,
            file_size    = excluded.file_size,
            last_offset  = excluded.last_offset,
            last_scanned = excluded.last_scanned,
            updated_at   = excluded.updated_at
    """, (file_path, checksum, file_size, last_offset, now, now))
    conn.commit()
    conn.close()


# ── IOC Indicators ────────────────────────────────────────────────

def _severity_from_confidence(confidence: int) -> str:
    """Derive a severity label from a confidence score (0-100)."""
    if confidence >= 90:
        return "critical"
    if confidence >= 70:
        return "high"
    if confidence >= 50:
        return "medium"
    return "low"


def insert_indicators(indicators, source_label="Unknown"):
    """Insert IOC indicators with deduplication and ingestion audit logging."""
    conn   = create_connection()
    cursor = conn.cursor()
    total_stored, total_duplicates = 0, 0
    now    = _now()

    cursor.execute("""
        INSERT INTO ingestion_logs (source, status, started_at)
        VALUES (?, 'running', ?)
    """, (source_label, now))
    log_id = cursor.lastrowid
    conn.commit()  # commit the log row early so the write lock is released sooner
    batch_count = 0

    for ind in indicators:
        stix_id = ind.get("stix_id")
        if not stix_id or stix_id == "unknown":
            stix_id = None

        query = "SELECT id FROM ioc_indicators WHERE ioc_value = ?"
        params = [ind["ioc_value"]]
        if stix_id is not None:
            query += " OR stix_id = ?"
            params.append(stix_id)

        cursor.execute(query, params)
        existing = cursor.fetchone()
        if existing:
            # UPSERT — mentor requirement: for real STIX polling, existing
            # indicators may have updated confidence/severity over time.
            # Update all mutable fields, not just last_seen.
            new_confidence = ind.get("confidence", 50)
            new_severity   = ind.get("severity") or _severity_from_confidence(new_confidence)
            cursor.execute("""
                UPDATE ioc_indicators
                SET last_seen   = ?,
                    confidence  = ?,
                    severity    = ?,
                    source      = COALESCE(?, source),
                    ioc_subtype = COALESCE(?, ioc_subtype),
                    is_active   = 1
                WHERE id = ?
            """, (
                now,
                new_confidence,
                new_severity,
                ind.get("source", source_label) or None,
                ind.get("ioc_subtype") or None,
                existing["id"],
            ))
            total_duplicates += 1

        else:
            # FIX: derive severity from confidence if not explicitly provided,
            # so _lookup_ioc can always read a meaningful severity value.
            confidence = ind.get("confidence", 50)
            severity   = ind.get("severity") or _severity_from_confidence(confidence)
            cursor.execute("""
                INSERT INTO ioc_indicators
                (stix_id, ioc_type, ioc_subtype, ioc_value,
                 confidence, severity, source, first_seen, last_seen,
                 country, geo_lat, geo_lon, city, asn,
                 revoked, tlp, tags, description, kill_chain, external_refs)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                stix_id,
                ind.get("ioc_type", "unknown"),
                ind.get("ioc_subtype", ""),
                ind["ioc_value"],
                confidence,
                severity,
                ind.get("source", source_label),
                now, now,
                # Superset metadata
                ind.get("country"),
                ind.get("geo_lat"),
                ind.get("geo_lon"),
                ind.get("city"),
                ind.get("asn"),
                1 if ind.get("revoked") else 0,
                ind.get("tlp", "GREEN"),
                ind.get("tags"),
                ind.get("description"),
                ind.get("kill_chain"),
                ind.get("external_refs"),
            ))
            total_stored += 1

        batch_count += 1
        if batch_count % 50 == 0:
            conn.commit()

    cursor.execute("""
        UPDATE ingestion_logs SET
            status = 'success',
            total_fetched = ?,
            total_stored = ?,
            total_duplicates = ?,
            completed_at = ?
        WHERE id = ?
    """, (len(indicators), total_stored, total_duplicates, _now(), log_id))

    conn.commit()
    conn.close()
    logger.info("Ingestion complete", stored=total_stored, duplicates=total_duplicates)
    return {"stored": total_stored, "duplicates": total_duplicates}


def save_event(event: dict) -> bool:
    """Save an incoming event to event_logs. Returns False if already exists."""
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT event_id FROM event_logs WHERE event_id = ?", (event["event_id"],))
    if cursor.fetchone():
        conn.close()
        return False
    cursor.execute("""
        INSERT INTO event_logs
        (event_id, source_ip, destination_ip, source_port, destination_port,
         protocol, timestamp, submitted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["event_id"],
        event.get("source_ip"),
        event.get("destination_ip"),
        event.get("source_port"),
        event.get("destination_port"),
        event.get("protocol"),
        event.get("timestamp", _now()),
        _now(),
    ))
    conn.commit()
    conn.close()
    return True


def get_all_iocs(limit=100, offset=0, ioc_type=None,
                 severity=None, country=None,
                 confidence_min=None, source=None):
    """Fetch IOCs with optional superset filters."""
    conn   = create_connection()
    cursor = conn.cursor()

    filters, params = ["is_active = 1"], []
    if ioc_type:
        filters.append("ioc_type = ?")
        params.append(ioc_type)
    if severity:
        filters.append("severity = ?")
        params.append(severity)
    if country:
        filters.append("country = ?")
        params.append(country.upper())
    if confidence_min is not None:
        filters.append("confidence >= ?")
        params.append(int(confidence_min))
    if source:
        filters.append("source LIKE ?")
        params.append(f"%{source}%")

    where = " WHERE " + " AND ".join(filters) if filters else ""
    params += [limit, offset]
    cursor.execute(
        f"SELECT * FROM ioc_indicators{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_correlation_results(event_id=None, limit=50):
    conn   = create_connection()
    cursor = conn.cursor()
    if event_id:
        cursor.execute(
            "SELECT * FROM correlation_results WHERE event_id = ? ORDER BY detected_at DESC",
            (event_id,)
        )
    else:
        cursor.execute(
            "SELECT * FROM correlation_results ORDER BY detected_at DESC LIMIT ?",
            (limit,)
        )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_db_stats():
    conn   = create_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM ioc_indicators WHERE is_active = 1")
        total_iocs = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM event_logs")
        total_events = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM correlation_results")
        total_correlations = cursor.fetchone()[0]

        # Consolidated: one query instead of four separate severity count queries
        severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        cursor.execute("""
            SELECT LOWER(severity) as sev, COUNT(*) as cnt
            FROM correlation_results
            GROUP BY LOWER(severity)
        """)
        for row in cursor.fetchall():
            sev = row[0]
            if sev in severity_breakdown:
                severity_breakdown[sev] = row[1]

        cursor.execute("""
            SELECT matched_ip, COUNT(*) as hit_count
            FROM correlation_results
            GROUP BY matched_ip ORDER BY hit_count DESC LIMIT 5
        """)
        top_threats = [dict(r) for r in cursor.fetchall()]

        ml_stats = {"total_ml_events": 0, "total_anomalies": 0, "model_trained": False}
        try:
            cursor.execute("SELECT COUNT(*) FROM ml_events")
            ml_stats["total_ml_events"] = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM ml_events WHERE is_anomaly = 1")
            ml_stats["total_anomalies"] = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM ml_model_runs WHERE status = 'success'")
            ml_stats["model_trained"] = cursor.fetchone()[0] > 0
        except Exception as e:
            logger.debug("ML stats tables not yet created: %s", str(e))

    finally:
        conn.close()

    return {
        "total_iocs": total_iocs,
        "total_events": total_events,
        "total_correlations": total_correlations,
        "severity_breakdown": severity_breakdown,
        "top_threats": top_threats,
        "ml": ml_stats,
    }


# ── User Management ───────────────────────────────────────────────

def create_user(username: str, password_hash: str, role: str = "viewer") -> dict:
    conn   = create_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username.lower(), password_hash, role)
        )
        conn.commit()
        return {"user_id": cursor.lastrowid, "username": username.lower(), "role": role}
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            raise ValueError(f"Username '{username}' is already taken.")
        raise
    finally:
        conn.close()


def get_user_by_username(username: str) -> dict | None:
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, role, is_active, created_at, last_login "
        "FROM users WHERE username = ? AND is_active = 1",
        (username.lower(),)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role, is_active, created_at, last_login "
        "FROM users WHERE id = ? AND is_active = 1",
        (user_id,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_last_login(user_id: int) -> None:
    conn = create_connection()
    conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (_now(), user_id))
    conn.commit()
    conn.close()


def list_users() -> list:
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role, is_active, created_at, last_login "
        "FROM users ORDER BY created_at DESC"
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def deactivate_user(user_id: int) -> bool:
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0


# ── Refresh Token Management ──────────────────────────────────────

@_retry_db_write
def store_refresh_token(jti: str, user_id: int, expires_at: str) -> None:
    conn = create_connection()
    conn.execute(
        "INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES (?, ?, ?)",
        (jti, user_id, expires_at)
    )
    conn.commit()
    conn.close()


def is_refresh_token_valid(jti: str) -> bool:
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT revoked, expires_at FROM refresh_tokens WHERE jti = ?",
        (jti,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row or row["revoked"]:
        return False
    try:
        expires = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expires:
            return False
    except Exception:
        return False
    return True


@_retry_db_write
def revoke_refresh_token(jti: str) -> None:
    conn = create_connection()
    conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?", (jti,))
    conn.commit()
    conn.close()


@_retry_db_write
def revoke_all_user_tokens(user_id: int) -> None:
    conn = create_connection()
    conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()