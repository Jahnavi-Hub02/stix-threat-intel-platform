import sqlite3
from datetime import datetime, timezone
from app.utils.logger import get_logger

logger = get_logger(__name__)

DB_PATH = "database/threat_intel.db"


def _now():
    return datetime.now(timezone.utc).isoformat()


def create_connection():
    """Create a SQLite database connection with dict-like row access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # ← allows row["column"] access
    return conn


def create_tables():
    """Create all required database tables if they don't exist."""
    conn = create_connection()
    cursor = conn.cursor()

    # IOC Indicators Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ioc_indicators (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        stix_id     TEXT UNIQUE,
        ioc_type    TEXT,
        ioc_subtype TEXT,
        ioc_value   TEXT UNIQUE,
        confidence  INTEGER DEFAULT 50,
        source      TEXT,
        is_active   INTEGER DEFAULT 1,
        first_seen  TIMESTAMP,
        last_seen   TIMESTAMP,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Event Logs Table
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

    # Correlation Results Table — UNIQUE constraint prevents duplicates
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
        detected_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(event_id, matched_ip, match_type)
    )
    """)

    # Ingestion Audit Log — tracks every TAXII/file ingest run
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


    # Users table — stores registered platform users
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

    # Refresh tokens table — allows token revocation on logout
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

    conn.commit()
    conn.close()
    logger.info("Database tables created/verified")



def insert_indicators(indicators, source_label="Unknown"):
    """Insert IOC indicators with deduplication and ingestion audit logging."""
    conn = create_connection()
    cursor = conn.cursor()

    total_stored = 0
    total_duplicates = 0
    now = _now()

    # Log start of ingestion
    cursor.execute("""
        INSERT INTO ingestion_logs (source, status, started_at)
        VALUES (?, 'running', ?)
    """, (source_label, now))
    log_id = cursor.lastrowid

    for ind in indicators:
        cursor.execute(
            "SELECT id FROM ioc_indicators WHERE ioc_value = ?",
            (ind["ioc_value"],)
        )
        exists = cursor.fetchone()

        if exists:
            # Update last_seen on duplicate
            cursor.execute(
                "UPDATE ioc_indicators SET last_seen = ? WHERE ioc_value = ?",
                (now, ind["ioc_value"])
            )
            total_duplicates += 1
        else:
            cursor.execute("""
                INSERT INTO ioc_indicators
                (stix_id, ioc_type, ioc_subtype, ioc_value, confidence, source, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ind.get("stix_id", "unknown"),
                ind.get("ioc_type", "unknown"),
                ind.get("ioc_subtype", ""),
                ind["ioc_value"],
                ind.get("confidence", 50),
                ind.get("source", source_label),
                now,
                now
            ))
            total_stored += 1

    # Complete ingestion log
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
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT event_id FROM event_logs WHERE event_id = ?", (event["event_id"],))
    if cursor.fetchone():
        conn.close()
        return False  # Already logged

    cursor.execute("""
        INSERT INTO event_logs
        (event_id, source_ip, destination_ip, source_port, destination_port, protocol, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        event["event_id"],
        event.get("source_ip"),
        event.get("destination_ip"),
        event.get("source_port"),
        event.get("destination_port"),
        event.get("protocol"),
        event.get("timestamp", _now())
    ))

    conn.commit()
    conn.close()
    return True


def get_all_iocs(limit=100, offset=0, ioc_type=None):
    """Fetch IOC indicators as list of dicts."""
    conn = create_connection()
    cursor = conn.cursor()

    if ioc_type:
        cursor.execute(
            "SELECT * FROM ioc_indicators WHERE ioc_type = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (ioc_type, limit, offset)
        )
    else:
        cursor.execute(
            "SELECT * FROM ioc_indicators ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_correlation_results(event_id=None, limit=50):
    """Fetch correlation results as list of dicts."""
    conn = create_connection()
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
    """Return platform-wide statistics."""
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM ioc_indicators WHERE is_active = 1")
    total_iocs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM event_logs")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM correlation_results")
    total_correlations = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM correlation_results WHERE severity = 'Critical'")
    critical = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM correlation_results WHERE severity = 'High'")
    high = cursor.fetchone()[0]

    cursor.execute("""
        SELECT matched_ip, COUNT(*) as hit_count
        FROM correlation_results
        GROUP BY matched_ip
        ORDER BY hit_count DESC
        LIMIT 5
    """)
    top_threats = [dict(r) for r in cursor.fetchall()]

    # ML anomaly stats (table may not exist yet)
    ml_stats = {"total_ml_events": 0, "total_anomalies": 0, "model_trained": False}
    try:
        cursor.execute("SELECT COUNT(*) FROM ml_events")
        ml_stats["total_ml_events"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM ml_events WHERE is_anomaly = 1")
        ml_stats["total_anomalies"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM ml_model_runs WHERE status = \'success\'")
        ml_stats["model_trained"] = cursor.fetchone()[0] > 0
    except Exception:
        pass

    conn.close()

    return {
        "total_iocs": total_iocs,
        "total_events": total_events,
        "total_correlations": total_correlations,
        "severity_breakdown": {"critical": critical, "high": high},
        "top_threats": top_threats,
        "ml": ml_stats,
    }


# ── User Management ───────────────────────────────────────────────

def create_user(username: str, password_hash: str, role: str = "viewer") -> dict:
    """Create a new user. Returns the created user dict or raises ValueError on duplicate."""
    conn   = create_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username.lower(), password_hash, role)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return {"user_id": user_id, "username": username.lower(), "role": role}
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            raise ValueError(f"Username '{username}' is already taken.")
        raise
    finally:
        conn.close()


def get_user_by_username(username: str) -> dict | None:
    """Fetch a user dict by username, or None if not found."""
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, role, is_active, created_at, last_login "
        "FROM users WHERE username = ? AND is_active = 1",
        (username.lower(),)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)


def get_user_by_id(user_id: int) -> dict | None:
    """Fetch a user dict by ID, or None if not found."""
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
    """Stamp last_login timestamp on successful login."""
    conn = create_connection()
    conn.execute(
        "UPDATE users SET last_login = ? WHERE id = ?",
        (_now(), user_id)
    )
    conn.commit()
    conn.close()


def list_users() -> list:
    """Return all users (without password hashes) for admin use."""
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
    """Soft-delete a user (sets is_active=0). Returns True if found."""
    conn    = create_connection()
    cursor  = conn.cursor()
    cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0


# ── Refresh Token Management ──────────────────────────────────────

def store_refresh_token(jti: str, user_id: int, expires_at: str) -> None:
    """Persist a refresh token JTI so we can revoke it on logout."""
    conn = create_connection()
    conn.execute(
        "INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES (?, ?, ?)",
        (jti, user_id, expires_at)
    )
    conn.commit()
    conn.close()


def is_refresh_token_valid(jti: str) -> bool:
    """Return True if the JTI exists, is not revoked, and has not expired."""
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT revoked, expires_at FROM refresh_tokens WHERE jti = ?",
        (jti,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return False
    if row["revoked"]:
        return False
    # Check expiry
    try:
        from datetime import datetime, timezone
        expires = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expires:
            return False
    except Exception:
        return False
    return True


def revoke_refresh_token(jti: str) -> None:
    """Mark a refresh token as revoked (logout)."""
    conn = create_connection()
    conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?", (jti,))
    conn.commit()
    conn.close()


def revoke_all_user_tokens(user_id: int) -> None:
    """Revoke all refresh tokens for a user (force logout everywhere)."""
    conn = create_connection()
    conn.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
        (user_id,)
    )
    conn.commit()
    conn.close()
