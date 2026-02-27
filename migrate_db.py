"""
Database Migration Script
Run this once to upgrade your existing database schema.
Usage: python migrate_db.py
"""
import sqlite3
import os

DB_PATH = os.path.join("database", "threat_intel.db")

print("=" * 50)
print("Database Migration")
print(f"DB: {DB_PATH}")
print("=" * 50)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# ── ioc_indicators new columns ───────────────────────────
ioc_cols = [
    ("ioc_subtype", "TEXT DEFAULT ''"),
    ("is_active",   "INTEGER DEFAULT 1"),
    ("first_seen",  "TIMESTAMP"),
    ("last_seen",   "TIMESTAMP"),
]
for col, definition in ioc_cols:
    try:
        cursor.execute(f"ALTER TABLE ioc_indicators ADD COLUMN {col} {definition}")
        print(f"  [OK] Added ioc_indicators.{col}")
    except sqlite3.OperationalError:
        print(f"  [SKIP] ioc_indicators.{col} already exists")

# ── correlation_results new columns ─────────────────────
corr_cols = [
    ("risk_score",   "REAL DEFAULT 0.0"),
    ("severity",     "TEXT DEFAULT 'Low'"),
    ("mitre_tactic", "TEXT"),
]
for col, definition in corr_cols:
    try:
        cursor.execute(f"ALTER TABLE correlation_results ADD COLUMN {col} {definition}")
        print(f"  [OK] Added correlation_results.{col}")
    except sqlite3.OperationalError:
        print(f"  [SKIP] correlation_results.{col} already exists")

# ── event_logs new columns ───────────────────────────────
event_cols = [
    ("source_port",      "INTEGER"),
    ("destination_port", "INTEGER"),
    ("protocol",         "TEXT"),
    ("is_processed",     "INTEGER DEFAULT 0"),
    ("submitted_at",     "TIMESTAMP"),
]
for col, definition in event_cols:
    try:
        cursor.execute(f"ALTER TABLE event_logs ADD COLUMN {col} {definition}")
        print(f"  [OK] Added event_logs.{col}")
    except sqlite3.OperationalError:
        print(f"  [SKIP] event_logs.{col} already exists")

# ── ingestion_logs table (new) ───────────────────────────
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
print("  [OK] ingestion_logs table ready")

# ── Add UNIQUE constraint workaround for correlation_results
# SQLite doesn't support ADD CONSTRAINT, so we verify it exists
cursor.execute("PRAGMA table_info(correlation_results)")
cols = [row[1] for row in cursor.fetchall()]
print(f"\n  correlation_results columns: {cols}")

cursor.execute("PRAGMA table_info(ioc_indicators)")
cols2 = [row[1] for row in cursor.fetchall()]
print(f"  ioc_indicators columns:      {cols2}")

conn.commit()
conn.close()

print()
print("=" * 50)
print("Migration complete! Now run: python run.py")
print("=" * 50)