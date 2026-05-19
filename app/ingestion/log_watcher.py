"""
app/ingestion/log_watcher.py
=============================
Background Log File Watcher — supports TWO modes configured via .env:

  OPTION A — Single file path:
    LOG_FILE_PATH=data/SSH_sample.log.log
    System reads that specific file, scans for IOC matches.

  OPTION B — Folder path:
    LOG_WATCH_FOLDER=logs/
    System scans ALL .log and .txt files in that folder.

Both options can be active at the same time.

Change Detection:
  Before reprocessing any log file, the system computes an MD5 checksum.
  If the checksum matches what's stored in the database, the file is
  SKIPPED — saving time on large (GB-level) log files that haven't changed.

  For continuously-updated "live" log files (e.g., today's syslog), the
  checksum will differ each cycle, so they are always reprocessed.
  For archived/rotated log files (e.g., yesterday's log), the checksum
  stays the same, so they are processed only once.

  File read offsets are also persisted in the database so only NEW lines
  are scanned — no duplicate processing even across server restarts.

Results are saved to the log_scan_results table in the database.
"""
import os
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


def _get_config() -> Dict:
    """Read log watcher config from environment variables."""
    return {
        "enabled":           os.getenv("LOG_WATCH_ENABLED", "true").lower() == "true",
        "log_file_path":     os.getenv("LOG_FILE_PATH", "").strip(),
        "log_watch_folder":  os.getenv("LOG_WATCH_FOLDER", "").strip(),
    }


def _compute_checksum(filepath: str) -> str:
    """Compute MD5 checksum of a file for change detection.

    Uses chunked reading to handle large (GB-level) log files
    without loading the entire file into memory.
    """
    md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
    except Exception as e:
        logger.error("Checksum computation failed for '%s': %s", filepath, e)
        return ""
    return md5.hexdigest()


def _has_file_changed(filepath: str, current_checksum: str) -> tuple:
    """Check if a log file has changed since last scan using stored checksum.

    Returns (changed: bool, stored_record: dict | None).
    - changed=True  → file is new or content has changed, needs processing
    - changed=False → file is identical, skip processing
    """
    from app.database.db_manager import get_log_file_checksum

    stored = get_log_file_checksum(filepath)
    if stored is None:
        # First time seeing this file — needs processing
        logger.info("Log watcher: new file detected — '%s'", filepath)
        return True, None

    if stored["checksum"] != current_checksum:
        # File content has changed since last scan
        logger.info(
            "Log watcher: file changed — '%s' (old=%s, new=%s)",
            filepath, stored["checksum"][:8], current_checksum[:8],
        )
        return True, stored

    # Checksum matches — file has NOT changed
    logger.debug(
        "Log watcher: file unchanged, skipping — '%s' (checksum=%s)",
        filepath, current_checksum[:8],
    )
    return False, stored


def _scan_file(filepath: str) -> List[Dict]:
    """
    Read new lines from a file (from last known position) and check
    each line against the IOC database.

    Change detection workflow:
      1. Compute MD5 checksum of the file
      2. Compare with stored checksum in database
      3. If unchanged → skip entirely (return empty list)
      4. If changed → read from last known offset, scan new lines
      5. Store new checksum + offset in database

    Returns a list of hit dicts, same format as log_checker.
    """
    from app.ingestion.log_checker import _check_line, _load_ioc_cache
    from app.database.db_manager import upsert_log_file_checksum

    path = Path(filepath)
    if not path.exists():
        logger.warning("Log watcher: file not found — '%s'", filepath)
        return []

    # ── Step 1: Compute checksum ─────────────────────────────────
    current_checksum = _compute_checksum(filepath)
    if not current_checksum:
        return []  # checksum computation failed

    # ── Step 2: Check if file has changed ────────────────────────
    changed, stored = _has_file_changed(filepath, current_checksum)
    if not changed:
        return []  # file is identical — skip processing

    # ── Step 3: Determine read offset ────────────────────────────
    # Use stored offset from DB if available (persists across restarts)
    last_offset = 0
    if stored and stored.get("last_offset"):
        # File changed but we have a previous offset — check if file
        # was truncated/rotated (new size < old offset)
        file_size = path.stat().st_size
        if file_size >= stored["last_offset"]:
            last_offset = stored["last_offset"]
        else:
            # File was rotated/truncated — read from beginning
            logger.info(
                "Log watcher: file rotated — '%s' (size %d < offset %d)",
                path.name, file_size, stored["last_offset"],
            )
            last_offset = 0

    hits = []

    try:
        # Load IOC cache once — avoids one DB connection per line
        # Also filters out revoked IOCs (mentor requirement)
        ioc_cache = _load_ioc_cache()

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(last_offset)           # jump to where we left off
            lines = f.readlines()
            new_offset = f.tell()         # remember new end position

        # Proper line numbering from the start of the scan chunk
        for i, line in enumerate(lines, start=1):
            if line.strip():
                line_hits = _check_line(line, i, str(path.name), ioc_cache)
                hits.extend(line_hits)

        # ── Step 4: Save checksum + offset to database ───────────
        file_size = path.stat().st_size
        upsert_log_file_checksum(
            file_path=str(path),
            checksum=current_checksum,
            file_size=file_size,
            last_offset=new_offset,
        )

        if lines:
            logger.info(
                "Log watcher: scanned '%s' — %d new lines, %d hits (checksum=%s)",
                path.name, len(lines), len(hits), current_checksum[:8],
            )
        else:
            logger.debug(
                "Log watcher: no new lines in '%s' from offset %d",
                path.name, last_offset,
            )

    except Exception as e:
        logger.error("Log watcher: error reading '%s': %s", filepath, e)

    return hits


def _get_folder_files(folder: str) -> List[str]:
    """Return all .log and .txt files in the given folder."""
    folder_path = Path(folder)
    if not folder_path.exists():
        folder_path.mkdir(parents=True, exist_ok=True)
        logger.info("Log watcher: created folder '%s'", folder)
        return []

    files = (
        list(folder_path.glob("*.log")) +
        list(folder_path.glob("*.txt")) +
        list(folder_path.glob("*.syslog"))
    )
    return [str(f) for f in files]


def scan_configured_logs() -> Dict:
    """
    Main entry point — called by the scheduler on every cycle.

    Checks both:
      - LOG_FILE_PATH  (single file, if configured)
      - LOG_WATCH_FOLDER (all .log/.txt files in folder, if configured)

    Change detection:
      Each file's MD5 checksum is compared with the value stored in the
      database. Unchanged files are skipped entirely, saving processing
      time on large log files.

    Saves all hits to the database.
    Returns a summary dict.
    """
    cfg = _get_config()

    if not cfg["enabled"]:
        logger.debug("Log watcher is disabled (LOG_WATCH_ENABLED=false)")
        return {"enabled": False, "total_hits": 0}

    from app.database.db_manager import save_log_scan_results, create_tables
    create_tables()   # ensure log_scan_results + log_file_checksums tables exist

    all_hits      = []
    files_scanned = []
    files_skipped = 0

    # ── OPTION A: Single file path ────────────────────────────────
    if cfg["log_file_path"]:
        fpath = cfg["log_file_path"]
        logger.info("Log watcher (single file): checking '%s'", fpath)
        hits = _scan_file(fpath)
        if hits is not None:  # None would mean error, empty list means skipped or no hits
            all_hits.extend(hits)
            if hits:
                files_scanned.append({
                    "file":  fpath,
                    "mode":  "single_file",
                    "hits":  len(hits),
                })
            else:
                # File was either skipped (unchanged) or had no hits
                files_scanned.append({
                    "file":  fpath,
                    "mode":  "single_file",
                    "hits":  0,
                    "status": "scanned_or_skipped",
                })

    # ── OPTION B: Folder path ─────────────────────────────────────
    if cfg["log_watch_folder"]:
        folder = cfg["log_watch_folder"]
        folder_files = _get_folder_files(folder)
        logger.info(
            "Log watcher (folder): '%s' has %d file(s)", folder, len(folder_files)
        )
        for fpath in folder_files:
            hits = _scan_file(fpath)
            all_hits.extend(hits)
            files_scanned.append({
                "file":  fpath,
                "mode":  "folder_watch",
                "hits":  len(hits),
            })

    # ── Save all hits to database ─────────────────────────────────
    saved = 0
    if all_hits:
        saved = save_log_scan_results(all_hits, scan_mode="background")
        logger.info("Log watcher: saved %d hits to database", saved)

    # ── Severity breakdown ────────────────────────────────────────
    severity_breakdown: Dict[str, int] = {}
    for h in all_hits:
        sev = h.get("severity", "unknown")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    return {
        "enabled":            True,
        "files_scanned":      len(files_scanned),
        "files_skipped":      files_skipped,
        "total_hits":         len(all_hits),
        "saved_to_db":        saved,
        "severity_breakdown": severity_breakdown,
        "files":              files_scanned,
        "scanned_at":         datetime.now(timezone.utc).isoformat(),
    }
