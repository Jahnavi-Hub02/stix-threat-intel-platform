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

Each file's read position is tracked so only NEW lines are scanned
each time — no duplicate processing.

Results are saved to the log_scan_results table in the database.
"""
import os
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)

# ── File position tracker ──────────────────────────────────────────
# Keeps track of how many bytes we've already read from each file.
# This means only NEW lines added after the last scan are processed.
_file_offsets: Dict[str, int] = {}


def _get_config() -> Dict:
    """Read log watcher config from environment variables."""
    return {
        "enabled":           os.getenv("LOG_WATCH_ENABLED", "true").lower() == "true",
        "log_file_path":     os.getenv("LOG_FILE_PATH", "").strip(),
        "log_watch_folder":  os.getenv("LOG_WATCH_FOLDER", "").strip(),
    }


def _scan_file(filepath: str) -> List[Dict]:
    """
    Read new lines from a file (from last known position) and check
    each line against the IOC database.

    Returns a list of hit dicts, same format as log_checker.
    """
    from app.ingestion.log_checker import _check_line

    path = Path(filepath)
    if not path.exists():
        logger.warning("Log watcher: file not found — '%s'", filepath)
        return []

    # Get last read position for this file (0 = start of file)
    last_offset = _file_offsets.get(str(path), 0)
    hits        = []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(last_offset)           # jump to where we left off
            line_number = last_offset     # approximate; reset per-scan

            lines = f.readlines()
            new_offset = f.tell()         # remember new end position

        # Proper line numbering from the start of the scan chunk
        for i, line in enumerate(lines, start=1):
            if line.strip():
                line_hits = _check_line(line, i, str(path.name))
                hits.extend(line_hits)

        # Save new offset only if we read successfully
        _file_offsets[str(path)] = new_offset

        if lines:
            logger.info(
                "Log watcher: scanned '%s' — %d new lines, %d hits",
                path.name, len(lines), len(hits),
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

    Saves all hits to the database.
    Returns a summary dict.
    """
    cfg = _get_config()

    if not cfg["enabled"]:
        logger.debug("Log watcher is disabled (LOG_WATCH_ENABLED=false)")
        return {"enabled": False, "total_hits": 0}

    from app.database.db_manager import save_log_scan_results, create_tables
    create_tables()   # ensure log_scan_results table exists

    all_hits     = []
    files_scanned = []

    # ── OPTION A: Single file path ────────────────────────────────
    if cfg["log_file_path"]:
        fpath = cfg["log_file_path"]
        logger.info("Log watcher (single file): scanning '%s'", fpath)
        hits = _scan_file(fpath)
        all_hits.extend(hits)
        files_scanned.append({
            "file":  fpath,
            "mode":  "single_file",
            "hits":  len(hits),
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
        "total_hits":         len(all_hits),
        "saved_to_db":        saved,
        "severity_breakdown": severity_breakdown,
        "files":              files_scanned,
        "scanned_at":         datetime.now(timezone.utc).isoformat(),
    }
