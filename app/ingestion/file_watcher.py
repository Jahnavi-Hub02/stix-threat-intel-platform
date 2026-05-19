"""
app/ingestion/file_watcher.py
==============================
Offline IOC File Folder Watcher.

Mentor requirement:
  "Give a provision like in a particular folder — we'll copy some files.
   Every 30 minutes check whether in that folder any file is there.
   Process that and remove/mark those files as used."

How it works:
  1. Read IOC_WATCH_FOLDER from .env  (default: data/ioc_watch)
  2. Find all .json and .xml files in the folder
  3. Parse each file using existing stix parsers
  4. Insert IOCs into the database
  5. Move the file to IOC_PROCESSED_FOLDER with a timestamp suffix
     → so the same file is never processed twice

Configuration (.env):
  IOC_WATCH_FOLDER=data/ioc_watch
  IOC_PROCESSED_FOLDER=data/ioc_processed
  IOC_WATCH_ENABLED=true
"""
import os
import shutil
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger(__name__)


def _get_config() -> Dict:
    """Read folder watcher config from environment variables."""
    return {
        "enabled":        os.getenv("IOC_WATCH_ENABLED", "true").lower() == "true",
        "watch_folder":   os.getenv("IOC_WATCH_FOLDER",   "data/ioc_watch"),
        "processed_folder": os.getenv("IOC_PROCESSED_FOLDER", "data/ioc_processed"),
    }


def _ensure_folders(watch: str, processed: str) -> None:
    """Create watch and processed folders if they don't exist."""
    Path(watch).mkdir(parents=True, exist_ok=True)
    Path(processed).mkdir(parents=True, exist_ok=True)


def _move_to_processed(filepath: Path, processed_folder: str) -> str:
    """
    Move a processed file to the processed folder with a timestamp suffix.
    Example: feed_data.json → data/ioc_processed/feed_data_done_20260504_062200.json
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = filepath.stem          # filename without extension
    ext  = filepath.suffix        # .json or .xml
    new_name = f"{stem}_done_{ts}{ext}"
    dest = Path(processed_folder) / new_name
    shutil.move(str(filepath), str(dest))
    return str(dest)


def process_watch_folder() -> Dict:
    """
    Main entry point — called by the scheduler every 30 minutes.

    Scans IOC_WATCH_FOLDER for .json and .xml files, processes each one,
    and moves it to IOC_PROCESSED_FOLDER when done.

    Returns a summary dict with counts.
    """
    cfg = _get_config()

    if not cfg["enabled"]:
        logger.debug("File watcher is disabled (IOC_WATCH_ENABLED=false)")
        return {"enabled": False, "files_processed": 0}

    watch_folder     = cfg["watch_folder"]
    processed_folder = cfg["processed_folder"]

    _ensure_folders(watch_folder, processed_folder)

    # Find all .json and .xml files in the watch folder (non-recursive)
    watch_path = Path(watch_folder)
    files: List[Path] = (
        list(watch_path.glob("*.json")) +
        list(watch_path.glob("*.xml"))
    )

    if not files:
        logger.info("File watcher: no new files in '%s'", watch_folder)
        return {
            "enabled":         True,
            "watch_folder":    watch_folder,
            "files_found":     0,
            "files_processed": 0,
            "files_failed":    0,
            "details":         [],
        }

    logger.info("File watcher: found %d file(s) in '%s'", len(files), watch_folder)

    from app.normalization.stix_parser import parse_stix_bundle
    from app.database.db_manager import insert_indicators

    total_stored     = 0
    total_duplicates = 0
    files_processed  = 0
    files_failed     = 0
    details          = []

    for filepath in files:
        file_result = {
            "file":       filepath.name,
            "status":     "pending",
            "stored":     0,
            "duplicates": 0,
            "error":      None,
            "moved_to":   None,
        }
        try:
            ext = filepath.suffix.lower()

            # Parse the file using existing normalization parsers
            if ext == ".json":
                # Read raw JSON and pass to STIX bundle parser
                import json
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    raw_data = json.load(f)
                # Handle both bare bundle dict and list of objects
                if isinstance(raw_data, list):
                    bundle = {"objects": raw_data}
                elif isinstance(raw_data, dict) and "objects" in raw_data:
                    bundle = raw_data
                else:
                    bundle = {"objects": [raw_data]}
                iocs = parse_stix_bundle(bundle)

            elif ext == ".xml":
                from app.normalization.stix_parser import parse_stix_file_xml
                iocs = parse_stix_file_xml(str(filepath))

            else:
                raise ValueError(f"Unsupported file type: {ext}")

            # Tag each IOC with its source file name
            source_label = f"offline_file:{filepath.name}"
            for ioc in iocs:
                ioc["source"] = source_label

            # Insert into database
            if iocs:
                result = insert_indicators(iocs, source_label=source_label)
                file_result["stored"]     = result.get("stored", 0)
                file_result["duplicates"] = result.get("duplicates", 0)
                total_stored     += file_result["stored"]
                total_duplicates += file_result["duplicates"]
            else:
                logger.warning("File watcher: no IOCs parsed from '%s'", filepath.name)

            # Move file to processed folder
            dest = _move_to_processed(filepath, processed_folder)
            file_result["moved_to"] = dest
            file_result["status"]   = "success"
            files_processed += 1

            logger.info(
                "File watcher: processed '%s' → stored=%d duplicates=%d → moved to '%s'",
                filepath.name, file_result["stored"], file_result["duplicates"], dest,
            )

        except Exception as e:
            file_result["status"] = "error"
            file_result["error"]  = str(e)
            files_failed += 1
            logger.error("File watcher: failed to process '%s': %s", filepath.name, e)

        details.append(file_result)

    summary = {
        "enabled":          True,
        "watch_folder":     watch_folder,
        "processed_folder": processed_folder,
        "files_found":      len(files),
        "files_processed":  files_processed,
        "files_failed":     files_failed,
        "total_stored":     total_stored,
        "total_duplicates": total_duplicates,
        "details":          details,
        "checked_at":       datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        "File watcher complete: processed=%d failed=%d stored=%d",
        files_processed, files_failed, total_stored,
    )
    return summary
