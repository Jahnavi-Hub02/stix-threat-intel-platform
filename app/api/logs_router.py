"""
app/api/logs_router.py
=======================
API endpoints for log file analysis.
Combines Module 1 (IOC correlation) + Module 2 (ML analysis) on the same log.

Endpoints:
  POST /logs/check        — check a log file or content against IOCs (Module 1)
  POST /logs/analyze      — ML analysis of a log file or content (Module 2)
  POST /logs/full         — run BOTH modules together (recommended)
  GET  /logs/ioc-health   — IOC freshness/expiry summary
"""
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone

from app.auth.security import verify_token, require_role

router = APIRouter(prefix="/logs", tags=["Log Analysis"])


class LogCheckRequest(BaseModel):
    """Request body for log content check (when not uploading a file)."""
    content:     str  = Field(..., description="Raw log content as a string")
    source_name: str  = Field("api-upload", description="Label for this log source")
    max_lines:   int  = Field(0, ge=0, description="Max lines to check (0=all)")


class LogFileRequest(BaseModel):
    """Request body for checking a log file by path (server-side file)."""
    filepath:  str = Field(..., description="Absolute path to the log file on the server")
    max_lines: int = Field(0, ge=0)


# ── POST /logs/check ─────────────────────────────────────────────────────────

@router.post("/check")
async def check_log(
    file: Optional[UploadFile] = File(None),
    content: Optional[str] = Form(None),
    source_name: str = Form("api-upload"),
    max_lines: int = Form(0),
    user: dict = Depends(require_role("analyst")),
):
    """
    Module 1: Check a log file or content against stored IOCs.
    Upload a file OR provide content as a form field.
    Returns all IOC matches with timestamps.
    """
    from app.ingestion.log_checker import check_log_content
    import tempfile, os

    if file:
        raw = await file.read()
        text = raw.decode("utf-8", errors="replace")
        name = file.filename or "uploaded-file"
    elif content:
        text = content
        name = source_name
    else:
        raise HTTPException(status_code=422, detail="Provide either 'file' or 'content'")

    result = check_log_content(text, source_name=name)
    return {
        "module":    "ioc_correlation",
        "submitted_by": user["sub"],
        **result,
    }


# ── POST /logs/upload ─────────────────────────────────────────────────────────

@router.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    user: dict = Depends(require_role("analyst")),
):
    """
    Upload a log file (.log, .txt, .csv) and scan it for IOC matches.

    This is the main log analysis endpoint for mentors / demo purposes.

    For every matched line it returns:
      - timestamp       : when the scan detected the hit
      - line_number     : exact line in the uploaded file
      - source_ip       : attacker IP extracted from the log line
      - destination_ip  : target IP extracted from the log line (if present)
      - matched_ioc     : the IOC that matched (value, type, confidence, severity)
      - log_line        : the raw log line snippet (first 300 chars)

    Also returns a summary:
      - total_lines_checked
      - total_matches
      - severity_breakdown  (critical / high / medium / low)
    """
    from app.ingestion.log_checker import check_log_content

    # Only allow safe file extensions
    allowed_ext = {".log", ".txt", ".csv", ".syslog"}
    filename = file.filename or "uploaded_file"
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in allowed_ext:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(allowed_ext)}",
        )

    raw  = await file.read()
    text = raw.decode("utf-8", errors="replace")

    if not text.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    result = check_log_content(text, source_name=filename)

    # Build a clean, mentor-friendly response
    hits = result.get("hits", [])
    clean_hits = [
        {
            "timestamp":      h.get("timestamp"),
            "line_number":    h.get("line_number"),
            "source_ip":      h.get("source_ip"),
            "destination_ip": h.get("destination_ip"),
            "severity":       h.get("severity"),
            "matched_ioc": {
                "value":      h["matched_ioc"].get("ioc_value"),
                "type":       h["matched_ioc"].get("ioc_type"),
                "confidence": h["matched_ioc"].get("confidence"),
                "severity":   h["matched_ioc"].get("severity"),
                "source":     h["matched_ioc"].get("source"),
                "last_seen":  h["matched_ioc"].get("last_seen"),
            },
            "log_line": h.get("log_line"),
        }
        for h in hits
    ]

    return {
        "status":               "completed",
        "submitted_by":         user["sub"],
        "filename":             filename,
        "scanned_at":           datetime.now(timezone.utc).isoformat(),
        "total_lines_checked":  result.get("lines_checked", 0),
        "total_matches":        result.get("total_hits", 0),
        "severity_breakdown":   result.get("severity_breakdown", {}),
        "matches":              clean_hits,
    }


# ── POST /logs/analyze ────────────────────────────────────────────────────────

@router.post("/analyze")
async def analyze_log(
    file: Optional[UploadFile] = File(None),
    content: Optional[str] = Form(None),
    source_name: str = Form("api-upload"),
    user: dict = Depends(require_role("analyst")),
):
    """
    Module 2: Analyze a log file or content using ML models.
    Detects unknown/novel threats using Random Forest + Isolation Forest.
    Returns lines where ML detected a malicious pattern.
    """
    from app.ml.log_analyzer import analyze_log_content

    if file:
        raw  = await file.read()
        text = raw.decode("utf-8", errors="replace")
        name = file.filename or "uploaded-file"
    elif content:
        text = content
        name = source_name
    else:
        raise HTTPException(status_code=422, detail="Provide either 'file' or 'content'")

    result = analyze_log_content(text, source_name=name)
    return {
        "module":       "ml_analysis",
        "submitted_by": user["sub"],
        **result,
    }


# ── POST /logs/full ───────────────────────────────────────────────────────────

@router.post("/full")
async def full_log_analysis(
    file: Optional[UploadFile] = File(None),
    content: Optional[str] = Form(None),
    source_name: str = Form("api-upload"),
    user: dict = Depends(require_role("analyst")),
):
    """
    Run BOTH Module 1 (IOC check) AND Module 2 (ML analysis) on the same log.
    This is the recommended endpoint for full threat analysis of a log file.

    Response includes:
      ioc_results  — known threats matched against IOC database
      ml_results   — unknown threats detected by ML models
      combined_hits — lines flagged by either module (deduplicated)
      summary      — total counts, severity breakdown
    """
    from app.ingestion.log_checker import check_log_content
    from app.ml.log_analyzer import analyze_log_content

    if file:
        raw  = await file.read()
        text = raw.decode("utf-8", errors="replace")
        name = file.filename or "uploaded-file"
    elif content:
        text = content
        name = source_name
    else:
        raise HTTPException(status_code=422, detail="Provide either 'file' or 'content'")

    ioc_result = check_log_content(text, source_name=name)
    ml_result  = analyze_log_content(text, source_name=name)

    # Merge hits by line number (deduplicate)
    ioc_lines = {h["line_number"] for h in ioc_result.get("hits", [])}
    ml_lines  = {a["line_number"] for a in ml_result.get("alerts", [])}
    both_lines = ioc_lines & ml_lines

    return {
        "module":        "full_analysis",
        "submitted_by":  user["sub"],
        "source_file":   name,
        "checked_at":    datetime.now(timezone.utc).isoformat(),
        "lines_checked": ioc_result.get("lines_checked", 0),
        "ioc_results": {
            "total_hits":         ioc_result.get("total_hits", 0),
            "severity_breakdown": ioc_result.get("severity_breakdown", {}),
            "hits":               ioc_result.get("hits", []),
        },
        "ml_results": {
            "total_alerts":  ml_result.get("total_alerts", 0),
            "alerts":        ml_result.get("alerts", []),
        },
        "summary": {
            "total_unique_flagged_lines": len(ioc_lines | ml_lines),
            "flagged_by_both":            len(both_lines),
            "flagged_ioc_only":           len(ioc_lines - ml_lines),
            "flagged_ml_only":            len(ml_lines - ioc_lines),
            "confirmed_threats":          len(both_lines),
        },
    }



# ── GET /logs/results ─────────────────────────────────────────────────────────

@router.get("/results")
def get_log_results(
    limit:       int           = 100,
    offset:      int           = 0,
    severity:    Optional[str] = None,
    source_file: Optional[str] = None,
    user:        dict          = Depends(verify_token),
):
    """
    View stored IOC matches found by the background log watcher.

    These are matches saved automatically when the scheduler runs
    (every 5 minutes for logs, every 30 minutes for feeds).

    Filters:
      - severity    : critical / high / medium / low
      - source_file : filename (e.g. SSH_sample.log.log)
    """
    from app.database.db_manager import get_log_scan_results
    results = get_log_scan_results(
        limit=limit, offset=offset,
        severity=severity, source_file=source_file,
    )
    return {
        "total":   len(results),
        "limit":   limit,
        "offset":  offset,
        "filters": {"severity": severity, "source_file": source_file},
        "results": results,
    }


# ── GET /logs/ioc-health ──────────────────────────────────────────────────────

@router.get("/ioc-health")
def ioc_health(user: dict = Depends(verify_token)):
    """
    Return freshness/expiry statistics for the stored IOC database.
    Shows how many IOCs are active, stale, or expired.
    """
    from app.ingestion.ioc_manager import ioc_health_summary
    return ioc_health_summary()


# ── WebSocket: /logs/stream ───────────────────────────────────────────────────
# Mentor requirement: check a log stream (online) against stored IOCs.
#
# Two usage modes:
#
#   MODE A — Tail a server-side file (filepath query param):
#     ws://host/logs/stream?filepath=/var/log/app.log&token=<jwt>
#     Server tails the file and pushes each IOC hit as a JSON message.
#
#   MODE B — Client pushes lines in real time (no filepath):
#     ws://host/logs/stream?token=<jwt>
#     Client sends log lines as text messages; server checks each line
#     against IOCs and pushes back any hits as JSON messages.
#     Send "CLOSE" to end the session cleanly.

from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import json as _json


def _auth_ws(token: str) -> dict:
    """Validate JWT for WebSocket connections (token passed as query param)."""
    from app.auth.security import verify_token_string
    return verify_token_string(token)


@router.websocket("/stream")
async def stream_log_ws(
    websocket: WebSocket,
    filepath:  Optional[str] = None,
    token:     str            = "",
):
    """
    WebSocket endpoint for real-time log stream analysis (Module 1 — IOC check).

    MODE A — server tails a file (pass filepath query param):
      Connects and immediately begins tailing filepath.
      Every new line is checked against the IOC database.
      Only lines that produce an IOC hit are sent back as JSON.
      Send any message to the server to stop tailing gracefully.

    MODE B — client streams lines (no filepath):
      Send log lines one at a time as text messages.
      Server checks each line and immediately replies with:
        - {"hit": true,  ...hit_dict}  if the line matches an IOC
        - {"hit": false, "line_number": N}  if the line is clean
      Send "CLOSE" to end the session.

    Authentication: pass token=<jwt> as a query param.
    """
    # ── Auth ─────────────────────────────────────────────────────────────────
    try:
        _auth_ws(token)
    except Exception:
        await websocket.close(code=4001, reason="Unauthorized: invalid or missing token")
        return

    await websocket.accept()

    # ── MODE A: tail a server-side file ──────────────────────────────────────
    if filepath:
        import os
        # Security: restrict file tailing to allowed directories only.
        # Prevents path traversal (e.g. /etc/passwd, C:\Windows\...)
        abs_fp = os.path.abspath(filepath)
        allowed_roots = [os.path.abspath(d) for d in ["data", "logs"]]
        if not any(abs_fp.startswith(root + os.sep) or abs_fp == root for root in allowed_roots):
            await websocket.send_json({
                "type":    "error",
                "message": f"Access denied: file must be in data/ or logs/ directory.",
            })
            await websocket.close()
            return

        if not os.path.exists(filepath):
            await websocket.send_json({
                "type":    "error",
                "message": f"File not found: {filepath}",
            })
            await websocket.close()
            return

        await websocket.send_json({
            "type":     "connected",
            "mode":     "file_tail",
            "filepath": filepath,
            "message":  f"Tailing {filepath}. IOC hits will appear below.",
        })

        from app.ingestion.log_checker import _check_line, _load_ioc_cache
        import time

        # Pre-load IOC cache once — avoids per-line DB hits during streaming
        ioc_cache = _load_ioc_cache()

        line_num = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)          # seek to end — only tail new lines
                while True:
                    line = f.readline()
                    if not line:
                        # No new data — yield to event loop, then poll again
                        await asyncio.sleep(0.3)
                        # Check if client sent a stop signal
                        try:
                            msg = await asyncio.wait_for(
                                websocket.receive_text(), timeout=0.01
                            )
                            if msg:          # any message from client stops tailing
                                break
                        except asyncio.TimeoutError:
                            pass
                        continue

                    line_num += 1
                    hits = _check_line(line, line_num, filepath, ioc_cache=ioc_cache)
                    for hit in hits:
                        await websocket.send_json({
                            "type":       "ioc_hit",
                            "line_number": hit["line_number"],
                            "severity":    hit["severity"],
                            "matched_ioc": hit["matched_ioc"],
                            "log_line":    hit["log_line"],
                            "timestamp":   hit["timestamp"],
                            "alert":       hit["alert"],
                        })
                    # Yield to event loop on every line to keep the WS responsive
                    await asyncio.sleep(0)

        except WebSocketDisconnect:
            pass
        finally:
            try:
                await websocket.send_json({"type": "closed", "lines_checked": line_num})
                await websocket.close()
            except Exception:
                pass
        return

    # ── MODE B: client pushes lines one at a time ─────────────────────────────
    await websocket.send_json({
        "type":    "connected",
        "mode":    "client_stream",
        "message": "Send log lines as text. Reply will be {hit:true,...} or {hit:false}. Send CLOSE to end.",
    })

    from app.ingestion.log_checker import _check_line, _load_ioc_cache

    # Pre-load IOC cache once — avoids per-line DB hits during streaming
    ioc_cache = _load_ioc_cache()

    line_num = 0
    try:
        while True:
            try:
                raw_line = await asyncio.wait_for(websocket.receive_text(), timeout=60)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping", "message": "still connected"})
                continue

            if raw_line.strip().upper() == "CLOSE":
                await websocket.send_json({
                    "type":          "closed",
                    "lines_checked": line_num,
                })
                break

            line_num += 1
            hits = _check_line(raw_line, line_num, "ws-stream", ioc_cache=ioc_cache)

            if hits:
                for hit in hits:
                    await websocket.send_json({
                        "type":        "ioc_hit",
                        "hit":         True,
                        "line_number": hit["line_number"],
                        "severity":    hit["severity"],
                        "matched_ioc": hit["matched_ioc"],
                        "log_line":    hit["log_line"],
                        "timestamp":   hit["timestamp"],
                        "alert":       True,
                    })
            else:
                await websocket.send_json({
                    "hit":         False,
                    "line_number": line_num,
                })

    except WebSocketDisconnect:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass