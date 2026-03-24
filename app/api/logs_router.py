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


# ── GET /logs/ioc-health ──────────────────────────────────────────────────────

@router.get("/ioc-health")
def ioc_health(user: dict = Depends(verify_token)):
    """
    Return freshness/expiry statistics for the stored IOC database.
    Shows how many IOCs are active, stale, or expired.
    """
    from app.ingestion.ioc_manager import ioc_health_summary
    return ioc_health_summary()
