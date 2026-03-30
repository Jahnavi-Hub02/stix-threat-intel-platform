"""
STIX 2.1 Threat Intelligence Correlation Platform — REST API v2.5.0
====================================================================
Changes in v2.5.0:
- Added POST /iocs/expire  (analyst+) — manually expire outdated IOCs
- Added GET  /iocs/health  (viewer+)  — IOC freshness/health summary
- Added POST /ml/train-classifier (analyst+) — train RF on NSL-KDD dataset

Changes in v2.4.0:
- Added /alerts/* endpoints (Alert Triage workflow)
- Added event_id path-traversal validation on POST /event
- POST /event now auto-creates an alert for any threat/anomaly detection

Public endpoints  (no token required):
  GET  /          health root
  GET  /health    Docker healthcheck
  POST /auth/register
  POST /auth/login
  POST /auth/refresh
  POST /auth/logout
  POST /auth/logout-all

Viewer endpoints  (any valid token):
  GET  /metrics
  GET  /iocs
  GET  /iocs/{value}
  GET  /iocs/health
  GET  /correlations
  GET  /ml/status
  GET  /scheduler/status
  GET  /ingest/servers
  GET  /auth/me
  GET  /alerts
  GET  /alerts/{id}

Analyst endpoints (role >= analyst):
  POST /event
  POST /iocs/expire
  POST /ml/train
  POST /ml/train-classifier
  POST /ml/predict
  POST /manual-ingest
  POST /ingest/file
  POST /ingest/taxii
  POST /ingest/trigger
  PATCH /alerts/{id}/status

Admin endpoints   (role == admin):
  GET  /auth/users
  DELETE /auth/users/{id}
"""

import re
from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
import os

from app.database import (
    create_tables, get_all_iocs, get_correlation_results,
    get_db_stats, insert_indicators,
)
from app.correlation import correlate_event
from app.utils import generate_report, get_logger
from app.normalization import parse_stix_json, parse_stix_xml
from app.ingestion import (
    TAXIIClient, start_scheduler, get_scheduler_status,
    trigger_ingestion_now, get_public_servers,
)
from app.api.ml import router as ml_router
from app.auth import auth_router, verify_token, require_role
from app.alerts import alerts_router
from app.api.logs_router import router as logs_router

logger = get_logger(__name__)

# Only allow alphanumeric, hyphens, underscores, dots — blocks ../etc/passwd etc.
_SAFE_EVENT_ID = re.compile(r'^[A-Za-z0-9\-_.]+$')


def _now():
    return datetime.now(timezone.utc).isoformat()


def _get_severity(score: float) -> str:
    if score >= 80: return "Critical"
    if score >= 60: return "High"
    if score >= 35: return "Medium"
    return "Low"


# ── Pydantic Models ────────────────────────────────────────────────

class EventRequest(BaseModel):
    event_id:         str           = Field(..., description="Unique event identifier")
    source_ip:        str           = Field(..., description="Source IP address")
    destination_ip:   str           = Field(..., description="Destination IP address")
    source_port:      Optional[int] = Field(None)
    destination_port: Optional[int] = Field(None)
    protocol:         Optional[str] = Field(None)
    timestamp:        Optional[str] = Field(None)


class TAXIIIngestRequest(BaseModel):
    server_url:  str           = Field(..., description="TAXII server URL")
    username:    Optional[str] = Field(None)
    password:    Optional[str] = Field(None)
    api_key:     Optional[str] = Field(None)
    use_delta:   bool          = Field(True)
    max_objects: Optional[int] = Field(None)


class FileIngestRequest(BaseModel):
    file_path: str = Field(..., description="Path to JSON or XML file")
    file_type: str = Field("json", description="File type: json or xml")


# ── Lifespan ───────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    try:
        from app.ml.detector import get_detector
        get_detector()
        logger.info("ML anomaly detector initialised")
    except Exception as e:
        logger.error("ML detector init failed (continuing without ML): %s", str(e))
    try:
        start_scheduler(interval_minutes=30)
        logger.info("TAXII scheduler started")
    except Exception as e:
        logger.error("Failed to start scheduler: %s", str(e))
    yield


# ── Application ────────────────────────────────────────────────────

app = FastAPI(
    title="STIX 2.1 Threat Intelligence Correlation Platform",
    description=(
        "Real-time threat intelligence with IOC correlation, Isolation Forest ML anomaly detection, "
        "and JWT authentication.\n\n"
        "**To use protected endpoints:**\n"
        "1. Register: `POST /auth/register`\n"
        "2. Login: `POST /auth/login` → copy `access_token`\n"
        "3. Click **Authorize** (🔒) and paste: `Bearer <access_token>`"
    ),
    version="2.4.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "https://*.onrender.com",
        os.getenv("FRONTEND_URL", ""),
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
app.include_router(auth_router)    # /auth/*
app.include_router(ml_router)      # /ml/*
app.include_router(alerts_router)  # /alerts/*
app.include_router(logs_router)    # /logs/*


# ── Public Health ──────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {
        "platform":  "STIX 2.1 Threat Intelligence Correlation Platform",
        "version":   "2.4.0",
        "status":    "operational",
        "auth":      "JWT Bearer token required for protected endpoints",
        "docs":      "/docs",
        "timestamp": _now(),
    }


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok"}


# ── Protected: Metrics ─────────────────────────────────────────────

@app.get("/metrics", tags=["Health"])
def get_metrics(user: dict = Depends(verify_token)):
    stats     = get_db_stats()
    scheduler = get_scheduler_status()
    return {
        "timestamp":    _now(),
        "statistics":   stats,
        "requested_by": user["sub"],
        "scheduler": {
            "running":    scheduler.get("is_running", False),
            "next_run":   scheduler.get("next_run"),
            "total_runs": scheduler.get("total_runs", 0),
        },
    }


# ── Protected: IOCs (viewer+) ──────────────────────────────────────

@app.get("/iocs", tags=["IOCs"])
def list_iocs(
    limit:    int           = Query(50, ge=1, le=500),
    offset:   int           = Query(0, ge=0),
    ioc_type: Optional[str] = Query(None),
    user:     dict          = Depends(verify_token),
):
    iocs = get_all_iocs(limit=limit, offset=offset, ioc_type=ioc_type)
    return {"total": len(iocs), "limit": limit, "offset": offset,
            "ioc_type_filter": ioc_type, "iocs": iocs}




@app.get("/iocs/health", tags=["IOCs"])
def ioc_health(user: dict = Depends(verify_token)):
    """
    IOC freshness and health summary.

    Returns counts of total, active, inactive, fresh (last 7 days),
    recently seen (last 30 days), and stale IOCs.

    Requires any valid token (viewer+).
    """
    from app.ingestion.ioc_manager import ioc_health_summary
    return ioc_health_summary()


@app.post("/iocs/expire", tags=["IOCs"])
def expire_iocs(
    max_age_days: int  = Query(default=90, ge=1, le=3650,
                               description="Mark IOCs unseen for this many days as inactive"),
    user:         dict = Depends(require_role("analyst")),
):
    """
    Manually expire outdated IOCs.

    Sets is_active=0 for any IOC whose last_seen timestamp is older than
    max_age_days. This keeps the threat intel database fresh and prevents
    stale indicators from triggering false positives.

    Examples:
      POST /iocs/expire?max_age_days=90   (default — expire IOCs older than 90 days)
      POST /iocs/expire?max_age_days=30   (aggressive — expire IOCs older than 30 days)
      POST /iocs/expire?max_age_days=365  (conservative — expire IOCs older than 1 year)

    Returns:
      expired      — number of IOCs marked inactive
      still_active — number of IOCs still active after expiry

    Requires analyst role or higher.
    """
    from app.ingestion.ioc_manager import expire_outdated_iocs
    result = expire_outdated_iocs(max_age_days=max_age_days)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return {
        "status":       "ok",
        "max_age_days": max_age_days,
        "expired":      result["expired"],
        "still_active": result["still_active"],
        "message": (
            f"Expired {result['expired']} IOC(s) older than {max_age_days} days. "
            f"{result['still_active']} IOC(s) remain active."
        ),
    }

@app.get("/iocs/{ioc_value:path}", tags=["IOCs"])
def lookup_ioc(ioc_value: str, user: dict = Depends(verify_token)):
    from app.database.db_manager import create_connection
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ioc_indicators WHERE ioc_value = ?", (ioc_value,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_value}' not found.")
    return {"status": "found", "ioc": dict(row)}



# ── Protected: Events (analyst+) ──────────────────────────────────

def _run_ml_analysis(event_dict: dict) -> dict:
    try:
        from app.ml.detector import get_detector
        return get_detector().analyze(event_dict)
    except ImportError:
        return {
            "ml_status": "unavailable", "anomaly_detected": False,
            "anomaly_score": 0.0, "confidence": "none", "risk_contribution": 0,
            "explanation": "scikit-learn not installed.",
        }
    except Exception as e:
        logger.error("ML analysis failed (non-fatal): %s", str(e))
        return {
            "ml_status": "error", "anomaly_detected": False,
            "anomaly_score": 0.0, "confidence": "none", "risk_contribution": 0,
            "explanation": str(e),
        }


@app.post("/event", tags=["Events"])
def submit_event(
    event: EventRequest,
    user:  dict = Depends(require_role("analyst")),
):
    """
    Submit a network event for dual-layer threat analysis.
    Requires analyst role or higher.
    event_id must be alphanumeric with hyphens/underscores/dots only
    (path traversal characters like ../ are rejected with 400).
    """
    # ── Validate event_id to prevent path traversal ────────────────
    if not _SAFE_EVENT_ID.match(event.event_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid event_id: only alphanumeric characters, hyphens, underscores, and dots are allowed.",
        )

    event_dict = event.model_dump()
    if not event_dict.get("timestamp"):
        event_dict["timestamp"] = _now()

    ioc_results = correlate_event(event_dict)
    ml_result   = _run_ml_analysis(event_dict)

    ioc_risk   = max((r.get("risk_score", 0) for r in ioc_results), default=0)
    ml_boost   = ml_result.get("risk_contribution", 0)
    final_risk = min(round(ioc_risk + ml_boost, 2), 100.0)
    final_sev  = _get_severity(final_risk)

    ioc_hit    = len(ioc_results) > 0
    ml_anomaly = ml_result.get("anomaly_detected", False)

    if   ioc_hit and ml_anomaly: status_val = "confirmed_threat"
    elif ioc_hit:                status_val = "threat_detected"
    elif ml_anomaly:             status_val = "anomaly_detected"
    else:                        status_val = "benign"

    report_path = generate_report(event_dict, ioc_results, ml_result=ml_result)

    # ── Auto-create alert for any non-benign detection ─────────────
    if status_val != "benign":
        try:
            from app.database.db_manager import create_alert
            create_alert(
                event_id=event.event_id,
                alert_type=status_val,
                risk_score=final_risk,
                severity=final_sev,
                ioc_matches=len(ioc_results),
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
            )
        except Exception as e:
            logger.error("Failed to create alert for event %s: %s", event.event_id, str(e))

    response = {
        "status":           status_val,
        "event_id":         event.event_id,
        "submitted_by":     user["sub"],
        "final_risk_score": final_risk,
        "final_severity":   final_sev,
        "ioc_analysis":     {"matches_found": len(ioc_results), "results": ioc_results},
        "ml_analysis":      ml_result,
        "report":           report_path,
    }
    if ioc_results:
        top = max(ioc_results,
                  key=lambda r: {"Critical":4,"High":3,"Medium":2,"Low":1}.get(r.get("severity","Low"),0))
        response["threats_found"]  = len(ioc_results)
        response["top_severity"]   = top.get("severity")
        response["top_risk_score"] = top.get("risk_score")
    return response


@app.get("/correlations", tags=["Correlations"])
def list_correlations(
    event_id: Optional[str] = Query(None),
    limit:    int            = Query(50, ge=1, le=200),
    user:     dict           = Depends(verify_token),
):
    results = get_correlation_results(event_id=event_id, limit=limit)
    return {"total": len(results), "results": results}


# ── Protected: Reports (viewer+) ──────────────────────────────────

@app.get("/report/{event_id}", tags=["Reports"])
def download_report(event_id: str, user: dict = Depends(verify_token)):
    # Reports are saved under reports/ by generate_report() — look there first,
    # then fall back to cwd for backward compatibility with older deployments.
    report_filename = f"Threat_Report_{event_id}.pdf"
    report_path     = os.path.join("reports", report_filename)
    if not os.path.exists(report_path):
        report_path = report_filename          # cwd fallback
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404,
                            detail=f"Report for '{event_id}' not found.")
    return FileResponse(path=report_path, media_type="application/pdf",
                        filename=report_filename)


# ── Protected: Ingestion (analyst+) ───────────────────────────────

@app.post("/manual-ingest", tags=["Ingestion"])
def manual_ingest(
    feed_type: str  = Query("json", description="'json' (default) or 'both'. XML is legacy."),
    user:      dict = Depends(require_role("analyst")),
):
    """
    Ingest from local sample data files.

    JSON is the preferred format (STIX 2.x, easier to parse than XML).
    XML support is retained as a legacy fallback only.
    For live feeds use POST /ingest/taxii or let the scheduler run.
    """
    results = {"json": 0, "xml": 0}
    if feed_type in ["json", "both"] and os.path.exists("data/TI_GOV.json"):
        r = insert_indicators(parse_stix_json("data/TI_GOV.json")) or {"stored": 0}
        results["json"] = r.get("stored", 0)
    if feed_type == "both" and os.path.exists("data/certin_ti_gov.xml"):
        # Legacy XML file — retained for backward compatibility only.
        # The mentor-preferred approach is TAXII 2.x JSON via /ingest/taxii.
        r = insert_indicators(parse_stix_xml("data/certin_ti_gov.xml")) or {"stored": 0}
        results["xml"] = r.get("stored", 0)
    return {"timestamp": _now(), "ingestion_results": results}


@app.post("/ingest/file", tags=["Ingestion"])
def ingest_from_file(
    request: FileIngestRequest,
    user:    dict = Depends(require_role("analyst")),
):
    if not os.path.exists(request.file_path):
        raise HTTPException(status_code=404, detail=f"File not found: {request.file_path}")
    file_type = request.file_type.lower()
    if file_type not in ("json", "xml"):
        raise HTTPException(status_code=400, detail="file_type must be 'json' or 'xml'")
    try:
        inds   = (parse_stix_json(request.file_path) if file_type == "json"
                  else parse_stix_xml(request.file_path))
        result = insert_indicators(inds) or {"stored": 0, "duplicates": 0}
        return {"timestamp": _now(), "file_path": request.file_path,
                "file_type": request.file_type, "indicators_extracted": len(inds),
                "stored": result.get("stored", 0),
                "duplicates_skipped": result.get("duplicates", 0)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("File ingestion failed: %s", str(e))
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/ingest/taxii", tags=["Ingestion"])
def ingest_from_taxii(
    request:          TAXIIIngestRequest,
    background_tasks: BackgroundTasks,
    user:             dict = Depends(require_role("analyst")),
):
    def _ingest():
        try:
            TAXIIClient(server_url=request.server_url, username=request.username,
                        password=request.password, api_key=request.api_key
                        ).ingest_all_collections(
                use_delta=request.use_delta,
                max_objects_per_collection=request.max_objects)
        except Exception as e:
            logger.error("TAXII ingestion failed: %s", str(e))
    background_tasks.add_task(_ingest)
    return {"status": "accepted", "message": "TAXII ingestion started.",
            "server": request.server_url}


@app.post("/ingest/trigger", tags=["Ingestion"])
def trigger_ingestion_endpoint(
    background_tasks: BackgroundTasks,
    user:             dict = Depends(require_role("analyst")),
):
    def _trigger():
        try:
            trigger_ingestion_now()
        except Exception as e:
            logger.error("Trigger ingestion failed: %s", str(e))
    background_tasks.add_task(_trigger)
    return {"status": "accepted", "message": "Scheduled ingestion triggered."}


@app.get("/ingest/servers", tags=["Ingestion"])
def list_public_servers(user: dict = Depends(verify_token)):
    return {"total": len(servers := get_public_servers()), "servers": servers}


# ── Protected: Scheduler (viewer+) ────────────────────────────────

@app.get("/scheduler/status", tags=["Scheduler"])
def scheduler_status(user: dict = Depends(verify_token)):
    return get_scheduler_status()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)