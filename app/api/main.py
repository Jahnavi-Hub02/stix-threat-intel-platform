"""
STIX 2.1 Threat Intelligence Correlation Platform — REST API v2.2.0
====================================================================
ML anomaly detection (Isolation Forest) is mounted via app/api/ml.py router.
"""

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
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

# ML router — imported here so tests can patch detector before TestClient init
from app.api.ml import router as ml_router

logger = get_logger(__name__)


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
    # Warm up ML detector (creates ml_events table, loads model from disk if exists)
    try:
        from app.ml.detector import get_detector
        get_detector()
        logger.info("ML anomaly detector initialised")
    except Exception as e:
        logger.error("ML detector init failed (continuing without ML): %s", str(e))
    # Start TAXII scheduler
    try:
        start_scheduler(interval_minutes=30)
        logger.info("TAXII scheduler started")
    except Exception as e:
        logger.error("Failed to start scheduler: %s", str(e))
    yield


app = FastAPI(
    title="STIX 2.1 Threat Intelligence Correlation Platform",
    description=(
        "Real-time threat intelligence correlation using STIX/TAXII standards "
        "with Isolation Forest ML anomaly detection."
    ),
    version="2.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Mount ML router at /ml
app.include_router(ml_router)


# ── Health ─────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {
        "platform":  "STIX 2.1 Threat Intelligence Correlation Platform",
        "version":   "2.2.0",
        "status":    "operational",
        "docs":      "/docs",
        "timestamp": _now(),
    }


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok"}


@app.get("/metrics", tags=["Health"])
def get_metrics():
    stats     = get_db_stats()
    scheduler = get_scheduler_status()
    return {
        "timestamp":  _now(),
        "statistics": stats,
        "scheduler": {
            "running":    scheduler.get("is_running", False),
            "next_run":   scheduler.get("next_run"),
            "total_runs": scheduler.get("total_runs", 0),
        },
    }


# ── IOCs ───────────────────────────────────────────────────────────

@app.get("/iocs", tags=["IOCs"])
def list_iocs(
    limit:    int           = Query(50, ge=1, le=500),
    offset:   int           = Query(0, ge=0),
    ioc_type: Optional[str] = Query(None, description="Filter: ipv4, domain, url, sha256, md5"),
):
    iocs = get_all_iocs(limit=limit, offset=offset, ioc_type=ioc_type)
    return {"total": len(iocs), "limit": limit, "offset": offset,
            "ioc_type_filter": ioc_type, "iocs": iocs}


@app.get("/iocs/{ioc_value:path}", tags=["IOCs"])
def lookup_ioc(ioc_value: str):
    from app.database.db_manager import create_connection
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ioc_indicators WHERE ioc_value = ?", (ioc_value,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_value}' not found.")
    return {"status": "found", "ioc": dict(row)}


# ── Events (IOC + ML merged) ───────────────────────────────────────

def _run_ml_analysis(event_dict: dict) -> dict:
    """Run ML anomaly detection; return safe fallback dict on any failure."""
    try:
        from app.ml.detector import get_detector
        return get_detector().analyze(event_dict)
    except ImportError:
        return {
            "ml_status": "unavailable", "anomaly_detected": False,
            "anomaly_score": 0.0, "confidence": "none", "risk_contribution": 0,
            "explanation": "scikit-learn not installed. Run: pip install scikit-learn numpy joblib",
        }
    except Exception as e:
        logger.error("ML analysis failed (non-fatal): %s", str(e))
        return {
            "ml_status": "error", "anomaly_detected": False,
            "anomaly_score": 0.0, "confidence": "none", "risk_contribution": 0,
            "explanation": str(e),
        }


@app.post("/event", tags=["Events"])
def submit_event(event: EventRequest):
    """
    Submit a network event for dual-layer analysis:
      Layer 1 — IOC correlation (signature-based, against STIX database)
      Layer 2 — Isolation Forest anomaly detection (behaviour-based ML)
    Final risk score = IOC risk + ML boost (capped at 100).
    """
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

    if   ioc_hit and ml_anomaly: status = "confirmed_threat"
    elif ioc_hit:                status = "threat_detected"
    elif ml_anomaly:             status = "anomaly_detected"
    else:                        status = "benign"

    report_path = generate_report(event_dict, ioc_results, ml_result=ml_result)

    response = {
        "status":           status,
        "event_id":         event.event_id,
        "final_risk_score": final_risk,
        "final_severity":   final_sev,
        "ioc_analysis":     {"matches_found": len(ioc_results), "results": ioc_results},
        "ml_analysis":      ml_result,
        "report":           report_path,
    }
    # Legacy fields kept for dashboard backward-compat
    if ioc_results:
        top = max(ioc_results,
                  key=lambda r: {"Critical":4,"High":3,"Medium":2,"Low":1}.get(r.get("severity","Low"), 0))
        response["threats_found"]  = len(ioc_results)
        response["top_severity"]   = top.get("severity")
        response["top_risk_score"] = top.get("risk_score")

    return response


@app.get("/correlations", tags=["Correlations"])
def list_correlations(
    event_id: Optional[str] = Query(None),
    limit:    int            = Query(50, ge=1, le=200),
):
    results = get_correlation_results(event_id=event_id, limit=limit)
    return {"total": len(results), "results": results}


# ── Reports ────────────────────────────────────────────────────────

@app.get("/report/{event_id}", tags=["Reports"])
def download_report(event_id: str):
    report_path = f"Threat_Report_{event_id}.pdf"
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404,
                            detail=f"Report for '{event_id}' not found.")
    return FileResponse(path=report_path, media_type="application/pdf",
                        filename=report_path)


# ── Ingestion ──────────────────────────────────────────────────────

@app.post("/manual-ingest", tags=["Ingestion"])
def manual_ingest(feed_type: str = Query("json")):
    results = {"json": 0, "xml": 0}
    if feed_type in ["json", "both"] and os.path.exists("data/TI_GOV.json"):
        r = insert_indicators(parse_stix_json("data/TI_GOV.json")) or {"stored": 0}
        results["json"] = r.get("stored", 0)
    if feed_type in ["xml", "both"] and os.path.exists("data/certin_ti_gov.xml"):
        r = insert_indicators(parse_stix_xml("data/certin_ti_gov.xml")) or {"stored": 0}
        results["xml"] = r.get("stored", 0)
    return {"timestamp": _now(), "ingestion_results": results}


@app.post("/ingest/file", tags=["Ingestion"])
def ingest_from_file(request: FileIngestRequest):
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
def ingest_from_taxii(request: TAXIIIngestRequest, background_tasks: BackgroundTasks):
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
    return {"status": "accepted", "message": "TAXII ingestion started.", "server": request.server_url}


@app.post("/ingest/trigger", tags=["Ingestion"])
def trigger_ingestion_endpoint(background_tasks: BackgroundTasks):
    def _trigger():
        try:
            trigger_ingestion_now()
        except Exception as e:
            logger.error("Trigger ingestion failed: %s", str(e))
    background_tasks.add_task(_trigger)
    return {"status": "accepted", "message": "Scheduled ingestion job triggered manually."}


@app.get("/ingest/servers", tags=["Ingestion"])
def list_public_servers():
    return {"total": len(servers := get_public_servers()), "servers": servers}


# ── Scheduler ─────────────────────────────────────────────────────

@app.get("/scheduler/status", tags=["Scheduler"])
def scheduler_status():
    return get_scheduler_status()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)