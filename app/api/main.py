from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
import os

from app.database import (
    create_tables,
    get_all_iocs,
    get_correlation_results,
    get_db_stats,
    insert_indicators,
)
from app.correlation import correlate_event
from app.utils import generate_report, get_logger
from app.normalization import parse_stix_json, parse_stix_xml
from app.ingestion import (
    TAXIIClient,
    start_scheduler,
    get_scheduler_status,
    trigger_ingestion_now,
    get_public_servers,
)

logger = get_logger(__name__)


def _now():
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────
# Pydantic Models
# ─────────────────────────────────────────────

class EventRequest(BaseModel):
    event_id:        str           = Field(..., description="Unique event identifier")
    source_ip:       str           = Field(..., description="Source IP address")
    destination_ip:  str           = Field(..., description="Destination IP address")
    source_port:     Optional[int] = Field(None)
    destination_port:Optional[int] = Field(None)
    protocol:        Optional[str] = Field(None)
    timestamp:       Optional[str] = Field(None)


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


# ─────────────────────────────────────────────
# App
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown."""
    create_tables()
    try:
        start_scheduler(interval_minutes=30)
        logger.info("TAXII scheduler started")
    except Exception as e:
        logger.error("Failed to start scheduler: %s", str(e))
    yield


app = FastAPI(
    title="STIX 2.1 Threat Intelligence Correlation Platform",
    description="Real-time cyber threat intelligence correlation using STIX/TAXII standards.",
    version="2.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)


# ─────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {
        "platform": "STIX 2.1 Threat Intelligence Correlation Platform",
        "version": "2.1.0",
        "status": "operational",
        "docs": "/docs",
        "timestamp": _now()
    }


@app.get("/health", tags=["Health"])
def health():
    """Docker/monitoring health check."""
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
        }
    }


# ─────────────────────────────────────────────
# IOC Endpoints
# ─────────────────────────────────────────────

@app.get("/iocs", tags=["IOCs"])
def list_iocs(
    limit:    int          = Query(50,  ge=1, le=500),
    offset:   int          = Query(0,   ge=0),
    ioc_type: Optional[str]= Query(None, description="Filter: ipv4, domain, url, sha256, md5")
):
    """List stored IOCs with pagination and optional type filter."""
    iocs = get_all_iocs(limit=limit, offset=offset, ioc_type=ioc_type)
    return {
        "total":           len(iocs),
        "limit":           limit,
        "offset":          offset,
        "ioc_type_filter": ioc_type,
        "iocs":            iocs
    }


@app.get("/iocs/{ioc_value:path}", tags=["IOCs"])
def lookup_ioc(ioc_value: str):
    """Look up a specific IOC by value (IP, domain, hash, or URL)."""
    from app.database.db_manager import create_connection
    conn   = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ioc_indicators WHERE ioc_value = ?", (ioc_value,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_value}' not found.")
    return {"status": "found", "ioc": dict(row)}


# ─────────────────────────────────────────────
# Event & Correlation
# ─────────────────────────────────────────────

@app.post("/event", tags=["Events"])
def submit_event(event: EventRequest):
    """Submit a network event for IOC correlation. Auto-generates PDF report."""
    event_dict = event.model_dump()
    if not event_dict.get("timestamp"):
        event_dict["timestamp"] = _now()

    results     = correlate_event(event_dict)
    report_path = generate_report(event_dict, results)

    if results:
        top = max(
            results,
            key=lambda r: {"Critical":4,"High":3,"Medium":2,"Low":1}.get(r.get("severity","Low"), 0)
        )
        return {
            "status":         "threat_detected",
            "event_id":       event.event_id,
            "threats_found":  len(results),
            "top_severity":   top.get("severity"),
            "top_risk_score": top.get("risk_score"),
            "report":         report_path,
            "results":        results
        }

    return {
        "status":        "benign",
        "event_id":      event.event_id,
        "threats_found": 0,
        "report":        report_path,
        "results":       []
    }


@app.get("/correlations", tags=["Correlations"])
def list_correlations(
    event_id: Optional[str] = Query(None),
    limit:    int            = Query(50, ge=1, le=200)
):
    """List correlation results, optionally filtered by event ID."""
    results = get_correlation_results(event_id=event_id, limit=limit)
    return {"total": len(results), "results": results}


# ─────────────────────────────────────────────
# Reports
# ─────────────────────────────────────────────

@app.get("/report/{event_id}", tags=["Reports"])
def download_report(event_id: str):
    """Download PDF threat report for a specific event."""
    report_path = f"Threat_Report_{event_id}.pdf"
    if not os.path.exists(report_path):
        raise HTTPException(
            status_code=404,
            detail=f"Report for event '{event_id}' not found. Submit the event first."
        )
    return FileResponse(path=report_path, media_type="application/pdf", filename=report_path)


# ─────────────────────────────────────────────
# Ingestion
# ─────────────────────────────────────────────

@app.post("/manual-ingest", tags=["Ingestion"])
def manual_ingest(feed_type: str = Query("json")):
    """Ingest from the default local data files."""
    results = {"json": 0, "xml": 0}
    if feed_type in ["json", "both"] and os.path.exists("data/TI_GOV.json"):
        inds = parse_stix_json("data/TI_GOV.json")
        r = insert_indicators(inds) or {"stored": 0}
        results["json"] = r.get("stored", 0)
    if feed_type in ["xml", "both"] and os.path.exists("data/certin_ti_gov.xml"):
        inds = parse_stix_xml("data/certin_ti_gov.xml")
        r = insert_indicators(inds) or {"stored": 0}
        results["xml"] = r.get("stored", 0)
    return {"timestamp": _now(), "ingestion_results": results}


@app.post("/ingest/file", tags=["Ingestion"])
def ingest_from_file(request: FileIngestRequest):
    """Ingest IOCs from a local JSON or XML file."""
    if not os.path.exists(request.file_path):
        raise HTTPException(status_code=404, detail=f"File not found: {request.file_path}")

    file_type = request.file_type.lower()
    if file_type not in ("json", "xml"):
        raise HTTPException(status_code=400, detail="file_type must be 'json' or 'xml'")

    try:
        indicators = parse_stix_json(request.file_path) if file_type == "json" \
                     else parse_stix_xml(request.file_path)
        result = insert_indicators(indicators) or {"stored": 0, "duplicates": 0}
        return {
            "timestamp":            _now(),
            "file_path":            request.file_path,
            "file_type":            request.file_type,
            "indicators_extracted": len(indicators),
            "stored":               result.get("stored", 0),
            "duplicates_skipped":   result.get("duplicates", 0),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("File ingestion failed: %s", str(e))
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/ingest/taxii", tags=["Ingestion"])
def ingest_from_taxii(request: TAXIIIngestRequest, background_tasks: BackgroundTasks):
    """Connect to a TAXII server and ingest in the background."""
    def _ingest():
        try:
            client = TAXIIClient(
                server_url=request.server_url,
                username=request.username,
                password=request.password,
                api_key=request.api_key,
            )
            client.ingest_all_collections(
                use_delta=request.use_delta,
                max_objects_per_collection=request.max_objects,
            )
        except Exception as e:
            logger.error("TAXII ingestion failed: %s", str(e))

    background_tasks.add_task(_ingest)
    return {
        "status":  "accepted",
        "message": "TAXII ingestion started in background.",
        "server":  request.server_url,
    }


@app.post("/ingest/trigger", tags=["Ingestion"])
def trigger_ingestion_endpoint(background_tasks: BackgroundTasks):
    """Manually trigger the scheduled TAXII ingestion job in background."""
    def _trigger():
        try:
            trigger_ingestion_now()
        except Exception as e:
            logger.error("Trigger ingestion failed: %s", str(e))

    background_tasks.add_task(_trigger)
    return {
        "status":  "accepted",
        "message": "Scheduled ingestion job triggered manually.",
    }


@app.get("/ingest/servers", tags=["Ingestion"])
def list_public_servers():
    """List all pre-configured public TAXII servers."""
    servers = get_public_servers()
    return {"total": len(servers), "servers": servers}


# ─────────────────────────────────────────────
# Scheduler
# ─────────────────────────────────────────────

@app.get("/scheduler/status", tags=["Scheduler"])
def scheduler_status():
    """Current scheduler state and last 10 ingestion run results."""
    return get_scheduler_status()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)