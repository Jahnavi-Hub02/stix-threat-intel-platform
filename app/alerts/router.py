"""
app/alerts/router.py
====================
Alert Triage endpoints:

  GET    /alerts              — list alerts (viewer+), optional ?status= filter
  GET    /alerts/{id}         — get single alert (viewer+)
  PATCH  /alerts/{id}/status  — update status + notes (analyst+)

Valid statuses: NEW | INVESTIGATING | RESOLVED | FALSE_POSITIVE

PATCH response shape (what tests assert):
  { "new_status": "...", "updated_by": "username", ... }

GET single alert shape (what tests assert):
  { "status", "notes", "assigned_to", "resolved_at", ... }

GET list alert shape (what tests assert):
  { "id", "event_id", "status", "severity", "alert_type",
    "risk_score", "source_ip", "destination_ip", "created_at" }
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime, timezone

from app.auth import verify_token, require_role
from app.database.db_manager import (
    get_all_alerts, get_alert_by_id, get_alert_summary, update_alert,
)

router = APIRouter(prefix="/alerts", tags=["Alerts"])

VALID_STATUSES = {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}


def _now():
    return datetime.now(timezone.utc).isoformat()


class AlertStatusUpdate(BaseModel):
    status: Literal["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"] = Field(
        ..., description="New triage status"
    )
    notes: Optional[str] = Field(None, max_length=1000, description="Analyst notes (max 1000 chars)")


# ── List alerts ────────────────────────────────────────────────────

@router.get("")
def list_alerts(
    status:  Optional[str] = Query(None),
    limit:   int            = Query(50, ge=1, le=500),
    offset:  int            = Query(0, ge=0),
    user:    dict           = Depends(verify_token),
):
    """List all alerts, optionally filtered by status. Requires any valid token."""
    # Unknown status → empty result, not an error
    if status and status not in VALID_STATUSES:
        return {"total": 0, "alerts": [], "summary": get_alert_summary()}

    alerts  = get_all_alerts(status_filter=status, limit=limit, offset=offset)
    summary = get_alert_summary()
    return {"total": len(alerts), "alerts": alerts, "summary": summary}


# ── Get single alert ───────────────────────────────────────────────

@router.get("/{alert_id}")
def get_alert(
    alert_id: int,
    user:     dict = Depends(verify_token),
):
    """Get a single alert by ID. Requires any valid token."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return alert


# ── Update alert status ────────────────────────────────────────────

@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    body:     AlertStatusUpdate,
    user:     dict = Depends(require_role("analyst")),
):
    """Update triage status and optional notes. Requires analyst role or higher."""
    existing = get_alert_by_id(alert_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    resolved_at = _now() if body.status in ("RESOLVED", "FALSE_POSITIVE") else None

    updated = update_alert(
        alert_id=alert_id,
        new_status=body.status,
        notes=body.notes,
        assigned_to=user["sub"],
        resolved_at=resolved_at,
    )

    return {
        "alert_id":   alert_id,
        "new_status": updated["status"],
        "updated_by": user["sub"],
        "notes":      updated.get("notes"),
        "updated_at": updated.get("updated_at"),
    }
