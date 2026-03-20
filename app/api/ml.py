"""
app/api/ml.py
=============
ML anomaly detection endpoints — JWT auth protected.

  GET  /ml/status   → viewer+  (any valid token)
  POST /ml/train    → analyst+ (require_role)
  POST /ml/predict  → analyst+ (require_role)
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field
from typing import Optional

from app.auth.security import verify_token, require_role

router = APIRouter(prefix="/ml", tags=["ML"])


class MLEventRequest(BaseModel):
    event_id:         str           = Field(..., description="Unique event identifier")
    source_ip:        str           = Field(..., description="Source IP address")
    destination_ip:   str           = Field(..., description="Destination IP address")
    source_port:      Optional[int] = Field(None)
    destination_port: Optional[int] = Field(None)
    protocol:         Optional[str] = Field(None)
    timestamp:        Optional[str] = Field(None)


def _detector():
    from app.ml.detector import get_detector
    return get_detector()


@router.get("/status")
def ml_status(user: dict = Depends(verify_token)):
    """Model state + training config. Requires any valid token (viewer+)."""
    try:
        return _detector().status()
    except Exception as e:
        return {"model_trained": False, "events_collected": 0, "error": str(e)}


@router.post("/train")
def ml_train(
    force: bool = Query(False, description="Force training below threshold"),
    user:  dict = Depends(require_role("analyst")),
):
    """Trigger Isolation Forest training. Requires analyst role or higher."""
    try:
        return _detector().train(force=force)
    except ImportError as e:
        raise HTTPException(status_code=503, detail=f"ML deps not installed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict")
def ml_predict(
    event: MLEventRequest,
    user:  dict = Depends(require_role("analyst")),
):
    """Score a single event without saving. Requires analyst role or higher."""
    try:
        result = _detector().analyze(event.model_dump())
        return {"event_id": event.event_id, "ml_analysis": result}
    except ImportError as e:
        raise HTTPException(status_code=503, detail=f"ML deps not installed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    # ── Classifier status endpoint (added for hybrid ML support) ──────────────
@router.get("/classifier/status")
def ml_classifier_status(user: dict = Depends(verify_token)):
    """
    Returns whether the supervised Random Forest classifier is trained,
    which attack classes it knows, and model metadata.
    Requires any valid token (viewer+).
    """
    try:
        from app.ml.classifier import status as clf_status
        return clf_status()
    except Exception as e:
        return {"classifier_trained": False, "error": str(e)}


@router.post("/classifier/predict")
def ml_classifier_predict(
    event: MLEventRequest,
    user:  dict = Depends(require_role("analyst")),
):
    """
    Classify a single event using the trained Random Forest classifier.
    Returns: predicted_class, confidence, is_attack, risk_contribution.
    Requires analyst role or higher.
    """
    try:
        from app.ml.classifier import predict as clf_predict
        result = clf_predict(event.model_dump())
        return {"event_id": event.event_id, "classifier": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))