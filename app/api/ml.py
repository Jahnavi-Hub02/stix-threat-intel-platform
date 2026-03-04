"""
app/api/ml.py
=============
ML anomaly detection endpoints, mounted as a router in main.py.

Keeping these in a separate file means:
- The ML singleton is imported lazily (inside each endpoint function)
- Tests can patch app.ml.detector._detector_instance = None BEFORE
  the TestClient is constructed, guaranteeing a fresh detector per test
- main.py stays clean — one line to include_router

Endpoints
---------
GET  /ml/status   → detector state, training config, last run info
POST /ml/train    → trigger Isolation Forest training
POST /ml/predict  → score a single event (read-only, no DB write)
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional

router = APIRouter(prefix="/ml", tags=["ML"])


# ── Shared request model (mirrors EventRequest in main.py) ────────
class MLEventRequest(BaseModel):
    event_id:         str           = Field(..., description="Unique event identifier")
    source_ip:        str           = Field(..., description="Source IP address")
    destination_ip:   str           = Field(..., description="Destination IP address")
    source_port:      Optional[int] = Field(None)
    destination_port: Optional[int] = Field(None)
    protocol:         Optional[str] = Field(None)
    timestamp:        Optional[str] = Field(None)


# ── Helper — always fetches the current singleton ─────────────────
def _detector():
    """
    Import and return the global AnomalyDetector singleton.
    Called inside each endpoint so monkeypatch in tests can reset
    _detector_instance before the request is processed.
    """
    from app.ml.detector import get_detector
    return get_detector()


# ── Endpoints ─────────────────────────────────────────────────────

@router.get("/status")
def ml_status():
    """
    Current state of the ML anomaly detection subsystem.

    Returns:
    - model_trained        — whether a trained model exists on disk
    - events_collected     — total feature vectors stored for training
    - min_train_samples    — threshold before auto-training triggers
    - retrain_interval     — re-train every N new events
    - contamination        — expected anomaly fraction (IsolationForest param)
    - ready_to_train       — True when enough events collected
    - last_training_run    — details of most recent train() call
    - feature_names        — the 10 features fed into the model
    """
    try:
        return _detector().status()
    except Exception as e:
        # Never crash the API — return degraded status instead
        return {
            "model_trained":     False,
            "events_collected":  0,
            "error":             str(e),
        }


@router.post("/train")
def ml_train(
    force: bool = Query(
        False,
        description=(
            "Force training even if below MIN_TRAIN_SAMPLES threshold. "
            "Useful for testing with small datasets."
        )
    )
):
    """
    Trigger Isolation Forest training on all collected event features.

    - Runs synchronously and returns the result immediately.
    - Auto-training also happens in a background thread once
      MIN_TRAIN_SAMPLES events accumulate.
    - Use force=true in dev/testing to train with fewer samples.
    """
    try:
        result = _detector().train(force=force)
        return result
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=f"ML dependencies not installed: {e}. Run: pip install scikit-learn numpy joblib",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict")
def ml_predict(event: MLEventRequest):
    """
    Score a single event for anomalies WITHOUT persisting it to the database.

    Useful for:
    - Testing the trained model against custom inputs
    - Integrating with external tools that call the API directly

    Returns:
    - anomaly_score    — float 0.0 (normal) to 1.0 (highly anomalous)
    - anomaly_detected — bool threshold decision
    - confidence       — low | medium | high
    - features         — the 10 extracted numeric features
    - explanation      — human-readable reason string
    """
    try:
        result = _detector().analyze(event.model_dump())
        return {
            "event_id":    event.event_id,
            "ml_analysis": result,
        }
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=f"ML dependencies not installed: {e}. Run: pip install scikit-learn numpy joblib",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))