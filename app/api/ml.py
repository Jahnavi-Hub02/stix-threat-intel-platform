"""
app/api/ml.py
=============
ML anomaly detection endpoints — JWT auth protected.

  GET  /ml/status              → viewer+  (any valid token)
  GET  /ml/classifier/status   → viewer+  (any valid token)
  POST /ml/train               → analyst+ (Isolation Forest retraining on live events)
  POST /ml/train-classifier    → analyst+ (Random Forest on NSL-KDD dataset)
  POST /ml/predict             → analyst+
  POST /ml/classifier/predict  → analyst+
"""

import os
from fastapi import APIRouter, HTTPException, Query, Depends, BackgroundTasks
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
    """
    Full ML system status — Isolation Forest + Random Forest + evaluation.

    Returns:
      model_trained        — whether IF anomaly detector is trained
      events_collected     — live events accumulated for IF training
      evaluation           — last RF training result (accuracy, classes, top features)
      classifier           — RF classifier detail (trained_at, n_features, etc.)
      isolation_forest     — IF detail (trained, contamination, etc.)
      dataset_summary      — NSL-KDD dataset stats (if dataset file is present)

    Requires any valid token (viewer+).
    """
    try:
        result = _detector().status()
    except Exception as e:
        return {"model_trained": False, "events_collected": 0, "error": str(e)}

    # Attach dataset summary so the dashboard can show dataset stats
    # without a separate API call. Non-fatal if dataset file is absent.
    dataset_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "data", "nslkdd", "KDDTrain+.txt"
    )
    if os.path.exists(dataset_path):
        try:
            from app.ml.nslkdd_preprocessor import dataset_summary
            result["dataset_summary"] = dataset_summary(dataset_path)
        except Exception as e:
            result["dataset_summary"] = {"error": str(e)}
    else:
        result["dataset_summary"] = {
            "available": False,
            "message": "Place KDDTrain+.txt at data/nslkdd/KDDTrain+.txt to see stats",
        }

    return result


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

# ── Train RF Classifier endpoint ──────────────────────────────────────────────

class TrainClassifierRequest(BaseModel):
    dataset_path: str = Field(
        default="data/nslkdd/KDDTrain+.txt",
        description="Path to KDDTrain+.txt relative to the project root"
    )
    sample_size: Optional[int] = Field(
        default=None,
        ge=100,
        description="Number of rows to sample. None = full dataset (~125k rows, ~2 min)"
    )
    background: bool = Field(
        default=False,
        description="Run training in a background task and return immediately"
    )


def _run_training(dataset_path: str, sample_size: Optional[int]):
    """Internal helper — called directly or via BackgroundTasks."""
    from app.ml.classifier import train
    return train(
        dataset_path=dataset_path,
        dataset_type="nslkdd",
        sample_size=sample_size,
    )


@router.post("/train-classifier")
def ml_train_classifier(
    req:               TrainClassifierRequest,
    background_tasks:  BackgroundTasks,
    user:              dict = Depends(require_role("analyst")),
):
    """
    Train the supervised Random Forest classifier (Layer 1) on the NSL-KDD
    dataset. This is the OFFLINE training step — historical data only.
    Live events are never used to retrain the RF classifier.

    - background=false  (default): trains synchronously, returns full result
    - background=true:  fires training in a background task, returns immediately

    Requires analyst role or higher.
    """
    # Resolve path relative to project root so it works regardless of cwd
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)
    )))
    abs_path = (req.dataset_path if os.path.isabs(req.dataset_path)
                else os.path.join(project_root, req.dataset_path))

    if not os.path.exists(abs_path):
        raise HTTPException(
            status_code=404,
            detail=(
                f"Dataset not found: {req.dataset_path}. "
                "Place KDDTrain+.txt at data/nslkdd/KDDTrain+.txt "
                "or pass an absolute path."
            )
        )

    if req.background:
        # Fire-and-forget — returns immediately, training runs in background
        background_tasks.add_task(_run_training, abs_path, req.sample_size)
        return {
            "status": "training_started",
            "message": "RF classifier training running in background.",
            "dataset_path": req.dataset_path,
            "sample_size":  req.sample_size,
            "tip": "Poll GET /ml/classifier/status to check when trained_at updates.",
        }

    # Synchronous training — blocks until complete (use sample_size for fast runs)
    try:
        result = _run_training(abs_path, req.sample_size)
    except ImportError as e:
        raise HTTPException(status_code=503, detail=f"ML deps missing: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if result.get("status") != "trained":
        raise HTTPException(status_code=500, detail=f"Training failed: {result}")

    return result