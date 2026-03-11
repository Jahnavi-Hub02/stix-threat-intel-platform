"""
app/ml/detector.py
==================
Isolation Forest anomaly detector for network events.

Lifecycle:
  1. Events arrive via /event endpoint → features extracted → stored in ml_events table
  2. Once MIN_TRAIN_SAMPLES events accumulated → model auto-trains
  3. Every RETRAIN_INTERVAL new events → model retrains on all historical data
  4. Model persisted to models/isolation_forest.pkl between server restarts
  5. Predictions return anomaly_score (0.0–1.0) + boolean anomaly_detected

Anomaly score interpretation:
  0.0 – 0.3  → Normal traffic
  0.3 – 0.5  → Slightly unusual
  0.5 – 0.7  → Suspicious
  0.7 – 1.0  → Strong anomaly
"""

import os
import json
import threading
from datetime import datetime, timezone
from typing import Optional

from app.utils.logger import get_logger
from app.ml.features import extract_features, explain_features, feature_names

DB_PATH = os.getenv("DB_PATH", "data/events.db")

logger = get_logger(__name__)

# ── Configuration ─────────────────────────────────────────────────
MIN_TRAIN_SAMPLES  = int(os.getenv("ML_MIN_TRAIN_SAMPLES", "50"))   # lower for faster testing
RETRAIN_INTERVAL   = int(os.getenv("ML_RETRAIN_INTERVAL",  "100"))  # retrain every N new events
CONTAMINATION      = float(os.getenv("ML_CONTAMINATION",   "0.05")) # expected anomaly fraction
MODEL_DIR          = os.getenv("ML_MODEL_DIR", "models")
MODEL_PATH         = os.path.join(MODEL_DIR, "isolation_forest.pkl")
SCALER_PATH        = os.path.join(MODEL_DIR, "scaler.pkl")

# Anomaly score thresholds
THRESHOLD_SUSPICIOUS = 0.50
THRESHOLD_ANOMALY    = 0.65


def _lazy_imports():
    """
    Import sklearn lazily so the app starts even if scikit-learn is missing.
    Raises ImportError with a clear message if not installed.
    """
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        import numpy as np
        import joblib
        return IsolationForest, StandardScaler, np, joblib
    except ImportError as e:
        raise ImportError(
            "scikit-learn is required for ML features. "
            "Run: pip install scikit-learn numpy joblib"
        ) from e


# ── Database helpers (local to avoid circular import) ────────────

def _get_db_path():
    from app.database.db_manager import DB_PATH
    return DB_PATH


def _create_ml_tables():
    """Create ml_events table if it doesn't exist."""
    import sqlite3
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ml_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id     TEXT UNIQUE,
            features_json TEXT NOT NULL,
            anomaly_score REAL,
            is_anomaly    INTEGER DEFAULT 0,
            used_in_train INTEGER DEFAULT 0,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ml_model_runs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            trained_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sample_count    INTEGER,
            contamination   REAL,
            status          TEXT,
            error_message   TEXT
        )
    """)
    conn.commit()
    conn.close()


def _save_event_features(event_id: str, features: list):
    """Persist feature vector to ml_events table."""
    import sqlite3
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT OR IGNORE INTO ml_events (event_id, features_json) VALUES (?, ?)",
            (event_id, json.dumps(features))
        )
        conn.commit()
    except Exception as e:
        logger.error("Failed to save ML event features: %s", str(e))
    finally:
        conn.close()


def _load_all_features() -> list:
    """Load all stored feature vectors from ml_events table."""
    import sqlite3
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    cursor.execute("SELECT features_json FROM ml_events ORDER BY created_at ASC")
    rows = cursor.fetchall()
    conn.close()
    return [json.loads(r[0]) for r in rows]


def _count_stored_events() -> int:
    import sqlite3
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM ml_events")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def _log_model_run(sample_count: int, status: str, error: str = None):
    import sqlite3
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO ml_model_runs (sample_count, contamination, status, error_message) VALUES (?,?,?,?)",
        (sample_count, CONTAMINATION, status, error)
    )
    conn.commit()
    conn.close()


def _update_prediction(event_id: str, score: float, is_anomaly: bool):
    import sqlite3
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE ml_events SET anomaly_score=?, is_anomaly=? WHERE event_id=?",
        (score, int(is_anomaly), event_id)
    )
    conn.commit()
    conn.close()


# ── Detector Class ────────────────────────────────────────────────

class AnomalyDetector:
    """
    Singleton Isolation Forest detector.

    Usage:
        detector = get_detector()
        result = detector.analyze(event_dict)
    """

    def __init__(self):
        self._model  = None
        self._scaler = None
        self._lock   = threading.Lock()
        self._event_count_since_retrain = 0

        os.makedirs(MODEL_DIR, exist_ok=True)
        _create_ml_tables()
        self._try_load_model()

    # ── Model persistence ────────────────────────────────────────

    def _try_load_model(self):
        """Load model from disk if it exists."""
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                _, _, _, joblib = _lazy_imports()
                self._model  = joblib.load(MODEL_PATH)
                self._scaler = joblib.load(SCALER_PATH)
                logger.info("ML model loaded from disk: %s", MODEL_PATH)
            except Exception as e:
                logger.error("Failed to load ML model from disk: %s", str(e))
                self._model = None

    def _save_model(self):
        """Persist trained model and scaler to disk."""
        try:
            _, _, _, joblib = _lazy_imports()
            joblib.dump(self._model,  MODEL_PATH)
            joblib.dump(self._scaler, SCALER_PATH)
            logger.info("ML model saved to %s", MODEL_PATH)
        except Exception as e:
            logger.error("Failed to save ML model: %s", str(e))

    # ── Training ─────────────────────────────────────────────────

    def train(self, force: bool = False) -> dict:
        """
        Train (or retrain) the Isolation Forest on all stored events.

        Parameters
        ----------
        force : bool
            If True, train even if below MIN_TRAIN_SAMPLES threshold.

        Returns
        -------
        dict with keys: status, sample_count, message
        """
        IsolationForest, StandardScaler, np, joblib = _lazy_imports()

        features_list = _load_all_features()
        n = len(features_list)

        if n < MIN_TRAIN_SAMPLES and not force:
            return {
                "status": "insufficient_data",
                "sample_count": n,
                "required": MIN_TRAIN_SAMPLES,
                "message": f"Need {MIN_TRAIN_SAMPLES - n} more events before training."
            }

        try:
            X = np.array(features_list, dtype=float)

            # Fit scaler on training data
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            # Train Isolation Forest
            # n_estimators=200 → more trees = more stable scores
            # max_samples='auto' → uses min(256, n_samples)
            # contamination = expected fraction of anomalies
            model = IsolationForest(
                n_estimators=200,
                max_samples="auto",
                contamination=CONTAMINATION,
                random_state=42,
                n_jobs=-1,       # use all CPU cores
                warm_start=False
            )
            model.fit(X_scaled)

            with self._lock:
                self._model  = model
                self._scaler = scaler
                self._event_count_since_retrain = 0

            self._save_model()
            _log_model_run(n, "success")

            logger.info("ML model trained on %d events (contamination=%.2f)", n, CONTAMINATION)
            return {
                "status":       "trained",
                "sample_count": n,
                "contamination": CONTAMINATION,
                "message":      f"Isolation Forest trained on {n} events."
            }

        except Exception as e:
            _log_model_run(n if 'n' in dir() else 0, "error", str(e))
            logger.error("ML training failed: %s", str(e))
            return {
                "status":  "error",
                "message": str(e)
            }

    # ── Prediction ───────────────────────────────────────────────

    def analyze(self, event: dict) -> dict:
        """
        Analyze a network event for anomalies.

        Steps:
          1. Extract features from event
          2. Save features to database (for future training)
          3. Trigger auto-training if threshold reached
          4. If model is trained, score the event
          5. Return analysis result

        Returns
        -------
        dict with keys:
          - ml_status: 'scored' | 'insufficient_data' | 'model_not_ready' | 'error'
          - anomaly_detected: bool
          - anomaly_score: float (0.0–1.0)
          - confidence: 'low' | 'medium' | 'high'
          - risk_contribution: int (0–30 added to final risk score)
          - features: dict (feature name → value)
          - explanation: str
        """
        event_id = event.get("event_id", "unknown")

        # Step 1: Extract features
        try:
            features = extract_features(event)
            feature_dict = explain_features(event)
        except Exception as e:
            logger.error("Feature extraction failed for %s: %s", event_id, str(e))
            return self._error_result("Feature extraction failed")

        # Step 2: Persist features
        _save_event_features(event_id, features)

        # Step 3: Auto-train / auto-retrain check
        self._event_count_since_retrain += 1
        total = _count_stored_events()

        should_train = (
            self._model is None and total >= MIN_TRAIN_SAMPLES
        ) or (
            self._model is not None and self._event_count_since_retrain >= RETRAIN_INTERVAL
        )

        if should_train:
            logger.info("Auto-training ML model (total events: %d)", total)
            threading.Thread(target=self.train, daemon=True).start()

        # Step 4: Score the event
        if self._model is None:
            return {
                "ml_status":        "insufficient_data",
                "anomaly_detected": False,
                "anomaly_score":    0.0,
                "confidence":       "none",
                "risk_contribution": 0,
                "events_collected": total,
                "events_needed":    max(0, MIN_TRAIN_SAMPLES - total),
                "features":         feature_dict,
                "explanation":      f"Collecting training data ({total}/{MIN_TRAIN_SAMPLES} events)."
            }

        try:
            IsolationForest, StandardScaler, np, joblib = _lazy_imports()

            with self._lock:
                X = np.array([features], dtype=float)
                X_scaled = self._scaler.transform(X)

                # score_samples returns negative average depth
                # More negative = more anomalous
                raw_score = self._model.score_samples(X_scaled)[0]
                prediction = self._model.predict(X_scaled)[0]  # -1=anomaly, 1=normal

            # Normalise raw_score to 0.0–1.0 range
            # score_samples typically ranges from -0.7 to -0.3
            # We invert and normalise: higher = more anomalous
            anomaly_score = float(max(0.0, min(1.0, (-raw_score - 0.3) / 0.4)))

            is_anomaly = (prediction == -1) or (anomaly_score >= THRESHOLD_ANOMALY)

            # Confidence tier
            if anomaly_score >= THRESHOLD_ANOMALY:
                confidence = "high"
            elif anomaly_score >= THRESHOLD_SUSPICIOUS:
                confidence = "medium"
            else:
                confidence = "low"

            # Risk contribution: 0–30 points added to IOC-based risk score
            risk_contribution = int(anomaly_score * 30)

            explanation = _build_explanation(feature_dict, anomaly_score, is_anomaly)

            _update_prediction(event_id, anomaly_score, is_anomaly)

            return {
                "ml_status":         "scored",
                "anomaly_detected":  is_anomaly,
                "anomaly_score":     round(anomaly_score, 4),
                "confidence":        confidence,
                "risk_contribution": risk_contribution,
                "features":          feature_dict,
                "explanation":       explanation,
            }

        except Exception as e:
            logger.error("ML prediction failed for %s: %s", event_id, str(e))
            return self._error_result(f"Prediction failed: {str(e)}")

    # ── Status ───────────────────────────────────────────────────

    def status(self) -> dict:
        """Return current ML subsystem status."""
        total = _count_stored_events()

        # Get last training run info
        import sqlite3
        last_run = None
        try:
            conn = sqlite3.connect(_get_db_path())
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM ml_model_runs ORDER BY trained_at DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if row:
                last_run = dict(zip([d[0] for d in cursor.description], row))
            conn.close()
        except Exception:
            pass

        return {
            "model_trained":      self._model is not None,
            "model_path":         MODEL_PATH if os.path.exists(MODEL_PATH) else None,
            "events_collected":   total,
            "min_train_samples":  MIN_TRAIN_SAMPLES,
            "retrain_interval":   RETRAIN_INTERVAL,
            "contamination":      CONTAMINATION,
            "ready_to_train":     total >= MIN_TRAIN_SAMPLES,
            "last_training_run":  last_run,
            "feature_names":      feature_names,
        }

    # ── Helpers ──────────────────────────────────────────────────

    @staticmethod
    def _error_result(message: str) -> dict:
        return {
            "ml_status":         "error",
            "anomaly_detected":  False,
            "anomaly_score":     0.0,
            "confidence":        "none",
            "risk_contribution": 0,
            "features":          {},
            "explanation":       message,
        }


# ── Explanation Builder ───────────────────────────────────────────

def _build_explanation(features: dict, score: float, is_anomaly: bool) -> str:
    """
    Generate a human-readable explanation of why this event was flagged.
    Looks at the most suspicious individual features.
    """
    flags = []

    dst_port = int(features.get("dest_port", 0))
    src_port = int(features.get("source_port", 0))
    hour     = int(features.get("hour_of_day", 12))
    cat      = int(features.get("dest_port_category", 0))
    is_priv_src = int(features.get("is_private_source", 0))
    is_priv_dst = int(features.get("is_private_dest", 0))
    ratio    = features.get("port_ratio", 0)

    if cat == 3:  # ADMIN_PORTS
        flags.append(f"suspicious destination port {dst_port} (admin/backdoor category)")
    if hour < 5 or hour > 22:
        flags.append(f"unusual hour of activity ({hour:02d}:00 UTC)")
    if src_port > 49000 and dst_port > 49000:
        flags.append("both ports are high ephemeral (non-standard service pattern)")
    if is_priv_src == 0 and is_priv_dst == 0:
        flags.append("external-to-external traffic (both IPs are public)")
    if ratio > 100:
        flags.append(f"high port asymmetry ratio ({ratio:.1f})")
    if dst_port == 0 and src_port == 0:
        flags.append("missing port information")

    if not flags:
        if is_anomaly:
            flags.append("statistical outlier based on overall traffic patterns")
        else:
            flags.append("traffic within normal parameters")

    severity_label = (
        "ANOMALY DETECTED" if score >= 0.65 else
        "SUSPICIOUS"       if score >= 0.50 else
        "normal"
    )

    return f"{severity_label} (score={score:.2f}): {'; '.join(flags)}"


# ── Singleton ─────────────────────────────────────────────────────

_detector_instance: Optional[AnomalyDetector] = None
_detector_lock = threading.Lock()


def get_detector() -> AnomalyDetector:
    """Get or create the global singleton AnomalyDetector."""
    global _detector_instance
    if _detector_instance is None:
        with _detector_lock:
            if _detector_instance is None:
                _detector_instance = AnomalyDetector()
    return _detector_instance
