"""
app/ml/detector.py  —  Isolation Forest anomaly detector (Layer 2)
Updated analyze() integrates the supervised classifier (Layer 1).
Combined result feeds into POST /event final verdict.
"""
import os, json, logging, threading
from typing import Optional, Dict

logger = logging.getLogger(__name__)

MIN_TRAIN_SAMPLES = int(os.getenv("ML_MIN_TRAIN_SAMPLES","50"))
RETRAIN_INTERVAL  = int(os.getenv("ML_RETRAIN_INTERVAL","100"))
CONTAMINATION     = float(os.getenv("ML_CONTAMINATION","0.05"))
# Module-level DB_PATH — exposed here so tests can monkeypatch it directly
# (conftest.py does: monkeypatch.setattr(ml_det, "DB_PATH", db_file))
DB_PATH = os.getenv("DB_PATH", "database/threat_intel.db")

MODEL_DIR         = os.getenv("ML_MODEL_DIR","models")
MODEL_PATH        = os.path.join(MODEL_DIR,"isolation_forest.pkl")
SCALER_PATH       = os.path.join(MODEL_DIR,"if_scaler.pkl")


def _get_db_path():
    # Uses the module-level DB_PATH so tests can monkeypatch it
    import app.ml.detector as _self
    return _self.DB_PATH

def _init_ml_table():
    import sqlite3
    conn = sqlite3.connect(_get_db_path())
    conn.execute("""CREATE TABLE IF NOT EXISTS ml_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE,
        features_json TEXT NOT NULL,
        anomaly_score REAL,
        is_anomaly INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit(); conn.close()

def _save_features(event_id, features):
    import sqlite3
    try:
        conn = sqlite3.connect(_get_db_path())
        conn.execute("INSERT OR IGNORE INTO ml_events(event_id,features_json) VALUES(?,?)",
                     (event_id, json.dumps(features)))
        conn.commit(); conn.close()
    except Exception as e:
        logger.error("save_features: %s", e)

def _load_all_features():
    import sqlite3
    conn = sqlite3.connect(_get_db_path())
    rows = conn.execute("SELECT features_json FROM ml_events").fetchall()
    conn.close()
    return [json.loads(r[0]) for r in rows]

def _count_events():
    import sqlite3
    conn = sqlite3.connect(_get_db_path())
    n = conn.execute("SELECT COUNT(*) FROM ml_events").fetchone()[0]
    conn.close(); return n

def _update_prediction(event_id, score, is_anomaly):
    import sqlite3
    conn = sqlite3.connect(_get_db_path())
    conn.execute("UPDATE ml_events SET anomaly_score=?,is_anomaly=? WHERE event_id=?",
                 (score, int(is_anomaly), event_id))
    conn.commit(); conn.close()


# ─── Feature Extraction (10 features) ────────────────────────────────────────

def extract_features(event: Dict) -> list:
    import socket, struct
    from datetime import datetime, timezone

    def ip_int(ip):
        try: return struct.unpack("!I",socket.inet_aton(ip or ""))[0]
        except: return 0

    def is_priv(ip):
        v = ip_int(ip)
        for net,mask in [(0x0A000000,0xFF000000),(0xAC100000,0xFFF00000),
                         (0xC0A80000,0xFFFF0000),(0x7F000000,0xFF000000)]:
            if v&mask==net: return 1
        return 0

    dst   = event.get("destination_port") or 0
    src   = event.get("source_port") or 0
    proto = (event.get("protocol") or "").upper()
    pe    = {"TCP":1,"UDP":2,"ICMP":3}.get(proto,0)
    src_i = ip_int(event.get("source_ip",""))
    dst_i = ip_int(event.get("destination_ip",""))

    ADMIN = {4444,5555,6666,7777,9999,1337,31337,22,23,3389}
    cat   = 3 if dst in ADMIN else (1 if dst in {80,443,8080,8443} else
            2 if dst in {3306,5432,1433,27017} else 0)

    ts = event.get("timestamp","")
    try:
        dt  = datetime.fromisoformat(ts.replace("Z","+00:00")).astimezone(timezone.utc)
        hr  = dt.hour; dow = dt.weekday()
    except: hr,dow = 12,0

    ioc_count  = int(event.get("ioc_match_count",0))
    risk_norm  = float(event.get("risk_score",0))/100.0

    return [float(dst), float(src), float(pe),
            float(is_priv(event.get("source_ip",""))),
            float(is_priv(event.get("destination_ip",""))),
            float(hr), float(dow), float(cat),
            float(ioc_count), float(risk_norm)]


# ─── Anomaly Detector ────────────────────────────────────────────────────────

class AnomalyDetector:
    def __init__(self):
        self._model  = None
        self._scaler = None
        self._lock   = threading.Lock()
        self._since_retrain = 0
        os.makedirs(MODEL_DIR, exist_ok=True)
        _init_ml_table()
        self._load()

    def _load(self):
        import app.ml.detector as _mod
        mp = getattr(_mod, "MODEL_PATH", MODEL_PATH)
        sp = getattr(_mod, "SCALER_PATH", SCALER_PATH)
        if os.path.exists(mp) and os.path.exists(sp):
            try:
                self._model  = joblib_load(mp)
                self._scaler = joblib_load(sp)
                logger.info("IF model loaded from disk")
            except Exception as e:
                logger.error("IF model load failed: %s", e)

    def train(self, force=False) -> Dict:
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            import numpy as np, joblib
        except ImportError:
            return {"status":"error","message":"pip install scikit-learn numpy joblib"}

        features = _load_all_features()
        n = len(features)
        if n < MIN_TRAIN_SAMPLES and not force:
            return {"status":"insufficient_data","sample_count":n,
                    "required":MIN_TRAIN_SAMPLES}
        try:
            X       = np.array(features, dtype=float)
            scaler  = StandardScaler()
            X_sc    = scaler.fit_transform(X)
            model   = IsolationForest(n_estimators=200, contamination=CONTAMINATION,
                                       random_state=42, n_jobs=-1)
            model.fit(X_sc)
            with self._lock:
                self._model = model; self._scaler = scaler
                self._since_retrain = 0
            import app.ml.detector as _mod
            joblib.dump(model,  getattr(_mod,"MODEL_PATH",MODEL_PATH))
            joblib.dump(scaler, getattr(_mod,"SCALER_PATH",SCALER_PATH))
            return {"status":"trained","sample_count":n,"contamination":CONTAMINATION}
        except Exception as e:
            return {"status":"error","message":str(e)}

    def analyze(self, event: Dict) -> Dict:
        event_id = event.get("event_id","unknown")
        feats    = extract_features(event)
        _save_features(event_id, feats)

        self._since_retrain += 1
        total = _count_events()
        if (self._model is None and total >= MIN_TRAIN_SAMPLES) or \
           (self._model is not None and self._since_retrain >= RETRAIN_INTERVAL):
            threading.Thread(target=self.train, daemon=True).start()

        # ── Isolation Forest prediction ────────────────────────────────────
        if_result = {"if_status":"not_ready","is_anomaly":False,
                     "anomaly_score":0.0,"if_risk_boost":0}
        if self._model is not None:
            try:
                import numpy as np
                with self._lock:
                    X    = np.array([feats], dtype=float)
                    X_sc = self._scaler.transform(X)
                    raw  = float(self._model.score_samples(X_sc)[0])
                    pred = int(self._model.predict(X_sc)[0])
                score = max(0.0, min(1.0, (-raw - 0.3)/0.4))
                is_a  = (pred == -1) or (score >= 0.65)
                _update_prediction(event_id, score, is_a)
                if_result = {"if_status":"scored","is_anomaly":is_a,
                             "anomaly_score":round(score,4),
                             "if_risk_boost":int(score*30),
                             "confidence":("high" if score>=0.65 else "medium" if score>=0.5 else "low")}
            except Exception as e:
                logger.error("IF predict error: %s", e)
        else:
            if_result["if_status"] = "insufficient_data"

        # ── Supervised classifier prediction ──────────────────────────────
        clf_result = {"classifier_status":"not_trained","is_attack":False,
                      "predicted_class":"UNKNOWN","risk_contribution":0}
        try:
            from app.ml.classifier import predict as clf_predict
            clf_result = clf_predict(event)
        except Exception as e:
            logger.warning("Classifier skipped: %s", e)

        # ── Combine both layers ────────────────────────────────────────────
        combined_anomaly = if_result["is_anomaly"] or clf_result.get("is_attack", False)
        combined_risk    = min(if_result.get("if_risk_boost",0) +
                               clf_result.get("risk_contribution",0), 50)

        # Determine overall ml_status for backward compat.
        # "insufficient_data" if Isolation Forest has no trained model yet.
        # The classifier (RF) may or may not be trained independently.
        if if_result.get("if_status") in ("insufficient_data", "not_ready"):
            top_status = "insufficient_data"
        else:
            top_status = "scored"

        return {
            "ml_status":        top_status,
            "anomaly_detected": combined_anomaly,
            "anomaly_score":    if_result.get("anomaly_score", 0.0),
            "confidence":       if_result.get("confidence", "none"),  # test_ml.py checks this
            "risk_contribution":combined_risk,
            "explanation":      _explain(if_result, clf_result),
            # Detailed breakdown
            "isolation_forest": if_result,
            "classifier":       clf_result,
        }

    def status(self) -> Dict:
        from app.ml.classifier import status as clf_status
        n_events = _count_events()
        clf_st   = clf_status()
        feat_names = [
            "destination_port","source_port","protocol_encoded",
            "is_private_source","is_private_dest",
            "hour_of_day","day_of_week","port_category",
            "ioc_match_count","risk_score_normalized"
        ]

        # ── Surface classifier evaluation at top level ────────────────────────
        # clf_status() includes last_evaluation when rf_evaluation.json exists.
        # Promote the most useful fields so the dashboard sees them directly
        # without needing to dig into nested keys.
        last_eval = clf_st.get("last_evaluation", {})
        evaluation_summary = None
        if last_eval:
            evaluation_summary = {
                "trained_at":    last_eval.get("trained_at"),
                "accuracy":      last_eval.get("accuracy"),
                "accuracy_pct":  f"{last_eval.get('accuracy', 0) * 100:.2f}%",
                "classes":       last_eval.get("classes", []),
                "total_samples": last_eval.get("total_samples"),
                "dataset_type":  last_eval.get("dataset_type"),
                "top_features":  last_eval.get("top_features", [])[:5],
            }

        return {
            # Flat keys — test_ml.py checks these at top level
            "model_trained":     self._model is not None,
            "events_collected":  n_events,
            "min_train_samples": MIN_TRAIN_SAMPLES,
            "contamination":     CONTAMINATION,
            "feature_names":     feat_names,
            # Promoted evaluation summary — visible at top level of /ml/status
            "evaluation":        evaluation_summary,
            # Nested detail
            "isolation_forest": {
                "model_trained":    self._model is not None,
                "events_collected": n_events,
                "min_train_samples":MIN_TRAIN_SAMPLES,
                "contamination":    CONTAMINATION,
            },
            "classifier": clf_st,
        }


def _explain(if_r, clf_r) -> str:
    parts = []
    if clf_r.get("is_attack"):
        parts.append(f"RF: {clf_r['predicted_class']} ({clf_r['confidence']*100:.0f}%)")
    if if_r.get("is_anomaly"):
        parts.append(f"IF: anomaly score {if_r['anomaly_score']:.2f}")
    return " | ".join(parts) if parts else "No threats detected"


def joblib_load(path):
    import joblib
    return joblib.load(path)


# Singleton
_detector_instance = None
_detector_lock     = threading.Lock()

def get_detector() -> AnomalyDetector:
    global _detector_instance
    if _detector_instance is None:
        with _detector_lock:
            if _detector_instance is None:
                _detector_instance = AnomalyDetector()
    return _detector_instance


# ─── Aliases for test compatibility ───────────────────────────────────────────
# conftest.py calls ml_det._create_ml_tables() — alias the internal function
_create_ml_tables = _init_ml_table

# test_ml.py calls det._save_event_features() directly
_save_event_features = _save_features

# conftest.py resets ml_det._detector_instance = None between tests
_detector_instance = None