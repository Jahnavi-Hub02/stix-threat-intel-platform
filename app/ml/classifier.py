"""
app/ml/classifier.py
=====================
Supervised Random Forest classifier — Layer 1 of the hybrid ML system.
Trained offline on NSL-KDD or CICIDS2017 labelled datasets.
At runtime, predicts attack class from live event features.

Dataset instructions:
  NSL-KDD  (fast, ~1 min train): https://github.com/jmnwong/NSL-KDD-Dataset
  CICIDS2017 (full, ~10 min):    https://www.unb.ca/cic/datasets/ids-2017.html
  Kaggle NSL-KDD mirror:         https://www.kaggle.com/datasets/hassan06/nslkdd
"""
import os, json, logging, joblib
import numpy as np
from datetime import datetime, timezone
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

MODEL_DIR    = os.getenv("ML_MODEL_DIR", "models")
CLF_PATH     = os.path.join(MODEL_DIR, "rf_classifier.pkl")
SCALER_PATH  = os.path.join(MODEL_DIR, "rf_scaler.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.pkl")
EVAL_PATH    = os.path.join(MODEL_DIR, "rf_evaluation.json")

# NSL-KDD 41 column names (no header in file)
NSLKDD_COLS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

# Map NSL-KDD specific attacks -> 5 broad categories
NSLKDD_MAP = {
    "normal":"BENIGN",
    "back":"DoS","land":"DoS","neptune":"DoS","pod":"DoS","smurf":"DoS",
    "teardrop":"DoS","apache2":"DoS","udpstorm":"DoS","mailbomb":"DoS",
    "ipsweep":"Probe","nmap":"Probe","portsweep":"Probe","satan":"Probe",
    "mscan":"Probe","saint":"Probe",
    "ftp_write":"R2L","guess_passwd":"R2L","imap":"R2L","multihop":"R2L",
    "phf":"R2L","spy":"R2L","warezclient":"R2L","warezmaster":"R2L",
    "sendmail":"R2L","named":"R2L","snmpgetattack":"R2L","snmpguess":"R2L",
    "xlock":"R2L","xsnoop":"R2L","worm":"R2L",
    "buffer_overflow":"U2R","loadmodule":"U2R","perl":"U2R","rootkit":"U2R",
    "httptunnel":"U2R","ps":"U2R","sqlattack":"U2R","xterm":"U2R",
}

CICIDS_MAP = {
    "benign":"BENIGN","bot":"Botnet",
    "dos hulk":"DoS","dos goldeneye":"DoS","dos slowloris":"DoS",
    "dos slowhttptest":"DoS","heartbleed":"DoS","ddos":"DDoS",
    "ftp-patator":"BruteForce","ssh-patator":"BruteForce",
    "web attack \u2013 brute force":"WebAttack",
    "web attack \u2013 xss":"WebAttack",
    "web attack \u2013 sql injection":"WebAttack",
    "infiltration":"Infiltration","portscan":"PortScan",
}

# Risk contribution per attack class (0-40 points added to final risk score)
ATTACK_RISK = {
    "DoS":12,"DDoS":18,"Botnet":18,"U2R":22,"R2L":14,
    "BruteForce":14,"WebAttack":12,"Probe":8,"Infiltration":20,
    "PortScan":6,"BENIGN":0,
}

# ─── Live-aligned feature columns ────────────────────────────────────────────
# These are the NSL-KDD columns that can be meaningfully extracted from a live
# POST /event payload. Training uses ONLY these columns so that the model
# trained offline matches exactly what predict() sends at runtime.
#
# Mapping to event fields:
#   protocol_type  ← event["protocol"]        (encoded: tcp=0, udp=1, icmp=2, …)
#   dst_bytes      ← 0 (not in live payload, default)
#   land           ← 1 if src_ip == dst_ip else 0
#   logged_in      ← 0 (not in live payload, default)
#   count          ← 0 (not in live payload, default)
#   srv_count      ← 0 (not in live payload, default)
#   dst_host_count ← 0 (not in live payload, default)
#   dst_host_srv_count ← 0 (not in live payload, default)
#   duration       ← 0 (not in live payload, default)
#   dst_port_cat   ← derived from destination_port (web/db/admin/mail/other)
#   hour_of_day    ← derived from event["timestamp"]
#   day_of_week    ← derived from event["timestamp"]
#   is_private_src ← derived from event["source_ip"]
#   is_private_dst ← derived from event["destination_ip"]
LIVE_FEATURE_COLS = [
    "protocol_type",     # encoded integer: tcp=0 udp=1 icmp=2
    "dst_bytes",         # bytes from server → client  (0 if unavailable)
    "land",              # 1 if src_ip == dst_ip
    "logged_in",         # 0 if unavailable
    "count",             # connections to same host/2s window  (0 if unavailable)
    "srv_count",         # connections to same service/2s window (0 if unavailable)
    "dst_host_count",    # (0 if unavailable)
    "dst_host_srv_count",# (0 if unavailable)
    "duration",          # connection duration seconds (0 if unavailable)
]
# Plus 5 derived features appended during extract_live_features():
#   dst_port_cat, hour_of_day, day_of_week, is_private_src, is_private_dst
# Total: 14 features — consistent between train() and predict()
N_LIVE_FEATURES = len(LIVE_FEATURE_COLS) + 5  # = 14


# ─── Live Feature Extraction ────────────────────────────────────────────────

def extract_live_features(event: Dict) -> list:
    """
    Extract 14 numeric features from a live POST /event payload.

    The first 9 features correspond directly to LIVE_FEATURE_COLS (NSL-KDD
    columns). The last 5 are derived from the event's IP/port/timestamp fields.
    This exact vector is what the trained model expects at prediction time.

    Feature vector (14 dimensions):
      [0]  protocol_type    — tcp=0, udp=1, icmp=2, other=3
      [1]  dst_bytes        — 0 (not available in live payload)
      [2]  land             — 1 if source_ip == destination_ip
      [3]  logged_in        — 0 (not available in live payload)
      [4]  count            — 0 (not available in live payload)
      [5]  srv_count        — 0 (not available in live payload)
      [6]  dst_host_count   — 0 (not available in live payload)
      [7]  dst_host_srv_count — 0 (not available in live payload)
      [8]  duration         — 0 (not available in live payload)
      [9]  dst_port_cat     — 0=other 1=web 2=db 3=admin/backdoor 4=mail
      [10] hour_of_day      — 0-23 UTC
      [11] day_of_week      — 0=Mon … 6=Sun
      [12] is_private_src   — 1 if source IP is RFC-1918
      [13] is_private_dst   — 1 if destination IP is RFC-1918
    """
    import socket, struct
    from datetime import datetime, timezone

    def ip_int(ip):
        try:
            return struct.unpack("!I", socket.inet_aton(ip or ""))[0]
        except Exception:
            return 0

    def is_private(ip):
        v = ip_int(ip)
        for net, mask in [(0x0A000000,0xFF000000),(0xAC100000,0xFFF00000),
                          (0xC0A80000,0xFFFF0000),(0x7F000000,0xFF000000)]:
            if v & mask == net:
                return 1
        return 0

    proto = (event.get("protocol") or "").lower()
    proto_enc = {"tcp": 0, "udp": 1, "icmp": 2}.get(proto, 3)

    src_ip = event.get("source_ip", "") or ""
    dst_ip = event.get("destination_ip", "") or ""
    land   = 1 if src_ip and src_ip == dst_ip else 0

    dst = event.get("destination_port") or 0
    WEB   = {80, 443, 8080, 8443, 8000}
    DB    = {1433, 1521, 3306, 5432, 6379, 27017}
    ADMIN = {22, 23, 3389, 4444, 5555, 6666, 7777, 9999, 1337, 31337}
    MAIL  = {25, 110, 143, 465, 587, 993, 995}
    cat   = (1 if dst in WEB else 2 if dst in DB else
             3 if dst in ADMIN else 4 if dst in MAIL else 0)

    ts = event.get("timestamp", "")
    try:
        dt  = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
        hr  = dt.hour
        dow = dt.weekday()
    except Exception:
        hr, dow = 12, 0

    # 9 NSL-KDD aligned features + 5 derived = 14 total
    return [
        float(proto_enc),   # [0] protocol_type
        0.0,                # [1] dst_bytes        (unavailable)
        float(land),        # [2] land
        0.0,                # [3] logged_in        (unavailable)
        0.0,                # [4] count            (unavailable)
        0.0,                # [5] srv_count        (unavailable)
        0.0,                # [6] dst_host_count   (unavailable)
        0.0,                # [7] dst_host_srv_count (unavailable)
        0.0,                # [8] duration         (unavailable)
        float(cat),         # [9] dst_port_cat
        float(hr),          # [10] hour_of_day
        float(dow),         # [11] day_of_week
        float(is_private(src_ip)),   # [12] is_private_src
        float(is_private(dst_ip)),   # [13] is_private_dst
    ]


# ─── Training ────────────────────────────────────────────────────────────────

def train(dataset_path: str, dataset_type: str = "auto",
          sample_size: Optional[int] = None) -> Dict:
    """
    Train Random Forest on NSL-KDD or CICIDS2017.

    Parameters
    ----------
    dataset_path : str   Path to CSV/TXT or directory of CSVs
    dataset_type : str   "nslkdd" | "cicids2017" | "auto"
    sample_size  : int   Rows to sample (None = full dataset)
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.metrics import classification_report, accuracy_score

    # Auto-detect dataset type from filename
    if dataset_type == "auto":
        fname = os.path.basename(dataset_path).lower()
        dataset_type = "nslkdd" if "kdd" in fname else "cicids2017"

    # ── Preprocessing ─────────────────────────────────────────────────────────
    if dataset_type == "nslkdd":
        # Delegate all preprocessing to the dedicated module.
        # This covers: load → encode categoricals → map labels →
        # extract features → remove rare classes → train/test split.
        from app.ml.nslkdd_preprocessor import preprocess
        prep = preprocess(dataset_path, sample_size=sample_size)
        X_tr   = prep["X_train"]
        X_te   = prep["X_test"]
        y_tr_s = prep["y_train"]   # string labels e.g. "BENIGN", "DoS"
        y_te_s = prep["y_test"]
        X      = prep["X_train"]   # used later for feature_importances_ names
    else:
        import pandas as pd, glob
        files = glob.glob(os.path.join(dataset_path,"*.csv")) if os.path.isdir(dataset_path) else [dataset_path]
        df = pd.concat([pd.read_csv(f,low_memory=False) for f in files], ignore_index=True)
        df.columns = df.columns.str.strip()
        label_col  = next(c for c in df.columns if c.lower()=="label")
        df = df.replace([float("inf"),float("-inf")],float("nan")).dropna()
        X_all = df.select_dtypes(include=[np.number]).drop(columns=[label_col], errors="ignore").fillna(0)
        y_all = df[label_col].str.strip().str.lower().map(CICIDS_MAP).fillna("Unknown")
        if sample_size and len(X_all) > sample_size:
            idx = X_all.sample(n=sample_size, random_state=42).index
            X_all, y_all = X_all.loc[idx], y_all.loc[idx]
        valid  = y_all.value_counts()[y_all.value_counts() >= 5].index
        X_all  = X_all[y_all.isin(valid)]
        y_all  = y_all[y_all.isin(valid)]
        from sklearn.model_selection import train_test_split
        X_tr, X_te, y_tr_s, y_te_s = train_test_split(
            X_all, y_all, test_size=0.2, random_state=42, stratify=y_all
        )
        X = X_tr

    # ── Encode string labels → integers for sklearn ───────────────────────────
    le    = LabelEncoder()
    y_tr  = le.fit_transform(y_tr_s)
    y_te  = le.transform(y_te_s)

    scaler      = StandardScaler()
    X_tr_s      = scaler.fit_transform(X_tr)
    X_te_s      = scaler.transform(X_te)

    clf = RandomForestClassifier(n_estimators=200, max_depth=20,
                                  class_weight="balanced", random_state=42, n_jobs=-1)
    clf.fit(X_tr_s, y_tr)

    y_pred   = clf.predict(X_te_s)
    accuracy = accuracy_score(y_te, y_pred)
    report   = classification_report(y_te, y_pred, target_names=le.classes_,
                                     output_dict=True, zero_division=0)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf,    CLF_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le,     ENCODER_PATH)

    top10 = sorted(zip(X.columns.tolist(), clf.feature_importances_),
                   key=lambda x:x[1], reverse=True)[:10]

    # ── Save evaluation report to disk ────────────────────────────────────────
    # Persists training results so GET /ml/status can return them without
    # reloading the model, and so the mentor can review offline.
    evaluation = {
        "trained_at":      datetime.now(timezone.utc).isoformat(),
        "dataset_type":    dataset_type,
        "dataset_path":    dataset_path,
        "total_samples":   len(X),
        "train_samples":   len(X_tr),
        "test_samples":    len(X_te),
        "accuracy":        round(float(accuracy), 4),
        "classes":         le.classes_.tolist(),
        "n_features":      int(clf.n_features_in_),
        "feature_names":   X.columns.tolist(),
        "top_features":    [(f, round(float(i), 4)) for f, i in top10],
        "classification_report": report,
    }
    try:
        with open(EVAL_PATH, "w") as f:
            json.dump(evaluation, f, indent=2)
        logger.info(
            "RF trained — accuracy=%.4f classes=%s eval saved to %s",
            accuracy, le.classes_.tolist(), EVAL_PATH
        )
    except Exception as e:
        # Non-fatal: model is saved even if eval JSON write fails
        logger.warning("Could not save evaluation JSON: %s", e)

    return {
        "status": "trained", "dataset_type": dataset_type,
        "total_samples": len(X), "train_samples": len(X_tr),
        "test_samples": len(X_te), "accuracy": round(float(accuracy),4),
        "classes": le.classes_.tolist(),
        "top_features": [(f, round(float(i),4)) for f,i in top10],
        "classification_report": report,
    }


# ─── Prediction ──────────────────────────────────────────────────────────────

def predict(event: Dict) -> Dict:
    """Classify a live event. Returns class, confidence, is_attack, risk_contribution."""
    if not os.path.exists(CLF_PATH):
        return {"classifier_status":"not_trained","predicted_class":"UNKNOWN",
                "is_attack":False,"confidence":0.0,"all_probabilities":{},
                "risk_contribution":0,
                "explanation":"Run: python scripts/train_classifier.py --dataset data/nslkdd/KDDTrain+.TXT"}
    try:
        clf    = joblib.load(CLF_PATH)
        scaler = joblib.load(SCALER_PATH)
        le     = joblib.load(ENCODER_PATH)
        feats = extract_live_features(event)   # always N_LIVE_FEATURES (14)
        n_tr  = clf.n_features_in_
        # Guard against stale model files trained on a different feature count
        if len(feats) != n_tr:
            logger.warning("Feature mismatch: model=%d live=%d", n_tr, len(feats))
            feats = (feats + [0.0] * n_tr)[:n_tr]
        X         = np.array([feats])
        X_sc      = scaler.transform(X)
        pred_int  = clf.predict(X_sc)[0]
        pred_prob = clf.predict_proba(X_sc)[0]
        label     = le.inverse_transform([pred_int])[0]
        conf      = float(max(pred_prob))
        is_attack = label != "BENIGN"
        base_risk = ATTACK_RISK.get(label, 10) if is_attack else 0
        risk_contribution = int(base_risk * conf)
        return {
            "classifier_status": "scored",
            "predicted_class":   label,
            "is_attack":         is_attack,
            "confidence":        round(conf,3),
            "all_probabilities": {c:round(float(p),3) for c,p in zip(le.classes_,pred_prob)},
            "risk_contribution": risk_contribution,
            "explanation": f"Classified as {label} ({conf*100:.1f}% confidence).",
        }
    except Exception as e:
        logger.error("Classifier predict error: %s", e)
        return {"classifier_status":"error","predicted_class":"UNKNOWN",
                "is_attack":False,"confidence":0.0,"all_probabilities":{},
                "risk_contribution":0,"explanation":str(e)}


def status() -> Dict:
    trained = os.path.exists(CLF_PATH)
    info = {"classifier_trained": trained}
    if trained:
        try:
            clf = joblib.load(CLF_PATH)
            le  = joblib.load(ENCODER_PATH)
            info.update({"classes":le.classes_.tolist(),
                         "n_estimators":clf.n_estimators,
                         "n_features":clf.n_features_in_,
                         "model_size_kb":round(os.path.getsize(CLF_PATH)/1024,1)})
        except Exception as e:
            info["error"] = str(e)
    # Attach last evaluation report if it exists
    if os.path.exists(EVAL_PATH):
        try:
            with open(EVAL_PATH) as f:
                eval_data = json.load(f)
            info["last_evaluation"] = {
                "trained_at": eval_data.get("trained_at"),
                "accuracy":   eval_data.get("accuracy"),
                "classes":    eval_data.get("classes"),
                "total_samples": eval_data.get("total_samples"),
                "dataset_type":  eval_data.get("dataset_type"),
                "top_features":  eval_data.get("top_features", [])[:5],
            }
        except Exception as e:
            info["evaluation_error"] = str(e)
    return info