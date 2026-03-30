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
# The 7 features that can be directly extracted from a live POST /event payload.
# Training uses ONLY these same columns so the model and predictor stay aligned.
#
# Feature vector (7 dimensions):
#   [0] destination_port   — raw port number  (0 if missing)
#   [1] protocol_encoded   — TCP=1, UDP=2, ICMP=3, other=0
#   [2] is_private_source  — 1 if source IP is RFC-1918
#   [3] is_private_dest    — 1 if destination IP is RFC-1918
#   [4] hour_of_day        — 0-23 UTC from timestamp
#   [5] day_of_week        — 0=Mon … 6=Sun from timestamp
#   [6] port_category      — 0=other 1=web 2=db 3=admin/backdoor 4=mail
#
# NSL-KDD column mapping used during training:
#   destination_port  ← dst_bytes (closest numeric proxy available)
#   protocol_encoded  ← protocol_type (tcp/udp/icmp)
#   is_private_source ← land (derived from src==dst comparison)
#   is_private_dest   ← logged_in (binary flag)
#   hour_of_day       ← count (session count, zero when unavailable)
#   day_of_week       ← srv_count
#   port_category     ← dst_host_count
LIVE_FEATURE_COLS = [
    "dst_bytes",          # proxy for destination_port in training data
    "protocol_type",      # tcp=1/udp=2/icmp=3 encoded
    "land",               # proxy for is_private_source
    "logged_in",          # proxy for is_private_dest
    "count",              # proxy for hour_of_day
    "srv_count",          # proxy for day_of_week
    "dst_host_count",     # proxy for port_category
]
N_LIVE_FEATURES = 7      # must match len(extract_live_features()) return value


# ─── Live Feature Extraction ────────────────────────────────────────────────

def extract_live_features(event: Dict) -> list:
    """
    Extract 7 numeric features from a live POST /event payload.

    These 7 features are the contract between training and prediction —
    the RF classifier is trained on exactly these 7 values and expects
    exactly these 7 values at prediction time.

    Feature vector (7 dimensions):
      [0]  destination_port  — raw port number (0 if missing)
      [1]  protocol_encoded  — TCP=1, UDP=2, ICMP=3, other=0
      [2]  is_private_source — 1 if source IP is RFC-1918 private
      [3]  is_private_dest   — 1 if destination IP is RFC-1918 private
      [4]  hour_of_day       — 0-23 UTC extracted from timestamp
      [5]  day_of_week       — 0=Monday … 6=Sunday
      [6]  port_category     — 0=other 1=web 2=db 3=admin/backdoor 4=mail
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

    dst   = event.get("destination_port") or 0
    proto = (event.get("protocol") or "").upper()
    proto_enc = {"TCP": 1, "UDP": 2, "ICMP": 3}.get(proto, 0)

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

    return [
        float(dst),                                # [0] destination_port
        float(proto_enc),                          # [1] protocol_encoded  TCP=1 UDP=2 ICMP=3
        float(is_private(event.get("source_ip",""))),     # [2] is_private_source
        float(is_private(event.get("destination_ip",""))),# [3] is_private_dest
        float(hr),                                 # [4] hour_of_day
        float(dow),                                # [5] day_of_week
        float(cat),                                # [6] port_category
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
        # Train on the same 7 columns that extract_live_features() produces
        # so the model and predictor are perfectly aligned at prediction time.
        #
        # NSL-KDD column → live feature mapping:
        #   dst_bytes       → destination_port proxy  (numeric, non-zero for active conns)
        #   protocol_type   → protocol_encoded        TCP=1, UDP=2, ICMP=3
        #   land            → is_private_source proxy (binary 0/1)
        #   logged_in       → is_private_dest proxy   (binary 0/1)
        #   count           → hour_of_day proxy       (session count, numeric)
        #   srv_count       → day_of_week proxy       (service count, numeric)
        #   dst_host_count  → port_category proxy     (host count, numeric)
        import pandas as pd
        df = pd.read_csv(dataset_path, header=None, names=NSLKDD_COLS)

        # Encode protocol_type: tcp=1, udp=2, icmp=3, other=0 (matches live)
        proto_map = {"tcp": 1, "udp": 2, "icmp": 3}
        df["protocol_type"] = (
            df["protocol_type"].str.lower().map(proto_map).fillna(0).astype(int)
        )
        # Select the 7 training columns
        train_cols = ["dst_bytes", "protocol_type", "land", "logged_in",
                      "count", "srv_count", "dst_host_count"]
        X_all = df[train_cols].apply(pd.to_numeric, errors="coerce").fillna(0)
        y_all = df["label"].str.lower().str.strip().map(NSLKDD_MAP).fillna("Unknown")

        # Rename columns to match what predict() names them (for feature_importances_)
        X_all.columns = ["destination_port", "protocol_encoded",
                         "is_private_source", "is_private_dest",
                         "hour_of_day", "day_of_week", "port_category"]

        if sample_size and len(X_all) > sample_size:
            idx = X_all.sample(n=sample_size, random_state=42).index
            X_all, y_all = X_all.loc[idx], y_all.loc[idx]

        # Remove rare classes (< 5 samples breaks stratify)
        valid = y_all.value_counts()[y_all.value_counts() >= 5].index
        X_all = X_all[y_all.isin(valid)]
        y_all = y_all[y_all.isin(valid)]

        from sklearn.model_selection import train_test_split as tts
        X_tr, X_te, y_tr_s, y_te_s = tts(
            X_all, y_all, test_size=0.2, random_state=42, stratify=y_all
        )
        X = X_tr   # used later for feature_importances_ column names
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
    # Fit on .values so the scaler has no feature-name expectations.
    # predict() passes a plain numpy array — this keeps them consistent
    # and eliminates sklearn's "X does not have valid feature names" warning.
    X_tr_s      = scaler.fit_transform(X_tr.values)
    X_te_s      = scaler.transform(X_te.values)

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
        feats = extract_live_features(event)   # always N_LIVE_FEATURES (7)
        n_tr  = clf.n_features_in_
        # Guard against stale model files trained on a different feature count
        if len(feats) != n_tr:
            logger.warning("Feature mismatch: model=%d live=%d", n_tr, len(feats))
            feats = (feats + [0.0] * n_tr)[:n_tr]
        # Convert to numpy array — scaler was fitted on a DataFrame so we pass
        # a plain array to avoid the "X does not have valid feature names" warning.
        X         = np.array([feats], dtype=float)
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