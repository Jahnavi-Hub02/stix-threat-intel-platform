"""
app/ml/__init__.py
==================
Public API for the ML Analysis System (Module 2).

This package implements the hybrid two-layer threat detection system:

  Layer 1 — Supervised classifier (Random Forest)
    Trained offline on the NSL-KDD dataset (125,973 labelled network
    connections). Predicts attack category: BENIGN, DoS, Probe, R2L, U2R.
    File: classifier.py

  Layer 2 — Unsupervised anomaly detector (Isolation Forest)
    Trained online on live events accumulated from POST /event.
    Detects novel/unknown threats that the RF classifier hasn't seen.
    File: detector.py

  Supporting modules:
    features.py            — 10-feature extraction for live events (IF layer)
    nslkdd_preprocessor.py — full preprocessing pipeline for NSL-KDD training
    log_analyzer.py        — apply both layers to a log file or stream

Mentor-required ML workflow:
  [1] Preprocessing      → nslkdd_preprocessor.preprocess()
  [2] Feature extraction → classifier.extract_live_features() / features.extract_features()
  [3] Dataset splitting  → nslkdd_preprocessor.split()  (80/20 stratified)
  [4] Model training     → classifier.train()  /  AnomalyDetector.train()
  [5] Evaluation         → classifier.train() returns report + saves rf_evaluation.json

Training (offline, historical data only):
  python scripts/train_classifier.py --dataset data/nslkdd/KDDTrain+.txt

Prediction (online, live events only):
  from app.ml import get_detector
  result = get_detector().analyze(event_dict)
"""

# ── Layer 1: Supervised Random Forest classifier ───────────────────────────
from app.ml.classifier import (
    train,                  # train RF on NSL-KDD / CICIDS2017 dataset
    predict,                # classify a single live event dict
    extract_live_features,  # convert live event → 14-feature vector
    status  as clf_status,  # classifier model info + last evaluation
    # Key constants
    NSLKDD_COLS,            # full 43-column NSL-KDD schema
    NSLKDD_MAP,             # 23 attack types → 5 broad categories
    LIVE_FEATURE_COLS,      # 9 NSL-KDD columns used for training
    N_LIVE_FEATURES,        # 14 (9 NSL-KDD + 5 derived)
    ATTACK_RISK,            # risk score contribution per attack class
    CLF_PATH,               # path to saved RF model file
    EVAL_PATH,              # path to rf_evaluation.json
)

# ── Layer 2: Unsupervised Isolation Forest anomaly detector ────────────────
from app.ml.detector import (
    AnomalyDetector,        # main IF class — use get_detector() singleton
    get_detector,           # returns the shared AnomalyDetector instance
    extract_features        as extract_if_features,  # 10-feature vector for IF
)

# ── Feature engineering ────────────────────────────────────────────────────
from app.ml.features import (
    extract_features        as extract_network_features,  # 10-dim network features
    explain_features,       # human-readable feature dict for debugging
    feature_names,          # ordered list of feature name strings
)

# ── NSL-KDD preprocessing pipeline ────────────────────────────────────────
from app.ml.nslkdd_preprocessor import (
    preprocess,             # full pipeline: load→encode→label→split
    load_raw,               # step 1: load KDDTrain+.txt as DataFrame
    encode_categoricals,    # step 2: encode protocol_type, service, flag
    map_labels,             # step 3: map 23 attacks → 5 broad categories
    extract_features        as extract_nslkdd_features,  # step 4: select LIVE_FEATURE_COLS
    remove_rare_classes,    # step 5: drop classes with < MIN_CLASS_SAMPLES rows
    split,                  # step 6: stratified 80/20 train/test split
    dataset_summary,        # dataset stats without training (for API/demo)
)

# ── Log stream analysis ────────────────────────────────────────────────────
from app.ml.log_analyzer import (
    analyze_log_content,    # run both modules on a log string
    analyze_log_file,       # run both modules on a log file path
    analyze_event_ml,       # ML-only analysis of a single event dict
)

__all__ = [
    # Layer 1 — classifier
    "train",
    "predict",
    "extract_live_features",
    "clf_status",
    "NSLKDD_COLS",
    "NSLKDD_MAP",
    "LIVE_FEATURE_COLS",
    "N_LIVE_FEATURES",
    "ATTACK_RISK",
    "CLF_PATH",
    "EVAL_PATH",
    # Layer 2 — anomaly detector
    "AnomalyDetector",
    "get_detector",
    "extract_if_features",
    # Feature engineering
    "extract_network_features",
    "explain_features",
    "feature_names",
    # Preprocessing
    "preprocess",
    "load_raw",
    "encode_categoricals",
    "map_labels",
    "extract_nslkdd_features",
    "remove_rare_classes",
    "split",
    "dataset_summary",
    # Log analysis
    "analyze_log_content",
    "analyze_log_file",
    "analyze_event_ml",
]