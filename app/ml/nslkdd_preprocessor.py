"""
app/ml/nslkdd_preprocessor.py
==============================
Dedicated preprocessing module for the NSL-KDD intrusion detection dataset.

This module is the first step in the mentor-required ML pipeline:
    [1] preprocessing  ← this file
    [2] feature extraction
    [3] dataset splitting
    [4] model training
    [5] evaluation

Why a separate module?
-----------------------
Keeping preprocessing isolated from training (classifier.py) means:
  - It can be unit-tested independently
  - The mentor can inspect the full preprocessing logic in one place
  - It can be reused for future datasets (KDDTest+.txt, CICIDS2017, etc.)
  - Changes to preprocessing don't risk breaking the classifier API

NSL-KDD Dataset Format
-----------------------
  - 125,973 rows, no header row
  - 43 columns: 41 features + label + difficulty score
  - 3 categorical columns: protocol_type, service, flag
  - Label column (col 42): 23 specific attack types mapped to 5 broad categories

Attack Category Mapping
------------------------
  BENIGN  → normal traffic
  DoS     → neptune, smurf, back, teardrop, pod, land, apache2, udpstorm, mailbomb
  Probe   → ipsweep, nmap, portsweep, satan, mscan, saint
  R2L     → warezclient, guess_passwd, imap, warezmaster, ftp_write, phf, spy, etc.
  U2R     → buffer_overflow, rootkit, loadmodule, perl, httptunnel, etc.

Protocol Encoding (matches extract_live_features() in classifier.py)
----------------------------------------------------------------------
  tcp=0, udp=1, icmp=2, other=3
"""

import os
import logging
import pandas as pd
import numpy as np
from typing import Optional, Tuple, Dict
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Import column names and label map from classifier so they stay in sync
from app.ml.classifier import NSLKDD_COLS, NSLKDD_MAP, LIVE_FEATURE_COLS

logger = logging.getLogger(__name__)

# ── Protocol encoding — must match extract_live_features() exactly ─────────
# tcp=0, udp=1, icmp=2, other=3
# This is intentionally different from a generic LabelEncoder so that the
# trained model and live prediction always use the same numeric values.
PROTOCOL_ENCODING = {"tcp": 0, "udp": 1, "icmp": 2}

# Minimum rows a class must have to be included in training.
# Classes below this threshold are dropped to avoid misleading metrics.
MIN_CLASS_SAMPLES = 5


# ── Public API ────────────────────────────────────────────────────────────────

def load_raw(path: str) -> pd.DataFrame:
    """
    Load the raw KDDTrain+.txt file into a DataFrame.

    Parameters
    ----------
    path : str
        Path to KDDTrain+.txt (no header row, comma-separated).

    Returns
    -------
    pd.DataFrame with columns named after NSLKDD_COLS (43 columns total).

    Raises
    ------
    FileNotFoundError if the file does not exist.
    ValueError if the file has the wrong number of columns.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"NSL-KDD dataset not found at: {path}\n"
            "Download from: https://github.com/jmnwong/NSL-KDD-Dataset\n"
            "Place at: data/nslkdd/KDDTrain+.txt"
        )

    df = pd.read_csv(path, header=None, names=NSLKDD_COLS)

    if df.shape[1] != len(NSLKDD_COLS):
        raise ValueError(
            f"Expected {len(NSLKDD_COLS)} columns, got {df.shape[1]}. "
            "Check the dataset file."
        )

    logger.info("Loaded NSL-KDD: %d rows, %d columns from %s",
                len(df), df.shape[1], path)
    return df


def encode_categoricals(df: pd.DataFrame) -> pd.DataFrame:
    """
    Encode the three categorical columns in-place.

    protocol_type : tcp=0, udp=1, icmp=2, other=3
        Fixed encoding — matches extract_live_features() so train and predict
        use identical numeric values.

    service       : integer via LabelEncoder (not used in LIVE_FEATURE_COLS
        but preserved in the DataFrame for completeness / CICIDS2017 use).

    flag          : integer via LabelEncoder (same — not in LIVE_FEATURE_COLS
        but kept for completeness).

    Parameters
    ----------
    df : pd.DataFrame  (modified in-place, also returned for chaining)

    Returns
    -------
    The same DataFrame with categorical columns replaced by integers.
    """
    df = df.copy()  # avoid mutating the caller's DataFrame

    # protocol_type: fixed map so live events always get the same encoding
    df["protocol_type"] = (
        df["protocol_type"].str.lower()
        .map(PROTOCOL_ENCODING)
        .fillna(3)           # 3 = "other" for any unseen protocol
        .astype(int)
    )

    # service and flag: generic LabelEncoder (ordinal, not used by live model)
    for col in ["service", "flag"]:
        df[col] = LabelEncoder().fit_transform(df[col].astype(str))

    logger.debug("Categoricals encoded: protocol_type (fixed), service, flag (LabelEncoder)")
    return df


def map_labels(df: pd.DataFrame) -> pd.Series:
    """
    Map the 23 specific NSL-KDD attack labels to 5 broad categories.

    Specific → Broad mapping:
      normal          → BENIGN
      neptune/smurf/… → DoS
      ipsweep/nmap/… → Probe
      warezclient/…  → R2L
      buffer_overflow/… → U2R

    Any label not in NSLKDD_MAP is mapped to "Unknown" and will be
    dropped by remove_rare_classes() below.

    Parameters
    ----------
    df : pd.DataFrame  must contain a "label" column

    Returns
    -------
    pd.Series of broad category strings, aligned with df.index
    """
    y = (
        df["label"]
        .str.lower()
        .str.strip()
        .map(NSLKDD_MAP)
        .fillna("Unknown")
    )
    counts = y.value_counts()
    logger.info("Label distribution after mapping: %s", counts.to_dict())
    return y


def extract_features(df: pd.DataFrame,
                     feature_cols: Optional[list] = None) -> pd.DataFrame:
    """
    Select and clean the feature columns used for training.

    Uses LIVE_FEATURE_COLS by default — the 9 NSL-KDD columns that can be
    approximated from a live POST /event payload. This keeps the trained model
    aligned with extract_live_features() in classifier.py.

    Parameters
    ----------
    df           : pd.DataFrame  (must already have categoricals encoded)
    feature_cols : list | None   columns to select; None = LIVE_FEATURE_COLS

    Returns
    -------
    pd.DataFrame with numeric values only, NaNs filled with 0.
    """
    cols = feature_cols or LIVE_FEATURE_COLS
    X = df[cols].apply(pd.to_numeric, errors="coerce").fillna(0)
    logger.debug("Features extracted: %d columns, %d rows", len(cols), len(X))
    return X


def remove_rare_classes(X: pd.DataFrame,
                        y: pd.Series,
                        min_samples: int = MIN_CLASS_SAMPLES
                        ) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Drop samples whose class has fewer than min_samples rows.

    This prevents train_test_split from failing on classes too small to
    appear in both the train and test splits (sklearn requires ≥2 per class
    when using stratify).

    Parameters
    ----------
    X           : feature DataFrame
    y           : label Series
    min_samples : minimum rows a class must have to be kept

    Returns
    -------
    (X_filtered, y_filtered) with rare classes removed.
    """
    counts = y.value_counts()
    rare   = counts[counts < min_samples].index.tolist()
    if rare:
        logger.warning(
            "Dropping %d rare class(es) with < %d samples: %s",
            len(rare), min_samples, rare
        )
    mask = ~y.isin(rare)
    return X[mask], y[mask]


def split(X: pd.DataFrame,
          y: pd.Series,
          test_size: float = 0.2,
          random_state: int = 42
          ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """
    Stratified train/test split.

    Stratify=y preserves the class distribution in both splits, which is
    important for NSL-KDD because U2R has only ~49 rows.

    Parameters
    ----------
    X            : feature DataFrame
    y            : label Series
    test_size    : fraction of data for test set (default 0.2 = 80/20 split)
    random_state : random seed for reproducibility

    Returns
    -------
    (X_train, X_test, y_train, y_test)
    """
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )
    logger.info(
        "Split: train=%d  test=%d  (%.0f/%.0f)",
        len(X_tr), len(X_te),
        (1 - test_size) * 100, test_size * 100
    )
    return X_tr, X_te, y_tr, y_te


def preprocess(path: str,
               sample_size: Optional[int] = None,
               feature_cols: Optional[list] = None,
               test_size: float = 0.2,
               ) -> Dict:
    """
    Full preprocessing pipeline — single entry point for classifier.py.

    Runs all 4 steps in order:
      1. load_raw()            — read CSV, assign column names
      2. encode_categoricals() — protocol_type (fixed), service/flag (LE)
      3. map_labels()          — 23 specific → 5 broad categories
      4. extract_features()    — select LIVE_FEATURE_COLS, fill NaN
      5. remove_rare_classes() — drop classes with < MIN_CLASS_SAMPLES rows
      6. split()               — stratified 80/20 train/test split

    Parameters
    ----------
    path         : str   path to KDDTrain+.txt
    sample_size  : int   rows to sample before splitting (None = all rows)
    feature_cols : list  columns to use (None = LIVE_FEATURE_COLS)
    test_size    : float fraction for test set (default 0.2)

    Returns
    -------
    dict with keys:
      X_train, X_test  — feature DataFrames
      y_train, y_test  — label Series (string category names)
      classes          — sorted list of unique class names
      feature_names    — list of feature column names
      total_samples    — total rows after filtering
      label_counts     — class distribution dict
    """
    logger.info("Starting NSL-KDD preprocessing pipeline: %s", path)

    # Step 1 — Load
    df = load_raw(path)

    # Step 2 — Encode categoricals
    df = encode_categoricals(df)

    # Step 3 — Map labels
    y = map_labels(df)

    # Step 4 — Extract features
    X = extract_features(df, feature_cols)

    # Optional sampling (for fast tests / CI)
    if sample_size and len(X) > sample_size:
        idx = X.sample(n=sample_size, random_state=42).index
        X, y = X.loc[idx], y.loc[idx]
        logger.info("Sampled %d rows from full dataset", sample_size)

    # Step 5 — Remove rare classes
    X, y = remove_rare_classes(X, y)

    # Step 6 — Split
    X_train, X_test, y_train, y_test = split(X, y, test_size=test_size)

    classes      = sorted(y.unique().tolist())
    label_counts = y.value_counts().to_dict()

    logger.info(
        "Preprocessing complete: %d total samples, %d classes: %s",
        len(X), len(classes), classes
    )

    return {
        "X_train":       X_train,
        "X_test":        X_test,
        "y_train":       y_train,
        "y_test":        y_test,
        "classes":       classes,
        "feature_names": X.columns.tolist(),
        "total_samples": len(X),
        "label_counts":  label_counts,
    }


def dataset_summary(path: str) -> Dict:
    """
    Return a summary of the dataset without training — useful for the API
    and for mentor demos to show dataset stats at a glance.

    Parameters
    ----------
    path : str  path to KDDTrain+.txt

    Returns
    -------
    dict with total_rows, columns, attack_distribution, protocol_distribution,
    feature_cols_used, class_imbalance_warning
    """
    df = load_raw(path)
    y  = map_labels(df)

    attack_dist   = y.value_counts().to_dict()
    proto_dist    = df["protocol_type"].value_counts().to_dict()
    total         = len(df)
    benign_pct    = round(attack_dist.get("BENIGN", 0) / total * 100, 1)
    u2r_count     = attack_dist.get("U2R", 0)

    return {
        "total_rows":            total,
        "total_columns":         df.shape[1],
        "feature_cols_used":     LIVE_FEATURE_COLS,
        "n_feature_cols":        len(LIVE_FEATURE_COLS),
        "attack_distribution":   attack_dist,
        "protocol_distribution": proto_dist,
        "benign_percentage":     benign_pct,
        "attack_percentage":     round(100 - benign_pct, 1),
        "class_imbalance_warning": (
            f"U2R has only {u2r_count} rows ({u2r_count/total*100:.2f}%). "
            "Consider SMOTE oversampling if U2R recall is critical."
            if u2r_count < 100 else None
        ),
    }