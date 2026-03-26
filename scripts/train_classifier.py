"""
scripts/train_classifier.py
============================
Train the Random Forest classifier (Layer 1) on the NSL-KDD dataset.

This script is the OFFLINE training step described by the mentor:
  preprocessing → feature extraction → dataset splitting → training → evaluation

The trained model is saved to the models/ directory and used at runtime
by POST /event and POST /ml/predict for live threat classification.
Live events are NEVER used for retraining — only this historical dataset.

Usage
-----
  # Full dataset (~125k rows, ~2 min on modern CPU)
  python scripts/train_classifier.py

  # Custom dataset path
  python scripts/train_classifier.py --dataset data/nslkdd/KDDTrain+.txt

  # Fast sample for testing (~15 seconds)
  python scripts/train_classifier.py --sample 20000

  # Show detailed per-class metrics after training
  python scripts/train_classifier.py --verbose
"""

import argparse
import json
import os
import sys
import time

# Ensure project root is on the path so `app.*` imports resolve correctly
# regardless of which directory this script is called from
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Train Random Forest classifier on NSL-KDD dataset",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/train_classifier.py
  python scripts/train_classifier.py --sample 20000
  python scripts/train_classifier.py --dataset data/nslkdd/KDDTrain+.txt --verbose
        """
    )
    parser.add_argument(
        "--dataset",
        default="data/nslkdd/KDDTrain+.txt",
        help="Path to KDDTrain+.txt (default: data/nslkdd/KDDTrain+.txt)"
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=None,
        metavar="N",
        help="Number of rows to sample for fast testing (default: full dataset)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-class precision / recall / F1 after training"
    )
    parser.add_argument(
        "--dataset-type",
        default="nslkdd",
        choices=["nslkdd", "cicids2017", "auto"],
        help="Dataset format (default: nslkdd)"
    )
    return parser.parse_args()


def check_dataset(path: str) -> str:
    """Resolve dataset path relative to project root. Raises if not found."""
    # Try as-is first, then relative to project root
    candidates = [path, os.path.join(PROJECT_ROOT, path)]
    for p in candidates:
        if os.path.exists(p):
            size_mb = os.path.getsize(p) / (1024 * 1024)
            print(f"  Dataset : {p}")
            print(f"  Size    : {size_mb:.1f} MB")
            return p
    print(f"\n  ERROR: Dataset not found at any of:")
    for p in candidates:
        print(f"    {p}")
    print("\n  Download NSL-KDD from:")
    print("    https://github.com/jmnwong/NSL-KDD-Dataset")
    print("  Then place KDDTrain+.txt at: data/nslkdd/KDDTrain+.txt")
    sys.exit(1)


def print_class_report(report: dict, classes: list):
    """Print a readable per-class metrics table."""
    print("\n  Per-class metrics:")
    print(f"  {'Class':<15} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print("  " + "-" * 55)
    for cls in classes:
        if cls in report:
            r = report[cls]
            print(f"  {cls:<15} {r['precision']:>10.3f} {r['recall']:>10.3f}"
                  f" {r['f1-score']:>10.3f} {int(r['support']):>10}")


def main():
    args = parse_args()

    print("\n" + "=" * 55)
    print("  STIX Threat Intel — RF Classifier Training")
    print("=" * 55)

    # ── 1. Locate dataset ────────────────────────────────────
    dataset_path = check_dataset(args.dataset)

    if args.sample:
        print(f"  Sample  : {args.sample:,} rows (fast mode)")
    else:
        print(f"  Sample  : full dataset")
    print(f"  Type    : {args.dataset_type}")
    print()

    # ── 2. Check dependencies ────────────────────────────────
    try:
        import pandas       # noqa: F401
        import sklearn      # noqa: F401
        import joblib       # noqa: F401
    except ImportError as e:
        print(f"  ERROR: Missing dependency — {e}")
        print("  Run: pip install -r requirements.txt")
        sys.exit(1)

    # ── 3. Run training ──────────────────────────────────────
    print("  Step 1/5  Loading and preprocessing dataset...")
    t_start = time.time()

    from app.ml.classifier import train

    print("  Step 2/5  Encoding features and splitting train/test...")
    print("  Step 3/5  Fitting RandomForestClassifier...")
    print("            (n_estimators=200, max_depth=20, class_weight=balanced)")

    result = train(
        dataset_path=dataset_path,
        dataset_type=args.dataset_type,
        sample_size=args.sample,
    )

    elapsed = time.time() - t_start

    # ── 4. Print results ─────────────────────────────────────
    if result.get("status") != "trained":
        print(f"\n  ERROR: Training failed — {result}")
        sys.exit(1)

    print(f"  Step 4/5  Evaluating on test set...")
    print(f"  Step 5/5  Saving model files...")
    print()
    print("=" * 55)
    print("  TRAINING COMPLETE")
    print("=" * 55)
    print(f"  Total samples  : {result['total_samples']:,}")
    print(f"  Train / Test   : {result['train_samples']:,} / {result['test_samples']:,}")
    print(f"  Accuracy       : {result['accuracy'] * 100:.2f}%")
    print(f"  Classes        : {', '.join(result['classes'])}")
    print(f"  Duration       : {elapsed:.1f}s")
    print()
    print("  Top 5 most important features:")
    for feat, importance in result["top_features"][:5]:
        bar = "█" * int(importance * 40)
        print(f"    {feat:<25} {bar} {importance:.4f}")

    if args.verbose:
        print_class_report(result["classification_report"], result["classes"])

    # ── 5. Show saved file locations ─────────────────────────
    from app.ml.classifier import CLF_PATH, SCALER_PATH, ENCODER_PATH
    eval_path = os.path.join(os.path.dirname(CLF_PATH), "rf_evaluation.json")
    print()
    print("  Saved model files:")
    for path in [CLF_PATH, SCALER_PATH, ENCODER_PATH, eval_path]:
        abs_path = os.path.join(PROJECT_ROOT, path) if not os.path.isabs(path) else path
        exists   = "✓" if os.path.exists(abs_path) else "✗"
        print(f"    [{exists}] {path}")

    print()
    print("  Next steps:")
    print("    1. Start the server:  uvicorn app.api.main:app --reload")
    print("    2. Check status:      GET  /ml/status")
    print("    3. Run prediction:    POST /ml/predict")
    print("=" * 55 + "\n")


if __name__ == "__main__":
    main()