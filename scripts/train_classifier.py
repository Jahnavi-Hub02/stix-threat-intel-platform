"""
scripts/train_classifier.py
============================
Run ONCE after downloading a dataset. Trains the Random Forest and saves model.

Usage:
  # NSL-KDD — fast (~1 min), good for dev/demo
  python scripts/train_classifier.py --dataset data/nslkdd/KDDTrain+.TXT --type nslkdd

  # CICIDS2017 — full dataset (~10 min), use for final report
  python scripts/train_classifier.py --dataset data/cicids2017/ --type cicids2017

  # Quick dev mode (10000 rows, ~5 seconds)
  python scripts/train_classifier.py --dataset data/nslkdd/KDDTrain+.TXT --sample 10000
"""
import sys, os, argparse, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--type",    choices=["nslkdd","cicids2017","auto"], default="auto")
    ap.add_argument("--sample",  type=int, default=None)
    ap.add_argument("--output",  default="models")
    args = ap.parse_args()

    if not os.path.exists(args.dataset):
        print(f"\nERROR: {args.dataset} not found.\n")
        print("Download NSL-KDD:")
        print("  https://github.com/jmnwong/NSL-KDD-Dataset")
        print("  Save as: data/nslkdd/KDDTrain+.TXT\n")
        print("Download CICIDS2017:")
        print("  https://www.unb.ca/cic/datasets/ids-2017.html")
        print("  Extract CSVs to: data/cicids2017/\n")
        sys.exit(1)

    os.environ["ML_MODEL_DIR"] = args.output
    os.makedirs(args.output, exist_ok=True)

    from app.ml.classifier import train

    print("="*60)
    print("STIX Platform — Classifier Training")
    print("="*60)
    print(f"Dataset : {args.dataset}")
    print(f"Type    : {args.type}")
    print(f"Sample  : {args.sample or 'Full'}")
    print()

    t0     = time.time()
    result = train(args.dataset, args.type, args.sample)
    elapsed= round(time.time()-t0,1)

    print(f"\nStatus     : {result['status']}")
    print(f"Samples    : {result['total_samples']:,}  (train={result['train_samples']:,}  test={result['test_samples']:,})")
    print(f"Accuracy   : {result['accuracy']*100:.2f}%")
    print(f"Classes    : {result['classes']}")
    print(f"Time       : {elapsed}s")
    print(f"\nTop features:")
    for feat,imp in result["top_features"]:
        bar = "█"*int(imp*50)
        print(f"  {feat:<38} {imp:.4f}  {bar}")

    print(f"\nClassification report:")
    rpt = result["classification_report"]
    print(f"  {'Class':<18} {'Prec':>7} {'Rec':>7} {'F1':>7} {'Support':>9}")
    print(f"  {'-'*18} {'-'*7} {'-'*7} {'-'*7} {'-'*9}")
    for cls in result["classes"]:
        if cls in rpt:
            r = rpt[cls]
            print(f"  {cls:<18} {r['precision']:>7.3f} {r['recall']:>7.3f} {r['f1-score']:>7.3f} {int(r['support']):>9,}")

    print(f"\nModel saved. Start API and submit events — classifier is live.")

if __name__ == "__main__":
    main()
