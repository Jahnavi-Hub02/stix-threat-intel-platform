"""
Cleanup Script — Remove old/duplicate files after consolidation

Run this AFTER verifying the new app/ structure works:
  python scripts/cleanup.py
"""

import os
import shutil
from pathlib import Path

ROOT = Path(__file__).parent.parent


def cleanup():
    """Remove old duplicate files."""
    
    # Files to delete at root level
    root_files_to_delete = [
        "api.py",
        "main.py",
        "db.py",
        "correlation.py",
        "parser_json.py",
        "parser_xml.py",
        "report_generator.py",
    ]

    # Directories to delete
    dirs_to_delete = [
        "modules",
    ]

    print("=" * 60)
    print("CLEANUP: Removing old/duplicate files")
    print("=" * 60)

    # Remove root files
    for filename in root_files_to_delete:
        filepath = ROOT / filename
        if filepath.exists():
            print(f"  Deleting: {filename}")
            filepath.unlink()
        else:
            print(f"  Not found (OK): {filename}")

    # Remove directories
    for dirname in dirs_to_delete:
        dirpath = ROOT / dirname
        if dirpath.exists():
            print(f"  Deleting directory: {dirname}/")
            shutil.rmtree(dirpath)
        else:
            print(f"  Not found (OK): {dirname}/")

    print("=" * 60)
    print("✓ Cleanup complete!")
    print("=" * 60)
    print("\nVerify with:")
    print("  python run.py")
    print("  python -m uvicorn app.api.main:app --reload")


if __name__ == "__main__":
    response = input(
        "This will DELETE old files. Continue? (yes/no): "
    ).strip().lower()

    if response == "yes":
        cleanup()
    else:
        print("Cancelled.")
