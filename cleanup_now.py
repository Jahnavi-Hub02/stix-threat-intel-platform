import os
import sys

# Force run from project root
os.chdir(os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.getcwd())

FILES_TO_DELETE = [
    "api.py",
    "scheduler.py",
    "taxii_ingest.py",
    "app/main.py",
    "app/database/connection.py",
    "app/database/models.py",
    "app/config/__init__.py",
    "app/config/settings.py",
    "CHECKLIST.md",
    "CLEANUP_GUIDE.md",
    "CONSOLIDATION_REPORT.md",
    "FINAL_SUMMARY.py",
    "PROJECT_SUMMARY.py",
    "QUICK_REFERENCE.py",
    "README_STRUCTURE.md",
    "SETUP_COMPLETE.md",
    "START_HERE.md",
    "verify_project.py",
]

print("=" * 50)
print("Project Cleanup")
print(f"Working directory: {os.getcwd()}")
print("=" * 50)

deleted = 0
skipped = 0

for f in FILES_TO_DELETE:
    path = f.replace("/", os.sep)  # Windows path fix
    if os.path.exists(path):
        os.remove(path)
        print(f"  DELETED: {path}")
        deleted += 1
    else:
        print(f"  NOT FOUND (skip): {path}")
        skipped += 1

# Remove app/config dir if empty
config_dir = os.path.join("app", "config")
if os.path.exists(config_dir) and not os.listdir(config_dir):
    os.rmdir(config_dir)
    print(f"  REMOVED empty dir: {config_dir}")

print()
print(f"Done! Deleted: {deleted} | Skipped: {skipped}")
print()
print("Next steps:")
print("  1. Replace the 5 fixed files from the audit")
print("  2. Run: uvicorn app:app --reload --port 8000")