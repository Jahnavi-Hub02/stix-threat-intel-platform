"""
Run this script from your project root to automatically fix app/api/main.py.
It adds the logs_router import and registration.

Usage:
    python fix_main.py
"""
import os, sys

main_path = os.path.join("app", "api", "main.py")

if not os.path.exists(main_path):
    print(f"ERROR: {main_path} not found. Run from project root.")
    sys.exit(1)

with open(main_path, "r", encoding="utf-8") as f:
    content = f.read()

changed = False

# 1. Add import for logs_router if missing
if "from app.api.logs_router" not in content:
    # Add after alerts_router import
    old = "from app.alerts import alerts_router"
    new = "from app.alerts import alerts_router\nfrom app.api.logs_router import router as logs_router"
    if old in content:
        content = content.replace(old, new)
        changed = True
        print("✓ Added logs_router import")
    else:
        print("WARNING: Could not find alerts_router import line")

# 2. Add include_router for logs_router if missing
if "include_router(logs_router)" not in content:
    # Add after alerts_router registration
    old = "app.include_router(alerts_router)"
    new = "app.include_router(alerts_router)\napp.include_router(logs_router)    # /logs/*"
    if old in content:
        content = content.replace(old, new)
        changed = True
        print("✓ Added app.include_router(logs_router)")
    else:
        print("WARNING: Could not find alerts_router include_router line")

# 3. Verify alerts_router is still registered
if "include_router(alerts_router)" not in content:
    print("ERROR: alerts_router is NOT registered! Adding it back...")
    old = "app.include_router(ml_router)"
    new = "app.include_router(ml_router)\napp.include_router(alerts_router)  # /alerts/*"
    if old in content:
        content = content.replace(old, new)
        changed = True
        print("✓ Re-added app.include_router(alerts_router)")

if changed:
    with open(main_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"\n✓ {main_path} updated successfully")
else:
    print(f"\n{main_path} already has all required routers")

# Show current router registrations
print("\nCurrent router registrations in main.py:")
for line in content.splitlines():
    if "include_router" in line:
        print(f"  {line.strip()}")