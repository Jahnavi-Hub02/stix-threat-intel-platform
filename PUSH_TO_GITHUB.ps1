# ─────────────────────────────────────────────────────────────────────────────
# STIX Platform v2.4.3 — Complete GitHub Push Instructions
# Run these commands in PowerShell from your project root:
# C:\Users\jaanu\OneDrive\Desktop\stix_threat_intel\
# ─────────────────────────────────────────────────────────────────────────────

# STEP 1 — Navigate to your project folder
cd C:\Users\jaanu\OneDrive\Desktop\stix_threat_intel

# STEP 2 — Copy the updated files into the correct locations:
#
#   FROM (downloaded from Claude)       TO (in your project)
#   ─────────────────────────────────   ─────────────────────────────────────
#   test_auth.py                    →   tests\test_auth.py
#   scheduler.py                    →   app\ingestion\scheduler.py
#   README.md                       →   README.md
#   ci.yml                          →   .github\workflows\ci.yml
#   .env.example                    →   .env.example
#   .gitignore                      →   .gitignore
#
# Do this manually in File Explorer or with PowerShell copy commands.

# STEP 3 — Verify tests still pass before pushing
.\venv\Scripts\Activate.ps1
$env:JWT_SECRET_KEY = "test-secret-key-for-local-dev"
$env:PYTHONPATH    = "."
pytest tests/ -v --tb=short
# Expected: 199 passed, 0 failed

# STEP 4 — Configure git (only needed once)
git config --global user.name  "Jahnavi-Hub02"
git config --global user.email "your-email@example.com"

# STEP 5 — Stage all changes
git add .

# STEP 6 — Review what will be committed (sanity check)
git status

# STEP 7 — Commit
git commit -m "fix: 199 tests passing - scheduler logger, admin bootstrap, README"

# STEP 8 — Push to GitHub
git push origin main

# ─────────────────────────────────────────────────────────────────────────────
# TROUBLESHOOTING COMMON PUSH ERRORS
# ─────────────────────────────────────────────────────────────────────────────

# ERROR: "rejected — non-fast-forward" (GitHub has commits your local doesn't)
# FIX:
git pull origin main --rebase
git push origin main

# ERROR: "fatal: not a git repository"
# FIX: Initialize git and connect to remote
git init
git remote add origin https://github.com/Jahnavi-Hub02/stix-threat-intel-platform.git
git add .
git commit -m "initial commit"
git push -u origin main

# ERROR: "remote: Permission denied" or authentication failure
# FIX: Use a Personal Access Token (PAT) instead of password
# 1. Go to GitHub → Settings → Developer settings → Personal access tokens → Generate new token
# 2. Select scopes: repo (full control)
# 3. When git asks for password, paste the token instead

# ERROR: Large files rejected (>100MB)
# FIX: These are already in .gitignore, but if accidentally staged:
git rm --cached database/threat_intel.db
git rm --cached -r models/
git rm --cached venv/

# ─────────────────────────────────────────────────────────────────────────────
# VERIFY CI/CD IS PASSING ON GITHUB
# ─────────────────────────────────────────────────────────────────────────────
# After pushing, visit:
# https://github.com/Jahnavi-Hub02/stix-threat-intel-platform/actions
#
# You should see 4 jobs:
#   ✅ Backend Tests (Python 3.11)
#   ✅ Backend Tests (Python 3.12)
#   ✅ Frontend Build
#   ✅ Docker Build      (main branch only)
#   ✅ Security Scan     (main branch only)
