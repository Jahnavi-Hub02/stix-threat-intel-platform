"""
PATCH FOR: app/api/main.py
===========================
Add this import and router registration to your existing main.py.

Find the line:
    from app.alerts import alerts_router

Add BELOW it:
    from app.api.logs_router import router as logs_router

Find the line:
    app.include_router(alerts_router)

Add BELOW it:
    app.include_router(logs_router)

That's the only change needed to main.py.
The new endpoints will appear automatically in /docs.
"""

# ── What to add to main.py ────────────────────────────────────────────────────

IMPORT_TO_ADD = """from app.api.logs_router import router as logs_router"""

ROUTER_TO_ADD = """app.include_router(logs_router)"""

# ── Where to add them ─────────────────────────────────────────────────────────
# After: from app.alerts import alerts_router
# After: app.include_router(alerts_router)
