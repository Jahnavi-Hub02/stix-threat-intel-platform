"""
STIX 2.1 Threat Intelligence Platform — Entry Point
====================================================
Run locally:
    uvicorn app:app --reload --port 8000

Frontend (separate terminal):
    cd frontend && npm run dev   -> http://localhost:5173

This file simply re-exports the 'app' object from app.api.main.
All middleware (CORS), routers, and lifespan hooks are registered
there — do NOT add middleware here to avoid double-registration.
"""

from app.api.main import app  # noqa: F401  — re-export for uvicorn

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
