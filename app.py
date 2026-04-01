"""
STIX 2.1 Threat Intelligence Platform — Entry Point
====================================================
Thin shim that re-exports the FastAPI application from app.api.main.
CORS and all middleware are configured once inside app.api.main — do NOT
add middleware here or it will be applied twice.

Run locally:
    uvicorn app:app --reload --port 8000

    OR (equivalent, preferred in Dockerfile / docker-compose):
    uvicorn app.api.main:app --reload --port 8000

Frontend (separate terminal):
    cd frontend && npm run dev   -> http://localhost:5173
"""

# Re-export the application so `uvicorn app:app` works.
# All middleware (CORS, etc.) lives in app.api.main — nothing is added here.
from app.api.main import app  # noqa: F401

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)