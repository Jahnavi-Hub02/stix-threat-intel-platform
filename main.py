from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.api.main import app as api_app
import os

# Mount the API
app = api_app

# ── Health endpoint for Docker ────────────────────────────────
@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok"}

# ── Serve React frontend (only when build exists) ─────────────
FRONTEND_BUILD = os.path.join(os.path.dirname(__file__), "frontend", "build")

if os.path.exists(FRONTEND_BUILD):
    # Serve static assets (JS, CSS, images)
    app.mount(
        "/static",
        StaticFiles(directory=os.path.join(FRONTEND_BUILD, "static")),
        name="static"
    )

    @app.get("/dashboard", include_in_schema=False)
    @app.get("/dashboard/{rest_of_path:path}", include_in_schema=False)
    def serve_react(rest_of_path: str = ""):
        """Serve React app for all dashboard routes."""
        return FileResponse(os.path.join(FRONTEND_BUILD, "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
