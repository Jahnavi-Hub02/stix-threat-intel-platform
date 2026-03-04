"""
STIX 2.1 Threat Intelligence Platform — Entry Point
====================================================
Run locally:
    uvicorn app:app --reload --port 8000

Frontend (separate terminal):
    cd frontend && npm run dev   -> http://localhost:3000
"""

import os
from fastapi.middleware.cors import CORSMiddleware
from app.api.main import app

# CORS — allows React frontend to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "https://*.onrender.com",
        os.getenv("FRONTEND_URL", ""),
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)