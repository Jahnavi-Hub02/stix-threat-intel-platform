# ─────────────────────────────────────────────────────────────────
# Stage 1: Build React Frontend
# ─────────────────────────────────────────────────────────────────
FROM node:18-alpine AS frontend-builder

WORKDIR /frontend

COPY frontend/package*.json ./
RUN npm ci --silent

COPY frontend/ ./
RUN npm run build

# ─────────────────────────────────────────────────────────────────
# Stage 2: Python Backend
# ─────────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

ARG BUILD_DATE
ARG GIT_COMMIT
LABEL org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.revision=$GIT_COMMIT \
      org.opencontainers.image.title="STIX 2.1 Threat Intelligence Platform"

# gcc needed for some scikit-learn / numpy C extensions
RUN apt-get update && apt-get install -y gcc curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/   ./app/
COPY data/  ./data/
COPY run.py .
COPY app.py .

# Copy built React frontend from Stage 1
COPY --from=frontend-builder /frontend/build ./frontend/build

# Create persistent directories
# - database/ → SQLite DB (mounted as volume)
# - models/   → Isolation Forest .pkl files (mounted as volume)
RUN mkdir -p database models

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ML_MIN_TRAIN_SAMPLES=50 \
    ML_CONTAMINATION=0.05 \
    ML_MODEL_DIR=/app/models

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]