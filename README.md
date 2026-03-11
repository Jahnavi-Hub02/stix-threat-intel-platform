# STIX Threat Intelligence Platform

Real-Time Cyber Threat Intelligence Correlation Platform using STIX 2.1 and TAXII

## Overview

This platform:
- **Ingests** threat intelligence from TAXII 2.1 feeds
- **Normalizes** STIX 2.1 objects into structured IOCs
- **Correlates** incoming security events against known malicious indicators
- **Scores** and maps threats to MITRE ATT&CK tactics and techniques
- **Reports** findings with risk scoring and actionable intelligence

## Architecture

```
app/
├── config/        - Configuration via environment variables
├── database/      - SQLAlchemy ORM models & connection pooling
├── ingestion/     - TAXII 2.1 client & scheduler
├── normalization/ - STIX parsing & normalization
├── correlation/   - Threat correlation engine
├── api/           - FastAPI REST endpoints
└── utils/         - Logging, validation, helpers
```

## Quick Start

### 1. Prerequisites
- Python 3.11+
- PostgreSQL 13+
- Docker & Docker Compose (optional)

### 2. Local Setup (PostgreSQL running)

```bash
# Clone and navigate
cd stix-threat-platform

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
# Edit .env with your database credentials and TAXII server details

# Start PostgreSQL (via Docker if needed)
docker-compose up postgres redis -d

# Create database tables
python scripts/init_db.py

# Run the application
uvicorn app.main:app --reload --port 8000
```

### 3. Full Docker Setup

```bash
docker-compose up --build
```

### 4. Verify Installation

- Open browser: http://localhost:8000 → Status JSON
- Swagger UI: http://localhost:8000/docs
- RedDoc: http://localhost:8000/redoc

## Database Models

### IOCIndicator
Stores normalized Indicators of Compromise from STIX feeds.
- Fields: stix_id, ioc_type, ioc_value, confidence, source, tlp_marking, is_active

### EventLog
Stores incoming network/security event metadata.
- Fields: source_ip, destination_ip, port data, protocol, event_type, is_processed

### CorrelationResult
Results of correlating events against IOC indicators.
- Fields: event_id, indicator_id, match_type, decision, risk_score, severity, mitre_mapping

### MITREMapping
Local cache of MITRE ATT&CK tactics and techniques.
- Fields: technique_id, technique_name, tactic, description

### IngestionLog
Audit trail for every TAXII ingestion run.
- Fields: source_url, status, total_fetched, total_stored, error_message

## Configuration

All settings via `.env` file:

```env
DEBUG=true/false
DATABASE_URL=postgresql://user:password@host:port/dbname
TAXII_SERVER_URL=https://taxii-server.com/
INGESTION_INTERVAL_MINUTES=30
REDIS_URL=redis://localhost:6379/0
```

## Development

### Run Tests
```bash
pytest tests/
```

### Database Migrations (Alembic)
```bash
alembic upgrade head
```

### API Documentation
- Interactive docs: /docs
- ReDoc: /redoc
- OpenAPI schema: /openapi.json

## Step-by-Step Implementation

- **Step 1** ✅ Project Setup & Environment Configuration
- **Step 2** → TAXII Ingestion Layer
- **Step 3** → STIX Normalization
- **Step 4** → Correlation Engine
- **Step 5** → Risk Scoring
- **Step 6** → REST API & Frontend
