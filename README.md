# STIX 2.1 Threat Intelligence Correlation Platform

![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)
![Tests](https://img.shields.io/badge/Tests-199%20passed-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Version](https://img.shields.io/badge/Version-2.4.3-orange)

A production-ready REST API platform for ingesting, correlating, and triaging STIX 2.1 cyber threat intelligence. Built with FastAPI, SQLite, Isolation Forest ML anomaly detection, JWT authentication, and a React frontend.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Running the Full Stack](#running-the-full-stack)
- [Running Tests](#running-tests)
- [API Reference](#api-reference)
- [Authentication](#authentication)
- [ML Anomaly Detection](#ml-anomaly-detection)
- [Alert Triage Workflow](#alert-triage-workflow)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [GitHub Actions CI/CD](#github-actions-cicd)
- [Docker](#docker)
- [Known Limitations and Roadmap](#known-limitations-and-roadmap)

---

## Features

| Feature | Detail |
|---|---|
| **STIX 2.1 Ingestion** | Parse JSON bundles and XML feeds; TAXII 2.1 client with delta sync |
| **IOC Correlation** | Real-time matching of source/destination IPs against indicator database |
| **ML Anomaly Detection** | Isolation Forest trained on 10-dimensional network feature vectors |
| **JWT Authentication** | PBKDF2-SHA256 hashing; access + refresh token pair; role-based access |
| **Alert Triage** | Auto-create alerts on threat detection; analyst NEW → RESOLVED workflow |
| **PDF Reports** | Auto-generated threat report per event via ReportLab |
| **Background Scheduler** | APScheduler ingests from public TAXII servers every 30 minutes |
| **React Frontend** | Dashboard at `http://localhost:3000` (Vite + React) |
| **199 Automated Tests** | Full pytest suite — auth, alerts, API, ML, database, pipeline |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  React Frontend  (:3000)                     │
│               Vite + React + Tailwind CSS                    │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP / JSON
┌──────────────────────────▼──────────────────────────────────┐
│                FastAPI Backend  (:8000)                      │
│                                                              │
│  /auth   /event   /alerts   /ml   /iocs   /correlations     │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                    SQLite Database                    │   │
│  │   ioc_indicators | events | alerts | users | tokens  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────┐   ┌────────────────────────────┐     │
│  │  Isolation Forest │   │  APScheduler (background)  │     │
│  │  ML Model (.pkl)  │   │  TAXII sync every 30 min   │     │
│  └──────────────────┘   └────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- **Python 3.11** — required. Do not use 3.12 or 3.13 (compiled ML C extensions are version-locked).
- Node.js 18+
- Git

### 1. Clone the repository

```powershell
git clone https://github.com/Jahnavi-Hub02/stix-threat-intel-platform.git
cd stix-threat-intel-platform
```

### 2. Create a Python 3.11 virtual environment

```powershell
# Windows
py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1

# macOS / Linux
python3.11 -m venv venv
source venv/bin/activate
```

Verify Python version:
```powershell
python --version
# Must print: Python 3.11.x
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Set the required environment variable

```powershell
# Windows PowerShell
$env:JWT_SECRET_KEY = "your-secret-key-change-in-production"

# macOS / Linux
export JWT_SECRET_KEY="your-secret-key-change-in-production"
```

### 5. Start the backend

```powershell
uvicorn app.api.main:app --reload --port 8000
```

Open `http://localhost:8000/docs` for the interactive Swagger UI.

---

## Running the Full Stack

### Terminal 1 — Backend

```powershell
cd stix-threat-intel-platform
.\venv\Scripts\Activate.ps1
$env:JWT_SECRET_KEY = "your-secret-key-change-in-production"
uvicorn app.api.main:app --reload --port 8000
```

### Terminal 2 — Frontend

```powershell
cd stix-threat-intel-platform\frontend
npm install        # first time only
npm run dev
# Opens at http://localhost:3000
```

### Optional — Seed the database

Loads 1,188 real threat indicators from the bundled STIX feeds:

```powershell
# Terminal 1, with venv active
python run.py
```

---

## Running Tests

```powershell
# 1. Activate venv
.\venv\Scripts\Activate.ps1

# 2. Set environment
$env:JWT_SECRET_KEY = "test-secret-key-for-local-dev"
$env:PYTHONPATH     = "."

# 3. Run all 199 tests
pytest tests/ -v --tb=short
```

Expected output:
```
199 passed, 0 failed, 2 warnings in ~80s
```

### Test suite breakdown

| File | Tests | Covers |
|---|---|---|
| `test_alerts.py` | 23 | Alert CRUD, triage transitions, path-traversal security |
| `test_api.py` | 29 | All REST endpoints, pagination, 401/403 enforcement |
| `test_auth.py` | 51 | JWT, password hashing, register/login/logout, RBAC, admin |
| `test_core.py` | 27 | JSON/XML parsers, IP validator, correlation engine |
| `test_database.py` | 14 | Table creation, IOC insert/dedup, event storage, stats |
| `test_ml.py` | 37 | Feature extraction, Isolation Forest train/predict, API |
| `test_pipeline.py` | 9 | End-to-end pipeline, PDF report generation |
| `test_placeholder.py` | 1 | Smoke test |
| **Total** | **199** | |

### Important: Python version must be 3.11

If you see `ModuleNotFoundError: No module named 'pydantic_core._pydantic_core'` or `sklearn.__check_build._check_build`, your venv was created with the wrong Python version. Fix:

```powershell
# Delete the broken venv and recreate with Python 3.11
Remove-Item -Recurse -Force venv
py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## API Reference

### Public Endpoints (no token required)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Platform info |
| `GET` | `/health` | Docker healthcheck |
| `POST` | `/auth/register` | Create a new account |
| `POST` | `/auth/login` | Authenticate, receive JWT tokens |
| `POST` | `/auth/refresh` | Get a new access token from refresh token |
| `POST` | `/auth/logout` | Revoke refresh token |

### Viewer Endpoints (any valid token)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/metrics` | Platform statistics and scheduler status |
| `GET` | `/iocs` | List IOC indicators (paginated, filterable by type) |
| `GET` | `/iocs/{value}` | Look up a specific IOC |
| `GET` | `/correlations` | List correlation results |
| `GET` | `/alerts` | List alerts (filterable by `?status=NEW`) |
| `GET` | `/alerts/{id}` | Get a single alert |
| `GET` | `/ml/status` | ML model training status |
| `GET` | `/auth/me` | Current user info |
| `GET` | `/scheduler/status` | Background scheduler status |
| `GET` | `/ingest/servers` | Configured TAXII servers |

### Analyst Endpoints (role ≥ analyst)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/event` | Submit network event for dual-layer threat analysis |
| `PATCH` | `/alerts/{id}/status` | Triage an alert (update status + notes) |
| `POST` | `/ml/train` | Trigger ML model training |
| `POST` | `/ml/predict` | Score a raw event with the ML model |
| `POST` | `/ingest/file` | Ingest IOCs from a local JSON or XML file |
| `POST` | `/ingest/taxii` | Ingest from a TAXII 2.1 server (async) |
| `POST` | `/ingest/trigger` | Manually trigger the scheduled ingestion |

### Admin Endpoints (role = admin)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/auth/users` | List all registered users |
| `DELETE` | `/auth/users/{id}` | Deactivate a user account |

---

## Authentication

The platform uses a **two-token JWT pattern**:

- **Access token** — short-lived (30 min), sent as `Authorization: Bearer <token>`
- **Refresh token** — long-lived (7 days), only used to get a new access token

### Roles

| Role | Permissions |
|---|---|
| `viewer` | Read-only: IOCs, alerts, metrics, correlations |
| `analyst` | viewer + submit events, triage alerts, train ML, ingest |
| `admin` | analyst + manage users (list, deactivate) |

### Example: Full login flow

```bash
# Step 1: Register
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","password":"SecurePass123!","role":"analyst"}'

# Step 2: Login — note the access_token in the response
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","password":"SecurePass123!"}'

# Step 3: Use the token
curl -X POST http://localhost:8000/event \
  -H "Authorization: Bearer <paste_access_token_here>" \
  -H "Content-Type: application/json" \
  -d '{"event_id":"evt-001","source_ip":"185.220.101.45","destination_ip":"10.0.0.1"}'
```

> **Creating an admin account:** The `/auth/register` endpoint requires an existing admin's Bearer token to create another admin. For the very first admin, insert directly into the database:
> ```python
> from app.database.db_manager import create_user
> from app.auth.security import hash_password
> create_user("myadmin", hash_password("StrongPass123!"), "admin")
> ```

---

## ML Anomaly Detection

### How it works

1. `POST /event` extracts 10 features from the network event
2. The event is stored in the `ml_events` table
3. Once 50+ events are accumulated, the model trains automatically
4. Each new event is scored; anomalies are flagged and contribute to the final risk score
5. The trained model is persisted to `models/isolation_forest.pkl`

### 10-feature vector

| Feature | Description |
|---|---|
| `src_ip_int` | Source IP as 32-bit integer |
| `dst_ip_int` | Destination IP as 32-bit integer |
| `src_port` | Source port number |
| `dst_port` | Destination port number |
| `protocol_enc` | TCP=1, UDP=2, other=0 |
| `is_private_src` | Source IP is RFC-1918 private (0/1) |
| `is_private_dst` | Destination IP is RFC-1918 private (0/1) |
| `port_category` | web=1, known backdoor=2, database=3, other=0 |
| `hour_of_day` | Hour of the event timestamp (0–23) |
| `port_ratio` | Ratio of source port to destination port |

### Anomaly score thresholds

| Score | Meaning |
|---|---|
| 0.0 – 0.3 | Normal |
| 0.3 – 0.5 | Slightly unusual |
| 0.5 – 0.7 | Suspicious |
| 0.7 – 1.0 | Strong anomaly |

---

## Alert Triage Workflow

When `POST /event` detects a threat, an alert is automatically created with `status: NEW`.

### Valid status values

```
NEW  →  INVESTIGATING  →  RESOLVED
NEW  →  INVESTIGATING  →  FALSE_POSITIVE
NEW  →  FALSE_POSITIVE
NEW  →  RESOLVED
```

### Triage an alert

```bash
curl -X PATCH http://localhost:8000/alerts/1/status \
  -H "Authorization: Bearer <analyst_token>" \
  -H "Content-Type: application/json" \
  -d '{"status":"INVESTIGATING","notes":"Confirmed C2 traffic from known bad IP"}'
```

Response:
```json
{
  "new_status": "INVESTIGATING",
  "updated_by": "analyst1",
  "alert_id": 1,
  "updated_at": "2026-03-12T10:00:00+00:00"
}
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET_KEY` | **required** | JWT signing secret — use a long random string in production |
| `JWT_EXPIRE_MINUTES` | `30` | Access token lifetime in minutes |
| `JWT_REFRESH_EXPIRE_DAYS` | `7` | Refresh token lifetime in days |
| `ML_MIN_TRAIN_SAMPLES` | `50` | Events needed before ML auto-trains |
| `ML_CONTAMINATION` | `0.05` | Expected anomaly fraction for Isolation Forest |
| `ML_MODEL_DIR` | `models` | Directory where `.pkl` model files are saved |
| `FRONTEND_URL` | `` | Added to CORS allowed origins |

---

## Project Structure

```
stix-threat-intel-platform/
│
├── app/
│   ├── api/
│   │   ├── main.py              # FastAPI app, all routes, lifespan
│   │   └── ml.py                # /ml/* router
│   ├── alerts/
│   │   └── router.py            # /alerts/* CRUD and triage
│   ├── auth/
│   │   ├── models.py            # Pydantic request/response models
│   │   ├── router.py            # /auth/* endpoints
│   │   └── security.py          # JWT, PBKDF2 hashing, RBAC
│   ├── correlation/
│   │   └── engine.py            # IOC correlation logic
│   ├── database/
│   │   └── db_manager.py        # SQLite CRUD for all tables
│   ├── ingestion/
│   │   ├── scheduler.py         # APScheduler background TAXII sync
│   │   └── taxii_client.py      # TAXII 2.1 client with delta support
│   ├── ml/
│   │   ├── detector.py          # Isolation Forest lifecycle
│   │   └── features.py          # Feature extraction and explanation
│   ├── normalization/
│   │   ├── parser_json.py       # STIX 2.1 JSON bundle parser
│   │   └── parser_xml.py        # STIX XML feed parser
│   └── utils/
│       ├── ip_validator.py      # Public/private IP classification
│       ├── logger.py            # Standard Python logging wrapper
│       └── report_generator.py  # ReportLab PDF generation
│
├── tests/
│   ├── conftest.py              # Shared fixtures (temp_db, api_client)
│   ├── test_alerts.py           # 23 alert triage tests
│   ├── test_api.py              # 29 REST endpoint tests
│   ├── test_auth.py             # 51 authentication tests
│   ├── test_core.py             # 27 parser and correlation tests
│   ├── test_database.py         # 14 database layer tests
│   ├── test_ml.py               # 37 ML model tests
│   ├── test_pipeline.py         # 9 end-to-end pipeline tests
│   └── test_placeholder.py      # Smoke test
│
├── frontend/                    # React + Vite dashboard
│   ├── src/
│   ├── package.json
│   └── vite.config.js
│
├── data/                        # STIX feed files
│   ├── TI_GOV.json
│   └── certin_ti_gov.xml
│
├── .github/
│   └── workflows/
│       └── ci.yml               # 4-job CI/CD pipeline
│
├── .env.example                 # Environment variable template
├── .gitignore
├── Dockerfile                   # Multi-stage: Node frontend + Python backend
├── docker-compose.yml
├── requirements.txt
├── run.py                       # Seed script: loads 1,188 threat indicators
└── README.md
```

---

## GitHub Actions CI/CD

Every push to `main` or `develop` runs a 4-job pipeline:

```
backend-tests ──┐
(Py 3.11+3.12)  ├──► docker-build   (main only, after both pass)
frontend-build ─┘
backend-tests ──► security-scan     (main only)
```

| Job | What it does |
|---|---|
| `backend-tests` | Runs all 199 pytest tests on Python 3.11 and 3.12; uploads coverage XML artifact |
| `frontend-build` | `npm ci` + `vite build`; uploads `dist/` artifact |
| `docker-build` | Builds multi-stage Docker image (main branch only after tests pass) |
| `security-scan` | `safety` CVE check + `bandit` SAST (main branch only) |

---

## Docker

### Build and run standalone

```bash
docker build -t stix-threat-intel:latest .

docker run -p 8000:8000 \
  -e JWT_SECRET_KEY="your-secret-key" \
  -v $(pwd)/database:/app/database \
  -v $(pwd)/models:/app/models \
  stix-threat-intel:latest
```

### Docker Compose

```bash
docker-compose up --build
```

The `database/` and `models/` directories are mounted as volumes so data and the trained ML model persist across container restarts.

---

## Known Limitations and Roadmap

### Current limitations

- **SQLite only** — single writer, no horizontal scaling. Migrate to PostgreSQL for production.
- **No DB indexes** — 9 frequently queried columns (event_id, source_ip, status) lack indexes, causing full table scans on large datasets.
- **MITRE mapping is hardcoded** — only 3 entries; should integrate the full MITRE ATT&CK STIX dataset.
- **Correlation checks IP fields only** — domain and file hash matching not yet implemented.
- **Docker container runs as root** — add `USER 1001` to the Dockerfile for production hardening.

### Roadmap

- [ ] **Step 12** — STIX 2.1 Export: `GET /export/stix` returns matched IOCs as valid STIX 2.1 bundles
- [ ] **Step 13** — WebSocket real-time alert stream
- [ ] **Step 14** — PostgreSQL migration with Alembic
- [ ] **Step 15** — SHAP explainability for ML predictions
- [ ] **Step 16** — Analyst feedback loop: label false positives to retrain the model

---

## License

MIT License — see [LICENSE](LICENSE) for details.
