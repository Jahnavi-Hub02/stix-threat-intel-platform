# STIX 2.1 Threat Intelligence Platform

**A full-stack threat intelligence platform that ingests live STIX/TAXII threat feeds, correlates every network event against known IOCs, runs dual-layer ML anomaly detection, and alerts analysts in real time.**

[![Tests](https://img.shields.io/badge/Tests-301%20passed-brightgreen?style=flat-square)](https://github.com/Jahnavi-Hub02/stix-threat-intel-platform/actions)
[![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square)](https://react.dev)
[![Version](https://img.shields.io/badge/Version-2.5.0-orange?style=flat-square)](https://github.com/Jahnavi-Hub02/stix-threat-intel-platform)

---

## What does it do?

Imagine your network is handling thousands of connections a second. This platform helps you answer: **"Is any of this traffic talking to a known threat — and does it look suspicious even if we've never seen it before?"**

It works in five phases:

1. **Collect** — Polls live TAXII 2.1 servers (AlienVault OTX, CISA AIS, etc.) every 30 minutes and **upserts** indicators into the local database — new IOCs are inserted, existing ones get updated attributes if the threat feed changes them. If all live feeds fail, a **fallback client** automatically fetches from a configurable internal IOC server.
2. **Watch** — Monitors an offline IOC folder (`data/ioc_watch/`) for dropped STIX files and a configurable set of log files for IOC matches — both run automatically in the background.
3. **Check** — When a network event arrives, two checks run in parallel: a fast SQL lookup against stored IOCs (with full superset metadata: geo-location, TLP, kill chain), and a dual-layer ML analysis (Isolation Forest + Random Forest classifier).
4. **Alert** — If either check flags something, an alert is created and a PDF report is generated automatically.
5. **Analyze** — Upload any log file (Apache, Nginx, syslog, firewall) and the platform scans every line using both IOC matching and ML threat detection.

---

## Dashboard

![STIX Platform Dashboard](docs/screenshots/dashboard_overview.png)

The dashboard shows at a glance:
- **Total IOCs** — threat indicators loaded from TAXII feeds, offline files, and fallback server
- **Events logged** — network connections analyzed
- **Correlations** — how many matched a known threat
- **Critical alerts** — items needing immediate attention
- **Severity chart** — breakdown of all four threat levels (Critical / High / Medium / Low) — all sourced from the database, not estimated client-side
- **Recent detections** — the latest flagged events in real time

---

## Architecture

How data flows through the platform — from raw threat feeds to analyst alerts:

![Architecture Diagram](docs/screenshots/architecture_diagram.png)

---

## Getting started

You need **Python 3.11** and **Node.js 18+** installed.

> Python 3.11 is recommended and fully tested. Python 3.12 is also supported and tested in CI.

### 1. Clone the repository

```bash
git clone https://github.com/Jahnavi-Hub02/stix-threat-intel-platform.git
cd stix-threat-intel-platform
```

### 2. Create a Python virtual environment

```powershell
# Windows
py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1

# Mac / Linux
python3.11 -m venv venv
source venv/bin/activate
```

Verify: `python --version` → should say `Python 3.11.x`

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
# Copy the template
cp .env.example .env   # Mac/Linux
copy .env.example .env  # Windows
```

Generate a secure JWT secret and add it to `.env`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Then edit `.env`:
```
JWT_SECRET_KEY=<paste the generated key here>
```

> ⚠️ The server will **refuse to start** if `JWT_SECRET_KEY` is not set. This protects against accidentally running with an insecure random key that changes on every restart.

### 5. Load initial threat data

```bash
python run.py
```

This loads real threat indicators from the bundled STIX XML feed (`data/certin_ti_gov.xml`) so you have data to work with immediately. Additional IOCs can be ingested via TAXII feeds, the offline file watcher, or the fallback server.

### 6. Start the backend

```bash
uvicorn app.api.main:app --reload --port 8000
```

Or use the Makefile shortcut:

```bash
make run
```

Open `http://localhost:8000/docs` — interactive API documentation with built-in test interface.

### 7. Start the dashboard

In a second terminal:

```bash
cd frontend
npm install    # first time only
npm run dev    # opens http://localhost:5173
```

---

## Your first threat check

**Register an account:**
```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","password":"MyPass123!","role":"analyst"}'
```

**Log in — copy `access_token` from the response:**
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","password":"MyPass123!"}'
```

**Submit a network event:**
```bash
curl -X POST http://localhost:8000/event \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "evt-001",
    "source_ip": "192.168.1.10",
    "destination_ip": "185.220.101.45",
    "protocol": "TCP",
    "destination_port": 443
  }'
```

Response includes: IOC match result, ML anomaly score (0–100), classifier verdict, severity, and a PDF report link.

**Analyze a log file:**
```bash
curl -X POST http://localhost:8000/logs/full \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -F "file=@/path/to/access.log"
```

Returns every line that matched a known IOC or was flagged by ML, with line numbers and severity.

---

## Live TAXII polling

The scheduler starts automatically when the server boots. It polls configured TAXII feeds every 30 minutes using delta mode (only fetches IOCs added in the last 24 hours).

Each scheduler cycle also:
- Checks the **offline IOC folder** (`data/ioc_watch/`) for new STIX files
- Scans **configured log files** for IOC matches
- If all live feeds returned 0 results, triggers the **fallback IOC client**
- Feeds stored IOCs through the **ML anomaly detector**

**Check scheduler status:**
```bash
curl http://localhost:8000/scheduler/status \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Trigger a manual ingestion:**
```bash
curl -X POST http://localhost:8000/ingest/taxii \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Configure feeds in `.env`:
```
FEED_1_NAME=AlienVault OTX
FEED_1_URL=https://otx.alienvault.com/taxii/taxii2/
FEED_1_AUTH=api_key
FEED_1_API_KEY=your-otx-api-key
FEED_1_ENABLED=true
```

---

## IOC ingestion sources

The platform supports **three data sources** for IOCs, with automatic fallback:

| Priority | Source | Description |
|----------|--------|-------------|
| 1 | **TAXII feeds** | Live STIX 2.1 feeds (AlienVault OTX, CISA AIS, Anomali Limo) — polled every 30 min |
| 2 | **Fallback server** | Internal HTTP server — used automatically if ALL live feeds return 0 results |
| 3 | **Offline file watcher** | Drop `.json` or `.xml` files into `data/ioc_watch/` — auto-processed and moved |

### Offline file watcher

Drop any STIX JSON or XML file into `data/ioc_watch/`. The scheduler picks it up every cycle, parses it, inserts the IOCs, and moves the file to `data/ioc_processed/` with a timestamp suffix (so it's never processed twice).

Configure in `.env`:
```
IOC_WATCH_FOLDER=data/ioc_watch
IOC_PROCESSED_FOLDER=data/ioc_processed
IOC_WATCH_ENABLED=true
```

### Fallback IOC server

If all TAXII feeds fail (e.g. network issues), the scheduler automatically fetches IOCs from a configurable internal server. The server can respond with JSON (`[{"type":"ip","value":"1.2.3.4"}]`) or plain text (one IOC per line).

Configure in `.env`:
```
FALLBACK_IOC_URL=http://your-internal-server/api/iocs
FALLBACK_ENABLED=true
FALLBACK_AUTH=none
FALLBACK_API_KEY=
```

---

## Log analysis

The platform supports multiple modes of log analysis, accessible from the dashboard and API:

| Mode | What it does |
|------|-------------|
| **IOC-based** (`POST /logs/check`) | Extracts IPs, domains, URLs, hashes from each log line and checks against the IOC database |
| **File upload** (`POST /logs/upload`) | Upload a `.log`/`.txt`/`.csv`/`.syslog` file for IOC scanning with structured results |
| **ML-based** (`POST /logs/analyze`) | Parses each line as a network event and runs both ML models |
| **Combined** (`POST /logs/full`) | Runs both modes together — recommended |
| **Real-time stream** (`WebSocket /logs/stream`) | Tails a live log file and pushes hits as they appear |
| **Background results** (`GET /logs/results`) | View stored matches from the automatic log watcher |

### Background log watcher

The scheduler automatically scans configured log files for IOC matches. Supports two modes:

- **Single file**: Set `LOG_FILE_PATH=data/SSH_sample.log.log` in `.env`
- **Folder**: Set `LOG_WATCH_FOLDER=logs/` to scan all `.log`, `.txt`, and `.syslog` files

Only new lines are scanned each cycle (file position is tracked). Results are saved to the database and viewable via `GET /logs/results`.

---

## Advanced IOC filtering

The `GET /iocs` endpoint supports filtering by multiple fields:

```bash
# Filter by severity
curl "http://localhost:8000/iocs?severity=critical" -H "Authorization: Bearer ..."

# Filter by country code
curl "http://localhost:8000/iocs?country=CN" -H "Authorization: Bearer ..."

# Filter by minimum confidence score
curl "http://localhost:8000/iocs?confidence_min=80" -H "Authorization: Bearer ..."

# Combine filters
curl "http://localhost:8000/iocs?severity=high&country=RU&source=OTX" -H "Authorization: Bearer ..."
```

Available filters: `ioc_type`, `severity`, `country`, `confidence_min`, `source` (partial match).

---

## IOC metadata (superset)

Each IOC stored in the database carries the full metadata superset:

| Field | Description |
|-------|-------------|
| `stix_id` | Original STIX indicator ID |
| `ioc_type` | `ipv4-addr`, `domain-name`, `url`, `file-hash`, `email-addr` |
| `ioc_value` | The actual indicator value |
| `confidence` | Confidence score (0–100) |
| `severity` | Computed from confidence: Critical / High / Medium / Low |
| `source` | Feed or file that provided the IOC |
| `tlp` | Traffic Light Protocol marking (WHITE / GREEN / AMBER / RED) |
| `country` | Country code (populated by enrichment) |
| `geo_lat` / `geo_lon` | Geolocation coordinates |
| `city` / `asn` | City name and Autonomous System Number |
| `kill_chain` | Kill chain phase names (comma-separated) |
| `tags` | STIX labels (comma-separated) |
| `description` | STIX indicator description |
| `revoked` | Whether the indicator has been revoked |
| `external_refs` | External reference URLs |

---

## ML anomaly detection

The platform uses a **two-layer ML system:**

| Layer | Algorithm | Purpose |
|-------|-----------|---------| 
| Layer 1 | Random Forest (supervised) | Trained on NSL-KDD dataset — classifies known attack types (DoS, PortScan, R2L, U2R) |
| Layer 2 | Isolation Forest (unsupervised) | Learns your normal traffic — flags anything that stands out, even novel attacks |

Both layers use a **7-feature vector** aligned between training and prediction, ensuring consistency.

**Train Layer 1 (offline, on NSL-KDD dataset):**
```bash
# Place KDDTrain+.txt at data/nslkdd/KDDTrain+.txt
curl -X POST http://localhost:8000/ml/train-classifier \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{"sample_size": 10000}'
```

**Layer 2 trains automatically** once 50+ events are collected (configurable via `ML_MIN_TRAIN_SAMPLES`).

---

## User roles

| Role | What they can do |
|------|-----------------|
| `viewer` | Read alerts, browse IOC database, view metrics |
| `analyst` | All of viewer + submit events, triage alerts, train ML models, trigger ingestion |
| `admin` | All of analyst + manage user accounts |

---

## Key terms

**IOC** (Indicator of Compromise) — a known bad IP, domain, URL, or file hash. When traffic matches one, it gets flagged immediately.

**STIX** — standard format for sharing threat intelligence. The platform reads `.json` and `.xml` STIX 2.1 files and polls live TAXII servers.

**TAXII** — protocol for downloading STIX data automatically from threat servers. The scheduler polls every 30 minutes in the background.

**TLP** (Traffic Light Protocol) — marking system for sharing sensitivity (WHITE / GREEN / AMBER / RED). Extracted automatically from STIX `object_marking_refs`.

**Upsert** — when a TAXII feed updates an existing indicator (e.g. raises its confidence score), the platform updates the stored record rather than silently ignoring the change.

**Isolation Forest** — an unsupervised ML algorithm that learns what "normal" traffic looks like for your network, then flags anything that deviates. No manual labelling required.

**JWT** — the login system. After login you receive a short-lived access token (30 min default) and a refresh token (7 days default).

---

## Project layout

```
stix-threat-intel-platform/
│
├── app/                      ← All backend Python code
│   ├── api/
│   │   ├── main.py           ← Core API routes (events, IOCs, reports)
│   │   ├── ml.py             ← ML endpoints (train, predict, status)
│   │   ├── logs_router.py    ← Log analysis + WebSocket streaming
│   │   └── alerts_router.py  ← Alert management
│   ├── auth/                 ← JWT auth, password hashing, RBAC
│   ├── ingestion/
│   │   ├── taxii_client.py   ← TAXII 2.x multi-feed client
│   │   ├── scheduler.py      ← Background 30-min polling scheduler
│   │   ├── log_checker.py    ← IOC-based log file analysis
│   │   ├── log_watcher.py    ← Background log file scanner (NEW)
│   │   ├── file_watcher.py   ← Offline IOC folder watcher (NEW)
│   │   ├── fallback_client.py← Internal fallback IOC server (NEW)
│   │   └── ioc_manager.py    ← IOC expiry and lifecycle management
│   ├── ml/
│   │   ├── detector.py       ← Isolation Forest (Layer 2)
│   │   ├── classifier.py     ← Random Forest (Layer 1)
│   │   ├── log_analyzer.py   ← ML-based log file analysis
│   │   └── features.py       ← Feature extraction from network events
│   ├── database/
│   │   └── db_manager.py     ← SQLite with WAL mode, retry logic, upsert
│   └── utils/                ← PDF reports, logging, IP tools
│
├── tests/                    ← 301 automated tests (all passing)
├── frontend/                 ← React 18 + Recharts dashboard
├── data/
│   ├── certin_ti_gov.xml     ← Bundled STIX XML feed
│   ├── ioc_watch/            ← Drop STIX files here for auto-ingestion
│   ├── ioc_processed/        ← Processed files are moved here
│   └── nslkdd/               ← NSL-KDD dataset for ML training
├── reports/                  ← Generated PDF threat reports
├── docs/screenshots/         ← Dashboard + architecture screenshots
├── scripts/
│   └── train_classifier.py   ← Standalone RF training script
├── requirements.txt          ← Pinned Python dependencies
├── pytest.ini                ← Pytest configuration (markers, filters)
├── run.py                    ← CLI: initialize DB + load bundled feeds
├── Dockerfile                ← Multi-stage build (React + FastAPI)
├── docker-compose.yml        ← Local dev stack (backend + frontend)
├── .dockerignore             ← Docker build context exclusions
└── .env.example              ← Copy to .env and fill in your values
```

---

## Running the tests

```bash
# Activate your virtual environment first, then:
pytest tests/ -v --tb=short
```

Expected result: **301 passed, 0 failed**

> No manual `JWT_SECRET_KEY` export needed — `conftest.py` sets a fixed test key automatically.

---

## Docker

```bash
# Build and start everything
docker-compose up --build

# Backend:  http://localhost:8000
# Frontend: http://localhost:5173
# API docs: http://localhost:8000/docs
```

The Docker setup uses a named volume for `frontend_node_modules` to persist dependencies across container restarts, and `npm ci` for faster, deterministic installs.

---

## Configuration reference

Copy `.env.example` to `.env` and set your values:

### Core settings

| Variable | Default | What it controls |
|----------|---------|----|
| `JWT_SECRET_KEY` | **required** | Signs login tokens — generate with `secrets.token_hex(32)` |
| `JWT_EXPIRE_MINUTES` | `30` | How long an access token stays valid |
| `JWT_REFRESH_EXPIRE_DAYS` | `7` | How long a refresh token stays valid |
| `FRONTEND_URL` | `http://localhost:5173` | Added to CORS allowed origins |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### ML settings

| Variable | Default | What it controls |
|----------|---------|----|
| `ML_MIN_TRAIN_SAMPLES` | `50` | Events needed before Isolation Forest auto-trains |
| `ML_CONTAMINATION` | `0.05` | Expected anomaly fraction (5 per 100 events) |
| `ML_RETRAIN_INTERVAL` | `100` | Auto-retrain every N new events |

### TAXII feed settings

| Variable | Default | What it controls |
|----------|---------|----|
| `FEED_1_NAME` | `AlienVault OTX` | Display name for TAXII feed 1 |
| `FEED_1_URL` | — | TAXII server URL for feed 1 |
| `FEED_1_API_KEY` | — | API key for feed 1 (if auth_type=api_key) |
| `FEED_1_ENABLED` | `true` | Enable/disable feed 1 |
| `SCHEDULER_INTERVAL_MINUTES` | `30` | How often TAXII feeds are polled |

### Offline file watcher

| Variable | Default | What it controls |
|----------|---------|----|
| `IOC_WATCH_FOLDER` | `data/ioc_watch` | Folder to watch for dropped STIX files |
| `IOC_PROCESSED_FOLDER` | `data/ioc_processed` | Where processed files are moved |
| `IOC_WATCH_ENABLED` | `true` | Enable/disable the file watcher |

### Background log watcher

| Variable | Default | What it controls |
|----------|---------|----|
| `LOG_FILE_PATH` | — | Single log file to scan (Option A) |
| `LOG_WATCH_FOLDER` | — | Folder of log files to scan (Option B) |
| `LOG_WATCH_ENABLED` | `true` | Enable/disable the log watcher |

### Fallback IOC server

| Variable | Default | What it controls |
|----------|---------|----|
| `FALLBACK_IOC_URL` | — | URL of the internal fallback IOC server |
| `FALLBACK_ENABLED` | `true` | Enable/disable the fallback client |
| `FALLBACK_AUTH` | `none` | Auth type: `none`, `api_key`, or `bearer` |
| `FALLBACK_API_KEY` | — | API key for the fallback server (if auth required) |

---

## What's planned next

- [ ] Export correlated threats as STIX 2.1 bundles (`GET /export/stix`)
- [ ] SHAP-based ML explanations — show *why* the model flagged an event
- [ ] Analyst false-positive feedback loop to improve model accuracy over time
- [ ] Migrate to PostgreSQL for high-volume deployments
- [ ] Nginx reverse proxy config for production deployment
- [ ] GeoIP enrichment — automatically populate country/city/ASN from IP addresses

---

## License

MIT — free to use and modify.