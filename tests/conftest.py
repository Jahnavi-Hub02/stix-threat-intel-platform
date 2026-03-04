"""
Shared pytest fixtures for the STIX Threat Intelligence Platform test suite.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="function")
def temp_db(monkeypatch, tmp_path):
    """
    Isolated SQLite database + ML paths for every test.

    Patch order matters:
      1. Kill the ML singleton FIRST (before any import of app.api.main)
      2. Redirect DB_PATH so db_manager writes to tmp file
      3. Redirect ML detector's _get_db_path to the same tmp file
      4. Redirect ML model dir so no .pkl files touch the real filesystem
      5. Lower MIN_TRAIN_SAMPLES so API tests can train in-test
      6. Create all tables (DB + ML)

    When TestClient(app) is later constructed, the lifespan handler calls
    get_detector() which builds a FRESH AnomalyDetector pointing at tmp paths.
    """
    import app.ml.detector as ml_det

    # ── 1. Kill any existing singleton from a previous test ──────
    ml_det._detector_instance = None

    # ── 2. Patch main DB path ────────────────────────────────────
    db_file = str(tmp_path / "test.db")
    monkeypatch.setattr("app.database.db_manager.DB_PATH", db_file)

    # ── 3. Patch ML detector's DB accessor ──────────────────────
    monkeypatch.setattr(ml_det, "_get_db_path", lambda: db_file)

    # ── 4. Patch ML model paths ──────────────────────────────────
    model_dir = str(tmp_path / "models")
    os.makedirs(model_dir, exist_ok=True)
    monkeypatch.setattr(ml_det, "MODEL_DIR",   model_dir)
    monkeypatch.setattr(ml_det, "MODEL_PATH",  os.path.join(model_dir, "if.pkl"))
    monkeypatch.setattr(ml_det, "SCALER_PATH", os.path.join(model_dir, "sc.pkl"))

    # ── 5. Low training threshold for fast tests ─────────────────
    monkeypatch.setattr(ml_det, "MIN_TRAIN_SAMPLES", 5)
    monkeypatch.setattr(ml_det, "RETRAIN_INTERVAL",  1000)

    # ── 6. Create DB + ML tables ─────────────────────────────────
    from app.database.db_manager import create_tables
    create_tables()
    ml_det._create_ml_tables()

    yield db_file

    # Teardown: nuke singleton so the NEXT test starts clean
    ml_det._detector_instance = None


@pytest.fixture(scope="function")
def db_with_iocs(temp_db):
    """Temp database pre-loaded with 5 sample IOC indicators."""
    from app.database.db_manager import insert_indicators
    sample_iocs = [
        {"stix_id": "indicator--001", "ioc_type": "ipv4",   "ioc_subtype": "network",
         "ioc_value": "185.220.101.45", "confidence": 90, "source": "Test Feed"},
        {"stix_id": "indicator--002", "ioc_type": "ipv4",   "ioc_subtype": "network",
         "ioc_value": "91.108.4.1",    "confidence": 75, "source": "Test Feed"},
        {"stix_id": "indicator--003", "ioc_type": "domain", "ioc_subtype": "network",
         "ioc_value": "evil.example.com", "confidence": 80, "source": "Test Feed"},
        {"stix_id": "indicator--004", "ioc_type": "sha256", "ioc_subtype": "file_hash",
         "ioc_value": "a" * 64, "confidence": 95, "source": "Test Feed"},
        {"stix_id": "indicator--005", "ioc_type": "md5",    "ioc_subtype": "file_hash",
         "ioc_value": "b" * 32, "confidence": 70, "source": "Test Feed"},
    ]
    insert_indicators(sample_iocs, source_label="Test Feed")
    yield temp_db


@pytest.fixture(scope="function")
def sample_event():
    return {
        "event_id":         "test-evt-001",
        "source_ip":        "185.220.101.45",
        "destination_ip":   "192.168.1.100",
        "source_port":      54231,
        "destination_port": 443,
        "protocol":         "TCP",
        "timestamp":        "2024-01-15T10:30:00",
    }


@pytest.fixture(scope="function")
def api_client(temp_db):
    """
    FastAPI TestClient with isolated DB + ML paths.
    temp_db fixture runs FIRST, resetting the singleton and patching all
    paths — so when TestClient(app) triggers the lifespan startup,
    get_detector() builds a fresh detector pointing at tmp_path.
    """
    from fastapi.testclient import TestClient
    from app.api.main import app
    return TestClient(app)