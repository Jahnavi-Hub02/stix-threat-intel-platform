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
    Isolated SQLite + ML paths for every test.
    Kills ML singleton BEFORE TestClient is built so lifespan
    creates a fresh detector pointing at tmp paths.
    """
    import app.ml.detector as ml_det

    # 1. Kill any existing ML singleton immediately
    ml_det._detector_instance = None

    # 2. Patch main DB path
    db_file = str(tmp_path / "test.db")
    monkeypatch.setattr("app.database.db_manager.DB_PATH", db_file)

    # 3. Patch ML detector DB accessor
    monkeypatch.setattr(ml_det, "_get_db_path", lambda: db_file)

    # 4. Patch ML model paths
    model_dir = str(tmp_path / "models")
    os.makedirs(model_dir, exist_ok=True)
    monkeypatch.setattr(ml_det, "MODEL_DIR",   model_dir)
    monkeypatch.setattr(ml_det, "MODEL_PATH",  os.path.join(model_dir, "if.pkl"))
    monkeypatch.setattr(ml_det, "SCALER_PATH", os.path.join(model_dir, "sc.pkl"))

    # 5. Low training threshold for fast tests
    monkeypatch.setattr(ml_det, "MIN_TRAIN_SAMPLES", 5)
    monkeypatch.setattr(ml_det, "RETRAIN_INTERVAL",  1000)

    # 6. Create all DB tables (main + ML + auth)
    from app.database.db_manager import create_tables
    create_tables()
    ml_det._create_ml_tables()

    yield db_file

    # Teardown: reset singleton so next test starts clean
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
    """FastAPI TestClient with isolated DB + ML paths."""
    from fastapi.testclient import TestClient
    from app.api.main import app
    return TestClient(app)


# ── Auth helpers shared across test files ─────────────────────────

@pytest.fixture(scope="function")
def analyst_token(api_client):
    """Register + login an analyst user, return access token."""
    api_client.post("/auth/register", json={
        "username": "analyst_fixture", "password": "Password123!", "role": "analyst"
    })
    r = api_client.post("/auth/login", json={
        "username": "analyst_fixture", "password": "Password123!"
    })
    return r.json()["access_token"]


@pytest.fixture(scope="function")
def viewer_token(api_client):
    """Register + login a viewer user, return access token."""
    api_client.post("/auth/register", json={
        "username": "viewer_fixture", "password": "Password123!", "role": "viewer"
    })
    r = api_client.post("/auth/login", json={
        "username": "viewer_fixture", "password": "Password123!"
    })
    return r.json()["access_token"]


@pytest.fixture(scope="function")
def admin_token(api_client):
    """Register + login an admin user, return access token."""
    api_client.post("/auth/register", json={
        "username": "admin_fixture", "password": "Password123!", "role": "admin"
    })
    r = api_client.post("/auth/login", json={
        "username": "admin_fixture", "password": "Password123!"
    })
    return r.json()["access_token"]


def auth_header(token: str) -> dict:
    """Build Authorization header dict from token string."""
    return {"Authorization": f"Bearer {token}"}
