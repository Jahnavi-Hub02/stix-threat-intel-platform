"""
Shared pytest fixtures for the STIX Threat Intelligence Platform test suite.
"""
import os
import sys
import sqlite3
import tempfile
import pytest

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────
# Temporary in-memory / temp-file database for tests
# ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="function")
def temp_db(monkeypatch, tmp_path):
    """
    Create a fresh temporary SQLite database for each test.
    Patches DB_PATH so tests never touch the real database.
    """
    db_file = str(tmp_path / "test.db")
    monkeypatch.setattr("app.database.db_manager.DB_PATH", db_file)

    # Import after patching so the path is correct
    from app.database.db_manager import create_tables
    create_tables()

    yield db_file


@pytest.fixture(scope="function")
def db_with_iocs(temp_db):
    """
    A temp database pre-loaded with sample IOC indicators.
    """
    from app.database.db_manager import insert_indicators

    sample_iocs = [
        {"stix_id": "indicator--001", "ioc_type": "ipv4",  "ioc_subtype": "network",
         "ioc_value": "185.220.101.45", "confidence": 90, "source": "Test Feed"},
        {"stix_id": "indicator--002", "ioc_type": "ipv4",  "ioc_subtype": "network",
         "ioc_value": "91.108.4.1",    "confidence": 75, "source": "Test Feed"},
        {"stix_id": "indicator--003", "ioc_type": "domain","ioc_subtype": "network",
         "ioc_value": "evil.example.com","confidence": 80, "source": "Test Feed"},
        {"stix_id": "indicator--004", "ioc_type": "sha256","ioc_subtype": "file_hash",
         "ioc_value": "a" * 64,        "confidence": 95, "source": "Test Feed"},
        {"stix_id": "indicator--005", "ioc_type": "md5",   "ioc_subtype": "file_hash",
         "ioc_value": "b" * 32,        "confidence": 70, "source": "Test Feed"},
    ]
    insert_indicators(sample_iocs, source_label="Test Feed")
    yield temp_db


@pytest.fixture(scope="function")
def sample_event():
    """Standard test network event."""
    return {
        "event_id":        "test-evt-001",
        "source_ip":       "185.220.101.45",   # known malicious IP in db_with_iocs
        "destination_ip":  "192.168.1.100",    # private — should be skipped
        "source_port":     54231,
        "destination_port": 443,
        "protocol":        "TCP",
        "timestamp":       "2024-01-15T10:30:00"
    }


@pytest.fixture(scope="function")
def api_client(temp_db):
    """
    FastAPI test client with a fresh database.
    """
    from fastapi.testclient import TestClient
    from app.api.main import app
    return TestClient(app)
