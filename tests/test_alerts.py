"""
tests/test_alerts.py
====================
Tests for the alert triage workflow (Step 11).

  GET  /alerts              — list alerts (viewer+)
  GET  /alerts/{id}         — single alert (viewer+)
  PATCH /alerts/{id}/status — update triage status (analyst+)
"""

import pytest


# ── Helpers ────────────────────────────────────────────────────────

def _register(client, username, role="analyst", password="Password123!"):
    return client.post("/auth/register", json={"username": username, "password": password, "role": role})


def _login(client, username, password="Password123!"):
    return client.post("/auth/login", json={"username": username, "password": password})


def _token(client, username, role="analyst"):
    if role == "admin":
        from app.auth.security import hash_password
        from app.database.db_manager import create_user
        try:
            create_user(username, hash_password("Password123!"), role="admin")
        except ValueError:
            pass
    else:
        _register(client, username, role=role)
    return _login(client, username).json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _submit_event(client, token, event_id="alert-evt-001",
                  source_ip="185.220.101.45", dest_ip="10.0.0.1"):
    """Submit a known-malicious IP event to trigger an IOC alert."""
    return client.post("/event", headers=_auth(token), json={
        "event_id":       event_id,
        "source_ip":      source_ip,
        "destination_ip": dest_ip,
        "destination_port": 443,
        "protocol": "TCP",
    })


# ── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def client_with_iocs(temp_db):
    """TestClient with isolated DB pre-loaded with a known malicious IP."""
    from fastapi.testclient import TestClient
    from app.api.main import app
    from app.database.db_manager import insert_indicators, create_tables

    # Must create tables first — lifespan hasn't run yet at this point
    create_tables()

    insert_indicators([{
        "stix_id": "indicator--alert-001", "ioc_type": "ipv4",
        "ioc_value": "185.220.101.45", "confidence": 90, "source": "Test Feed",
    }])

    with TestClient(app) as c:
        yield c


# ══════════════════════════════════════════════════════════════════
# Listing Alerts
# ══════════════════════════════════════════════════════════════════

class TestListAlerts:

    def test_list_alerts_requires_auth(self, api_client):
        assert api_client.get("/alerts").status_code == 401

    def test_viewer_can_list_alerts(self, api_client):
        token = _token(api_client, "viewer_alerts", role="viewer")
        r = api_client.get("/alerts", headers=_auth(token))
        assert r.status_code == 200
        data = r.json()
        assert "alerts"  in data
        assert "summary" in data
        assert "total"   in data

    def test_list_alerts_empty_by_default(self, api_client):
        token = _token(api_client, "empty_viewer", role="viewer")
        r = api_client.get("/alerts", headers=_auth(token))
        assert r.status_code == 200
        assert r.json()["total"] == 0
        assert r.json()["alerts"] == []

    def test_alert_created_after_threat_event(self, client_with_iocs):
        """Submitting an event with a known-malicious IP should create an alert."""
        token = _token(client_with_iocs, "analyst_alert_test")
        _submit_event(client_with_iocs, token)

        viewer_token = _token(client_with_iocs, "alert_viewer", role="viewer")
        r = client_with_iocs.get("/alerts", headers=_auth(viewer_token))
        assert r.status_code == 200
        assert r.json()["total"] >= 1

    def test_new_alert_has_correct_fields(self, client_with_iocs):
        token = _token(client_with_iocs, "alert_fields_user")
        _submit_event(client_with_iocs, token, event_id="field-test-evt")

        r = client_with_iocs.get("/alerts", headers=_auth(token))
        alert = r.json()["alerts"][0]

        assert "id"             in alert
        assert "event_id"       in alert
        assert "status"         in alert
        assert "severity"       in alert
        assert "alert_type"     in alert
        assert "risk_score"     in alert
        assert "source_ip"      in alert
        assert "destination_ip" in alert
        assert "created_at"     in alert

    def test_new_alert_status_is_NEW(self, client_with_iocs):
        token = _token(client_with_iocs, "new_status_user")
        _submit_event(client_with_iocs, token, event_id="new-status-evt")

        r = client_with_iocs.get("/alerts", headers=_auth(token))
        alert = r.json()["alerts"][0]
        assert alert["status"] == "NEW"

    def test_filter_alerts_by_status(self, client_with_iocs):
        token = _token(client_with_iocs, "filter_user")
        _submit_event(client_with_iocs, token, event_id="filter-evt")

        r = client_with_iocs.get("/alerts?status=NEW", headers=_auth(token))
        assert r.status_code == 200
        for alert in r.json()["alerts"]:
            assert alert["status"] == "NEW"

    def test_filter_unknown_status_returns_empty(self, client_with_iocs):
        token = _token(client_with_iocs, "unknown_filter_user")
        _submit_event(client_with_iocs, token)
        r = client_with_iocs.get("/alerts?status=NONEXISTENT", headers=_auth(token))
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_alert_summary_counts_by_status(self, client_with_iocs):
        token = _token(client_with_iocs, "summary_user")
        _submit_event(client_with_iocs, token, event_id="summary-evt")
        r = client_with_iocs.get("/alerts", headers=_auth(token))
        summary = r.json()["summary"]
        assert "NEW" in summary
        assert summary["NEW"] >= 1


# ══════════════════════════════════════════════════════════════════
# Get Single Alert
# ══════════════════════════════════════════════════════════════════

class TestGetAlert:

    def test_get_alert_by_id(self, client_with_iocs):
        token = _token(client_with_iocs, "get_alert_user")
        _submit_event(client_with_iocs, token, event_id="get-single-evt")

        alerts = client_with_iocs.get("/alerts", headers=_auth(token)).json()["alerts"]
        alert_id = alerts[0]["id"]

        r = client_with_iocs.get(f"/alerts/{alert_id}", headers=_auth(token))
        assert r.status_code == 200
        assert r.json()["id"] == alert_id

    def test_get_nonexistent_alert_returns_404(self, api_client):
        token = _token(api_client, "get_404_user")
        assert api_client.get("/alerts/99999", headers=_auth(token)).status_code == 404

    def test_get_alert_requires_auth(self, api_client):
        assert api_client.get("/alerts/1").status_code == 401


# ══════════════════════════════════════════════════════════════════
# Update Alert Status (Triage)
# ══════════════════════════════════════════════════════════════════

class TestUpdateAlertStatus:

    def test_analyst_can_update_alert_to_investigating(self, client_with_iocs):
        token = _token(client_with_iocs, "triage_analyst")
        _submit_event(client_with_iocs, token, event_id="triage-evt-001")

        alerts   = client_with_iocs.get("/alerts", headers=_auth(token)).json()["alerts"]
        alert_id = alerts[0]["id"]

        r = client_with_iocs.patch(
            f"/alerts/{alert_id}/status",
            headers=_auth(token),
            json={"status": "INVESTIGATING"},
        )
        assert r.status_code == 200
        assert r.json()["new_status"] == "INVESTIGATING"
        assert r.json()["updated_by"] == "triage_analyst"

    def test_status_persists_after_update(self, client_with_iocs):
        token = _token(client_with_iocs, "persist_analyst")
        _submit_event(client_with_iocs, token, event_id="persist-evt")

        alerts   = client_with_iocs.get("/alerts", headers=_auth(token)).json()["alerts"]
        alert_id = alerts[0]["id"]

        client_with_iocs.patch(
            f"/alerts/{alert_id}/status",
            headers=_auth(token),
            json={"status": "RESOLVED", "notes": "Confirmed and remediated."},
        )

        updated = client_with_iocs.get(f"/alerts/{alert_id}", headers=_auth(token)).json()
        assert updated["status"]  == "RESOLVED"
        assert updated["notes"]   == "Confirmed and remediated."
        assert updated["assigned_to"] == "persist_analyst"
        assert updated["resolved_at"] is not None

    def test_mark_as_false_positive(self, client_with_iocs):
        token = _token(client_with_iocs, "fp_analyst")
        _submit_event(client_with_iocs, token, event_id="fp-evt")

        alerts   = client_with_iocs.get("/alerts", headers=_auth(token)).json()["alerts"]
        alert_id = alerts[0]["id"]

        r = client_with_iocs.patch(
            f"/alerts/{alert_id}/status",
            headers=_auth(token),
            json={"status": "FALSE_POSITIVE", "notes": "Internal scanner — whitelist"},
        )
        assert r.status_code == 200
        assert r.json()["new_status"] == "FALSE_POSITIVE"

    def test_viewer_cannot_update_alert_status(self, client_with_iocs):
        analyst_token = _token(client_with_iocs, "analyst_for_viewer_test")
        _submit_event(client_with_iocs, analyst_token, event_id="viewer-block-evt")

        viewer_token = _token(client_with_iocs, "blocked_viewer", role="viewer")
        alerts   = client_with_iocs.get("/alerts", headers=_auth(viewer_token)).json()["alerts"]
        alert_id = alerts[0]["id"]

        r = client_with_iocs.patch(
            f"/alerts/{alert_id}/status",
            headers=_auth(viewer_token),
            json={"status": "INVESTIGATING"},
        )
        assert r.status_code == 403

    def test_update_requires_auth(self, api_client):
        r = api_client.patch("/alerts/1/status", json={"status": "INVESTIGATING"})
        assert r.status_code == 401

    def test_update_invalid_status_returns_422(self, client_with_iocs):
        token = _token(client_with_iocs, "invalid_status_user")
        _submit_event(client_with_iocs, token, event_id="invalid-status-evt")

        alerts   = client_with_iocs.get("/alerts", headers=_auth(token)).json()["alerts"]
        alert_id = alerts[0]["id"]

        r = client_with_iocs.patch(
            f"/alerts/{alert_id}/status",
            headers=_auth(token),
            json={"status": "INVALID_STATUS"},
        )
        assert r.status_code == 422

    def test_update_nonexistent_alert_returns_404(self, api_client):
        token = _token(api_client, "not_found_analyst")
        r = api_client.patch(
            "/alerts/99999/status",
            headers=_auth(token),
            json={"status": "INVESTIGATING"},
        )
        assert r.status_code == 404

    def test_update_with_notes_stores_notes(self, client_with_iocs):
        token = _token(client_with_iocs, "notes_analyst")
        _submit_event(client_with_iocs, token, event_id="notes-evt")

        alerts   = client_with_iocs.get("/alerts", headers=_auth(token)).json()["alerts"]
        alert_id = alerts[0]["id"]

        client_with_iocs.patch(
            f"/alerts/{alert_id}/status",
            headers=_auth(token),
            json={"status": "INVESTIGATING", "notes": "Checking firewall logs now."},
        )

        updated = client_with_iocs.get(f"/alerts/{alert_id}", headers=_auth(token)).json()
        assert updated["notes"] == "Checking firewall logs now."

    def test_notes_too_long_returns_422(self, client_with_iocs):
        token = _token(client_with_iocs, "long_notes_user")
        _submit_event(client_with_iocs, token, event_id="long-notes-evt")

        alerts   = client_with_iocs.get("/alerts", headers=_auth(token)).json()["alerts"]
        alert_id = alerts[0]["id"]

        r = client_with_iocs.patch(
            f"/alerts/{alert_id}/status",
            headers=_auth(token),
            json={"status": "INVESTIGATING", "notes": "x" * 1001},
        )
        assert r.status_code == 422


# ══════════════════════════════════════════════════════════════════
# Security: event_id path traversal prevention
# ══════════════════════════════════════════════════════════════════

class TestEventIdSecurity:

    def test_event_id_path_traversal_blocked(self, api_client):
        token = _token(api_client, "sec_analyst")
        r = api_client.post("/event", headers=_auth(token), json={
            "event_id":       "../etc/passwd",
            "source_ip":      "1.2.3.4",
            "destination_ip": "5.6.7.8",
        })
        assert r.status_code == 400
        assert "invalid" in r.json()["detail"].lower()

    def test_valid_event_id_accepted(self, api_client):
        token = _token(api_client, "valid_id_analyst")
        r = api_client.post("/event", headers=_auth(token), json={
            "event_id":       "evt-2024-001",
            "source_ip":      "1.2.3.4",
            "destination_ip": "5.6.7.8",
        })
        assert r.status_code == 200
