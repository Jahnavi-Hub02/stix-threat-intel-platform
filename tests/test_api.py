"""
tests/test_api.py
=================
Integration tests for all FastAPI endpoints.
All protected endpoints now supply a JWT token via the
`viewer_token` or `analyst_token` fixtures from conftest.py.
"""
import pytest
import json as json_lib


# ── Shared auth header helper ─────────────────────────────────────
def _h(token):
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════
# Health (public — no token needed)
# ══════════════════════════════════════════════════════════════════

@pytest.mark.api
class TestHealthEndpoints:

    def test_root(self, api_client):
        r = api_client.get("/")
        assert r.status_code == 200
        assert r.json()["status"] == "operational"

    def test_health(self, api_client):
        r = api_client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_metrics(self, api_client, viewer_token):
        r = api_client.get("/metrics", headers=_h(viewer_token))
        assert r.status_code == 200
        data = r.json()
        assert "statistics" in data or "data" in data

    def test_metrics_no_token_returns_401(self, api_client):
        assert api_client.get("/metrics").status_code == 401


# ══════════════════════════════════════════════════════════════════
# IOCs (viewer+)
# ══════════════════════════════════════════════════════════════════

@pytest.mark.api
class TestIOCEndpoints:

    def test_list_iocs_empty(self, api_client, viewer_token):
        r = api_client.get("/iocs", headers=_h(viewer_token))
        assert r.status_code == 200
        data = r.json()
        assert "iocs" in data
        assert isinstance(data["iocs"], list)

    def test_list_iocs_no_token_returns_401(self, api_client):
        assert api_client.get("/iocs").status_code == 401

    def test_list_iocs_with_data(self, api_client, viewer_token, db_with_iocs):
        r = api_client.get("/iocs?limit=10", headers=_h(viewer_token))
        assert r.status_code == 200
        assert r.json()["total"] > 0

    def test_list_iocs_type_filter(self, api_client, viewer_token, db_with_iocs):
        r = api_client.get("/iocs?ioc_type=ipv4", headers=_h(viewer_token))
        assert r.status_code == 200
        for ioc in r.json()["iocs"]:
            assert ioc["ioc_type"] == "ipv4"

    def test_list_iocs_pagination(self, api_client, viewer_token, db_with_iocs):
        h = _h(viewer_token)
        page1 = api_client.get("/iocs?limit=2&offset=0", headers=h).json()["iocs"]
        page2 = api_client.get("/iocs?limit=2&offset=2", headers=h).json()["iocs"]
        ids1 = {i["id"] for i in page1}
        ids2 = {i["id"] for i in page2}
        assert ids1.isdisjoint(ids2)

    def test_lookup_existing_ioc(self, api_client, viewer_token, db_with_iocs):
        r = api_client.get("/iocs/185.220.101.45", headers=_h(viewer_token))
        assert r.status_code == 200
        assert r.json()["ioc"]["ioc_value"] == "185.220.101.45"

    def test_lookup_missing_ioc(self, api_client, viewer_token, db_with_iocs):
        r = api_client.get("/iocs/9.9.9.9", headers=_h(viewer_token))
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════
# Events (analyst+)
# ══════════════════════════════════════════════════════════════════

@pytest.mark.api
class TestEventEndpoints:

    def test_submit_benign_event(self, api_client, analyst_token, db_with_iocs):
        r = api_client.post("/event", headers=_h(analyst_token), json={
            "event_id":        "api-test-001",
            "source_ip":       "8.8.8.8",
            "destination_ip":  "1.1.1.1",
            "timestamp":       "2024-01-01T00:00:00",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "benign"
        assert data.get("threats_found", 0) == 0
        assert data["ioc_analysis"]["matches_found"] == 0

    def test_submit_threat_event(self, api_client, analyst_token, db_with_iocs):
        r = api_client.post("/event", headers=_h(analyst_token), json={
            "event_id":        "api-test-002",
            "source_ip":       "185.220.101.45",
            "destination_ip":  "192.168.1.10",
            "timestamp":       "2024-01-01T00:00:00",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["status"]         == "threat_detected"
        assert data["threats_found"]  >= 1
        assert data["top_severity"]   in ["Critical", "High", "Medium", "Low"]
        assert data["top_risk_score"] > 0

    def test_event_has_report_path(self, api_client, analyst_token, db_with_iocs):
        r = api_client.post("/event", headers=_h(analyst_token), json={
            "event_id":       "api-test-003",
            "source_ip":      "8.8.8.8",
            "destination_ip": "1.1.1.1",
        })
        assert "report" in r.json()

    def test_event_missing_required_fields(self, api_client, analyst_token):
        """Missing source_ip → 422 validation error (checked before auth body parse)."""
        r = api_client.post("/event", headers=_h(analyst_token),
                            json={"event_id": "bad-event"})
        assert r.status_code == 422

    def test_event_auto_timestamp(self, api_client, analyst_token, db_with_iocs):
        r = api_client.post("/event", headers=_h(analyst_token), json={
            "event_id":       "api-test-004",
            "source_ip":      "8.8.8.8",
            "destination_ip": "1.1.1.1",
        })
        assert r.status_code == 200

    def test_event_no_token_returns_401(self, api_client):
        r = api_client.post("/event", json={
            "event_id": "x", "source_ip": "1.2.3.4", "destination_ip": "5.6.7.8"
        })
        assert r.status_code == 401

    def test_event_viewer_returns_403(self, api_client, viewer_token):
        """Viewer role cannot submit events — analyst+ only."""
        r = api_client.post("/event", headers=_h(viewer_token), json={
            "event_id": "x", "source_ip": "1.2.3.4", "destination_ip": "5.6.7.8"
        })
        assert r.status_code == 403


# ══════════════════════════════════════════════════════════════════
# Correlations (viewer+)
# ══════════════════════════════════════════════════════════════════

@pytest.mark.api
class TestCorrelationEndpoints:

    def test_list_correlations_empty(self, api_client, viewer_token):
        r = api_client.get("/correlations", headers=_h(viewer_token))
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_list_correlations_after_event(self, api_client, analyst_token,
                                            viewer_token, db_with_iocs):
        api_client.post("/event", headers=_h(analyst_token), json={
            "event_id":       "corr-test-001",
            "source_ip":      "185.220.101.45",
            "destination_ip": "1.1.1.1",
        })
        r = api_client.get("/correlations", headers=_h(viewer_token))
        assert r.status_code == 200
        assert r.json()["total"] >= 1

    def test_filter_correlations_by_event(self, api_client, analyst_token,
                                           viewer_token, db_with_iocs):
        api_client.post("/event", headers=_h(analyst_token), json={
            "event_id":       "corr-filter-test",
            "source_ip":      "185.220.101.45",
            "destination_ip": "1.1.1.1",
        })
        r = api_client.get("/correlations?event_id=corr-filter-test",
                           headers=_h(viewer_token))
        assert r.status_code == 200
        for c in r.json()["results"]:
            assert c["event_id"] == "corr-filter-test"


# ══════════════════════════════════════════════════════════════════
# Ingestion (analyst+)
# ══════════════════════════════════════════════════════════════════

@pytest.mark.api
class TestIngestionEndpoints:

    def test_list_servers(self, api_client, viewer_token):
        r = api_client.get("/ingest/servers", headers=_h(viewer_token))
        assert r.status_code == 200
        data = r.json()
        assert "servers" in data
        assert len(data["servers"]) > 0

    def test_file_ingest_missing_file(self, api_client, analyst_token, temp_db):
        r = api_client.post("/ingest/file", headers=_h(analyst_token), json={
            "file_path": "/nonexistent/file.json",
            "file_type": "json",
        })
        assert r.status_code == 404

    def test_file_ingest_invalid_type(self, api_client, analyst_token,
                                       temp_db, tmp_path):
        path = str(tmp_path / "test.csv")
        open(path, "w").write("a,b,c")
        r = api_client.post("/ingest/file", headers=_h(analyst_token), json={
            "file_path": path,
            "file_type": "csv",
        })
        assert r.status_code == 400

    def test_file_ingest_json(self, api_client, analyst_token, temp_db, tmp_path):
        path = str(tmp_path / "bundle.json")
        with open(path, "w") as f:
            json_lib.dump({"type": "bundle", "objects": [{
                "type":       "indicator",
                "id":         "indicator--test",
                "pattern":    "[ipv4-addr:value = '5.5.5.5']",
                "confidence": 80,
            }]}, f)
        r = api_client.post("/ingest/file", headers=_h(analyst_token), json={
            "file_path": path,
            "file_type": "json",
        })
        assert r.status_code == 200
        assert r.json()["stored"] == 1

    def test_trigger_ingestion(self, api_client, analyst_token):
        r = api_client.post("/ingest/trigger", headers=_h(analyst_token))
        assert r.status_code == 200
        assert r.json()["status"] == "accepted"

    def test_ingest_no_token_returns_401(self, api_client):
        r = api_client.post("/ingest/trigger")
        assert r.status_code == 401

    def test_ingest_viewer_returns_403(self, api_client, viewer_token):
        r = api_client.post("/ingest/trigger", headers=_h(viewer_token))
        assert r.status_code == 403


# ══════════════════════════════════════════════════════════════════
# Scheduler (viewer+)
# ══════════════════════════════════════════════════════════════════

@pytest.mark.api
class TestSchedulerEndpoint:

    def test_scheduler_status(self, api_client, viewer_token):
        r = api_client.get("/scheduler/status", headers=_h(viewer_token))
        assert r.status_code == 200
        data = r.json()
        assert "is_running" in data or "scheduler_running" in data