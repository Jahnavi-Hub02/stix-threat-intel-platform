"""
Integration tests — FastAPI endpoints
Tests every route in app/api/main.py
"""
import pytest


@pytest.mark.api
class TestHealthEndpoints:
    def test_root(self, api_client):
        r = api_client.get("/")
        assert r.status_code == 200
        data = r.json()
        assert "platform" in data
        assert data["status"] == "operational"

    def test_health(self, api_client):
        r = api_client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_metrics(self, api_client):
        r = api_client.get("/metrics")
        assert r.status_code == 200
        data = r.json()
        assert "statistics" in data or "data" in data


@pytest.mark.api
class TestIOCEndpoints:
    def test_list_iocs_empty(self, api_client):
        r = api_client.get("/iocs")
        assert r.status_code == 200
        data = r.json()
        assert "iocs" in data
        assert isinstance(data["iocs"], list)

    def test_list_iocs_with_data(self, api_client, db_with_iocs):
        r = api_client.get("/iocs?limit=10")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] > 0

    def test_list_iocs_type_filter(self, api_client, db_with_iocs):
        r = api_client.get("/iocs?ioc_type=ipv4")
        assert r.status_code == 200
        data = r.json()
        for ioc in data["iocs"]:
            assert ioc["ioc_type"] == "ipv4"

    def test_list_iocs_pagination(self, api_client, db_with_iocs):
        page1 = api_client.get("/iocs?limit=2&offset=0").json()["iocs"]
        page2 = api_client.get("/iocs?limit=2&offset=2").json()["iocs"]
        ids1 = {i["id"] for i in page1}
        ids2 = {i["id"] for i in page2}
        assert ids1.isdisjoint(ids2)

    def test_lookup_existing_ioc(self, api_client, db_with_iocs):
        r = api_client.get("/iocs/185.220.101.45")
        assert r.status_code == 200
        data = r.json()
        assert data["ioc"]["ioc_value"] == "185.220.101.45"

    def test_lookup_missing_ioc(self, api_client, db_with_iocs):
        r = api_client.get("/iocs/9.9.9.9")
        assert r.status_code == 404


@pytest.mark.api
class TestEventEndpoints:
    def test_submit_benign_event(self, api_client, db_with_iocs):
        """Event with no matching IPs → benign."""
        r = api_client.post("/event", json={
            "event_id": "api-test-001",
            "source_ip": "8.8.8.8",
            "destination_ip": "1.1.1.1",
            "timestamp": "2024-01-01T00:00:00"
        })
        assert r.status_code == 200
        data = r.json()
        assert data["status"]        == "benign"
        assert data["threats_found"] == 0

    def test_submit_threat_event(self, api_client, db_with_iocs):
        """Event with a known malicious source IP → threat detected."""
        r = api_client.post("/event", json={
            "event_id":      "api-test-002",
            "source_ip":     "185.220.101.45",
            "destination_ip":"192.168.1.10",
            "timestamp":     "2024-01-01T00:00:00"
        })
        assert r.status_code == 200
        data = r.json()
        assert data["status"]        == "threat_detected"
        assert data["threats_found"] >= 1
        assert data["top_severity"]  in ["Critical","High","Medium","Low"]
        assert data["top_risk_score"] > 0

    def test_event_has_report_path(self, api_client, db_with_iocs):
        """Event response should always include a report path."""
        r = api_client.post("/event", json={
            "event_id": "api-test-003",
            "source_ip": "8.8.8.8",
            "destination_ip": "1.1.1.1"
        })
        assert "report" in r.json()

    def test_event_missing_required_fields(self, api_client):
        """Missing source_ip → 422 validation error."""
        r = api_client.post("/event", json={"event_id": "bad-event"})
        assert r.status_code == 422

    def test_event_auto_timestamp(self, api_client, db_with_iocs):
        """Omitting timestamp should not cause an error."""
        r = api_client.post("/event", json={
            "event_id": "api-test-004",
            "source_ip": "8.8.8.8",
            "destination_ip": "1.1.1.1"
        })
        assert r.status_code == 200


@pytest.mark.api
class TestCorrelationEndpoints:
    def test_list_correlations_empty(self, api_client):
        r = api_client.get("/correlations")
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_list_correlations_after_event(self, api_client, db_with_iocs):
        # Submit a threat event first
        api_client.post("/event", json={
            "event_id": "corr-test-001",
            "source_ip": "185.220.101.45",
            "destination_ip": "1.1.1.1"
        })
        r = api_client.get("/correlations")
        assert r.status_code == 200
        assert r.json()["total"] >= 1

    def test_filter_correlations_by_event(self, api_client, db_with_iocs):
        api_client.post("/event", json={
            "event_id": "corr-filter-test",
            "source_ip": "185.220.101.45",
            "destination_ip": "1.1.1.1"
        })
        r = api_client.get("/correlations?event_id=corr-filter-test")
        assert r.status_code == 200
        for c in r.json()["results"]:
            assert c["event_id"] == "corr-filter-test"


@pytest.mark.api
class TestIngestionEndpoints:
    def test_list_servers(self, api_client):
        r = api_client.get("/ingest/servers")
        assert r.status_code == 200
        data = r.json()
        assert "servers" in data
        assert len(data["servers"]) > 0

    def test_file_ingest_missing_file(self, api_client, temp_db):
        r = api_client.post("/ingest/file", json={
            "file_path": "/nonexistent/file.json",
            "file_type": "json"
        })
        assert r.status_code == 404

    def test_file_ingest_invalid_type(self, api_client, temp_db, tmp_path):
        path = str(tmp_path / "test.csv")
        open(path, "w").write("a,b,c")
        r = api_client.post("/ingest/file", json={
            "file_path": path,
            "file_type": "csv"
        })
        assert r.status_code == 400

    def test_file_ingest_json(self, api_client, temp_db, tmp_path):
        import json as j
        path = str(tmp_path / "bundle.json")
        with open(path, "w") as f:
            j.dump({"type":"bundle","objects":[{
                "type":"indicator","id":"indicator--test",
                "pattern":"[ipv4-addr:value = '5.5.5.5']",
                "confidence":80
            }]}, f)
        r = api_client.post("/ingest/file", json={
            "file_path": path,
            "file_type": "json"
        })
        assert r.status_code == 200
        data = r.json()
        assert data["stored"] == 1

    def test_trigger_ingestion(self, api_client):
        """Trigger endpoint should accept and return 200."""
        r = api_client.post("/ingest/trigger")
        assert r.status_code == 200
        assert r.json()["status"] == "accepted"


@pytest.mark.api
class TestSchedulerEndpoint:
    def test_scheduler_status(self, api_client):
        r = api_client.get("/scheduler/status")
        assert r.status_code == 200
        data = r.json()
        assert "is_running" in data or "scheduler_running" in data
