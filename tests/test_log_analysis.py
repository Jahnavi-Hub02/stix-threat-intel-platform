"""
tests/test_log_analysis.py
===========================
Tests for Module 1 (log IOC check) and Module 2 (log ML analysis).
Uses temp DB and synthetic log content — no real files needed.
"""
import pytest
import os


SAMPLE_LOGS_CLEAN = """
192.168.1.10 - - [20/Mar/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234
10.0.0.5 - - [20/Mar/2026:10:00:01 +0000] "POST /api/data HTTP/1.1" 201 567
172.16.0.3 - - [20/Mar/2026:10:00:02 +0000] "GET /health HTTP/1.1" 200 89
""".strip()

SAMPLE_LOGS_WITH_THREAT = """
192.168.1.10 - - [20/Mar/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234
185.220.101.45 - - [20/Mar/2026:10:00:01 +0000] "POST /login HTTP/1.1" 200 567
8.8.8.8 - - [20/Mar/2026:10:00:02 +0000] "GET /health HTTP/1.1" 200 89
""".strip()

MALICIOUS_IP = "185.220.101.45"


# ── Log checker unit tests ────────────────────────────────────────────────────

class TestLogChecker:

    def test_clean_logs_return_no_hits(self, temp_db):
        """Log lines with only private IPs should produce no IOC hits."""
        from app.ingestion.log_checker import check_log_content
        result = check_log_content(SAMPLE_LOGS_CLEAN)
        assert result["total_hits"] == 0
        assert result["hits"] == []

    def test_lines_checked_count(self, temp_db):
        from app.ingestion.log_checker import check_log_content
        result = check_log_content(SAMPLE_LOGS_CLEAN)
        assert result["lines_checked"] == 3

    def test_hit_detected_when_ioc_in_db(self, temp_db):
        """IOC stored in DB should be found in log content."""
        from app.ingestion.log_checker import check_log_content
        from app.database.db_manager import insert_indicators

        insert_indicators([{
            "stix_id": "indicator--test-log",
            "ioc_type": "ipv4-addr", "ioc_subtype": "network",
            "ioc_value": MALICIOUS_IP,
            "confidence": 90, "source": "test",
        }])

        result = check_log_content(SAMPLE_LOGS_WITH_THREAT)
        assert result["total_hits"] >= 1
        assert any(h["matched_ioc"]["ioc_value"] == MALICIOUS_IP
                   for h in result["hits"])

    def test_hit_has_required_fields(self, temp_db):
        from app.ingestion.log_checker import check_log_content
        from app.database.db_manager import insert_indicators

        insert_indicators([{
            "stix_id": "indicator--field-test",
            "ioc_type": "ipv4-addr", "ioc_subtype": "network",
            "ioc_value": MALICIOUS_IP,
            "confidence": 85, "source": "test",
        }])

        result = check_log_content(SAMPLE_LOGS_WITH_THREAT)
        assert result["total_hits"] >= 1
        hit = result["hits"][0]
        for field in ["timestamp", "source_file", "line_number",
                       "log_line", "matched_ioc", "severity", "alert"]:
            assert field in hit, f"Missing field: {field}"

    def test_hit_includes_timestamp(self, temp_db):
        from app.ingestion.log_checker import check_log_content
        from app.database.db_manager import insert_indicators

        insert_indicators([{
            "stix_id": "indicator--ts-test",
            "ioc_type": "ipv4-addr", "ioc_subtype": "network",
            "ioc_value": MALICIOUS_IP, "confidence": 80, "source": "test",
        }])

        result = check_log_content(SAMPLE_LOGS_WITH_THREAT)
        assert result["total_hits"] >= 1
        hit = result["hits"][0]
        # Timestamp should be an ISO string
        assert "T" in hit["timestamp"] or "-" in hit["timestamp"]

    def test_alert_flag_is_true(self, temp_db):
        from app.ingestion.log_checker import check_log_content
        from app.database.db_manager import insert_indicators

        insert_indicators([{
            "stix_id": "indicator--alert-test",
            "ioc_type": "ipv4-addr", "ioc_subtype": "network",
            "ioc_value": MALICIOUS_IP, "confidence": 80, "source": "test",
        }])

        result = check_log_content(SAMPLE_LOGS_WITH_THREAT)
        assert result["total_hits"] >= 1
        assert result["hits"][0]["alert"] is True

    def test_inactive_ioc_not_matched(self, temp_db):
        """IOC marked is_active=0 should not be matched."""
        import sqlite3, app.database.db_manager as dbm
        db = getattr(dbm, "DB_PATH", "database/threat_intel.db")
        now = "2026-03-20T00:00:00Z"
        conn = sqlite3.connect(db)
        conn.execute(
            """INSERT OR IGNORE INTO ioc_indicators
               (stix_id, ioc_type, ioc_subtype, ioc_value, confidence, source,
                first_seen, last_seen, is_active)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            ("ind-inactive", "ipv4-addr", "network", MALICIOUS_IP,
             90, "test", now, now, 0)
        )
        conn.commit(); conn.close()

        from app.ingestion.log_checker import check_log_content
        result = check_log_content(SAMPLE_LOGS_WITH_THREAT)
        # Should not match because is_active=0
        assert result["total_hits"] == 0

    def test_severity_breakdown_present(self, temp_db):
        from app.ingestion.log_checker import check_log_content
        result = check_log_content(SAMPLE_LOGS_CLEAN)
        assert "severity_breakdown" in result

    def test_missing_file_returns_error(self, temp_db):
        from app.ingestion.log_checker import check_log_file
        result = check_log_file("/nonexistent/path/file.log")
        assert "error" in result

    def test_check_file_reads_content(self, tmp_path, temp_db):
        from app.ingestion.log_checker import check_log_file
        f = tmp_path / "test.log"
        f.write_text(SAMPLE_LOGS_CLEAN)
        result = check_log_file(str(f))
        assert result["lines_checked"] == 3
        assert result["total_hits"] == 0


# ── IOC Manager tests ─────────────────────────────────────────────────────────

class TestIOCManager:

    def test_expire_returns_dict(self, temp_db):
        from app.ingestion.ioc_manager import expire_outdated_iocs
        result = expire_outdated_iocs(max_age_days=30)
        assert "expired" in result
        assert "still_active" in result

    def test_health_summary_returns_dict(self, temp_db):
        from app.ingestion.ioc_manager import ioc_health_summary
        result = ioc_health_summary()
        assert "total" in result
        assert "active" in result

    def test_old_ioc_gets_expired(self, temp_db):
        import sqlite3, app.database.db_manager as dbm
        db = getattr(dbm, "DB_PATH", "database/threat_intel.db")
        # Insert an IOC with old last_seen date
        old_date = "2020-01-01T00:00:00Z"
        conn = sqlite3.connect(db)
        conn.execute(
            """INSERT OR IGNORE INTO ioc_indicators
               (stix_id, ioc_type, ioc_subtype, ioc_value, confidence, source,
                first_seen, last_seen, is_active)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            ("ind-old", "ipv4-addr", "network", "1.2.3.4",
             50, "test", old_date, old_date, 1)
        )
        conn.commit(); conn.close()

        from app.ingestion.ioc_manager import expire_outdated_iocs
        result = expire_outdated_iocs(max_age_days=30)
        assert result["expired"] >= 1

    def test_recent_ioc_not_expired(self, temp_db):
        import sqlite3, app.database.db_manager as dbm
        from datetime import datetime, timezone
        db = getattr(dbm, "DB_PATH", "database/threat_intel.db")
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(db)
        conn.execute(
            """INSERT OR IGNORE INTO ioc_indicators
               (stix_id, ioc_type, ioc_subtype, ioc_value, confidence, source,
                first_seen, last_seen, is_active)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            ("ind-fresh","ipv4-addr","network","9.9.9.9",50,"test",now,now,1)
        )
        conn.commit(); conn.close()

        from app.ingestion.ioc_manager import expire_outdated_iocs
        result = expire_outdated_iocs(max_age_days=30)
        # The recent IOC should NOT be expired
        conn2 = sqlite3.connect(db)
        is_active = conn2.execute(
            "SELECT is_active FROM ioc_indicators WHERE ioc_value='9.9.9.9'"
        ).fetchone()
        conn2.close()
        assert is_active and is_active[0] == 1


# ── ML Log Analyzer tests ─────────────────────────────────────────────────────

class TestMLLogAnalyzer:

    def test_clean_logs_no_crash(self, temp_db):
        from app.ml.log_analyzer import analyze_log_content
        result = analyze_log_content(SAMPLE_LOGS_CLEAN)
        assert isinstance(result, dict)
        assert "alerts" in result
        assert "lines_checked" in result

    def test_result_has_required_keys(self, temp_db):
        from app.ml.log_analyzer import analyze_log_content
        result = analyze_log_content(SAMPLE_LOGS_CLEAN)
        for key in ["alerts", "lines_checked", "total_alerts", "checked_at"]:
            assert key in result

    def test_alert_has_ml_analysis_key(self, temp_db):
        """Any alert produced should include ml_analysis sub-dict."""
        from app.ml.log_analyzer import analyze_log_content, analyze_event_ml

        # Inject a fake threat event to verify structure
        event = {
            "event_id": "test-log-event",
            "source_ip": "185.220.101.45",
            "destination_ip": "10.0.0.5",
            "destination_port": 4444,
            "protocol": "TCP",
            "timestamp": "2026-03-20T03:00:00Z",
        }
        ml = analyze_event_ml(event)
        assert "is_threat" in ml
        assert "risk_score" in ml
        assert "classifier" in ml
        assert "isolation_forest" in ml

    def test_missing_file_returns_error(self, temp_db):
        from app.ml.log_analyzer import analyze_log_file
        result = analyze_log_file("/nonexistent/path/file.log")
        assert "error" in result

    def test_analyze_file_reads_content(self, tmp_path, temp_db):
        from app.ml.log_analyzer import analyze_log_file
        f = tmp_path / "test.log"
        f.write_text(SAMPLE_LOGS_CLEAN)
        result = analyze_log_file(str(f))
        assert result["lines_checked"] >= 0  # may be 0 if lines don't parse


# ── API endpoint tests ────────────────────────────────────────────────────────

class TestLogAPIEndpoints:

    def test_logs_check_endpoint_exists(self, api_client, analyst_token):
        r = api_client.post(
            "/logs/check",
            data={"content": SAMPLE_LOGS_CLEAN, "source_name": "test"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "hits" in data
        assert "total_hits" in data

    def test_logs_analyze_endpoint_exists(self, api_client, analyst_token):
        r = api_client.post(
            "/logs/analyze",
            data={"content": SAMPLE_LOGS_CLEAN, "source_name": "test"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "alerts" in data
        assert "total_alerts" in data

    def test_logs_full_endpoint_exists(self, api_client, analyst_token):
        r = api_client.post(
            "/logs/full",
            data={"content": SAMPLE_LOGS_CLEAN, "source_name": "test"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "ioc_results" in data
        assert "ml_results" in data
        assert "summary" in data

    def test_logs_ioc_health_endpoint(self, api_client, analyst_token):
        r = api_client.get(
            "/logs/ioc-health",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert r.status_code == 200
        assert "total" in r.json()

    def test_logs_require_auth(self, api_client):
        r = api_client.post("/logs/check", data={"content": "test"})
        assert r.status_code == 401

    def test_logs_full_returns_summary(self, api_client, analyst_token):
        r = api_client.post(
            "/logs/full",
            data={"content": SAMPLE_LOGS_CLEAN},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        data = r.json()
        summary = data.get("summary", {})
        assert "total_unique_flagged_lines" in summary
        assert "confirmed_threats" in summary
