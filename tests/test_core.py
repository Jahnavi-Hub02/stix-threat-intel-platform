"""
Unit tests — Parsers and Correlation Engine
"""
import json
import pytest
import os
import tempfile


# ─────────────────────────────────────────────────────────────
# Parser JSON tests
# ─────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestParserJSON:
    def _write_bundle(self, tmp_path, objects):
        """Helper: write a STIX bundle JSON and return path."""
        path = str(tmp_path / "bundle.json")
        with open(path, "w") as f:
            json.dump({"type":"bundle","objects":objects}, f)
        return path

    def test_extracts_ipv4(self, tmp_path):
        from app.normalization.parser_json import parse_stix_json
        path = self._write_bundle(tmp_path, [{
            "type":"indicator","id":"indicator--1",
            "pattern":"[ipv4-addr:value = '185.220.101.45']",
            "confidence":90
        }])
        result = parse_stix_json(path)
        assert len(result) == 1
        assert result[0]["ioc_type"]  == "ipv4"
        assert result[0]["ioc_value"] == "185.220.101.45"
        assert result[0]["confidence"] == 90

    def test_extracts_domain(self, tmp_path):
        from app.normalization.parser_json import parse_stix_json
        path = self._write_bundle(tmp_path, [{
            "type":"indicator","id":"indicator--2",
            "pattern":"[domain-name:value = 'evil.example.com']","confidence":70
        }])
        result = parse_stix_json(path)
        assert result[0]["ioc_type"]  == "domain"
        assert result[0]["ioc_value"] == "evil.example.com"

    def test_extracts_sha256(self, tmp_path):
        from app.normalization.parser_json import parse_stix_json
        h = "a" * 64
        path = self._write_bundle(tmp_path, [{
            "type":"indicator","id":"indicator--3",
            "pattern":f"[file:hashes.'SHA-256' = '{h}']","confidence":95
        }])
        result = parse_stix_json(path)
        assert result[0]["ioc_type"]  == "sha256"
        assert result[0]["ioc_value"] == h

    def test_extracts_md5(self, tmp_path):
        from app.normalization.parser_json import parse_stix_json
        h = "b" * 32
        path = self._write_bundle(tmp_path, [{
            "type":"indicator","id":"indicator--4",
            "pattern":f"[file:hashes.MD5 = '{h}']","confidence":60
        }])
        result = parse_stix_json(path)
        assert result[0]["ioc_type"]  == "md5"

    def test_extracts_url(self, tmp_path):
        from app.normalization.parser_json import parse_stix_json
        path = self._write_bundle(tmp_path, [{
            "type":"indicator","id":"indicator--5",
            "pattern":"[url:value = 'http://malware.example.com/payload']",
            "confidence":80
        }])
        result = parse_stix_json(path)
        assert result[0]["ioc_type"] == "url"

    def test_skips_non_indicators(self, tmp_path):
        from app.normalization.parser_json import parse_stix_json
        path = self._write_bundle(tmp_path, [
            {"type":"malware","id":"malware--1","name":"BadSoftware"},
            {"type":"identity","id":"identity--1","name":"ACME Corp"},
            {"type":"indicator","id":"indicator--6",
             "pattern":"[ipv4-addr:value = '1.2.3.4']","confidence":50}
        ])
        result = parse_stix_json(path)
        assert len(result) == 1  # only the indicator

    def test_empty_bundle(self, tmp_path):
        from app.normalization.parser_json import parse_stix_json
        path = self._write_bundle(tmp_path, [])
        assert parse_stix_json(path) == []

    def test_missing_file(self, tmp_path):
        from app.normalization.parser_json import parse_stix_json
        result = parse_stix_json("/nonexistent/path/bundle.json")
        assert result == []

    def test_multiple_indicators(self, tmp_path):
        from app.normalization.parser_json import parse_stix_json
        objects = [
            {"type":"indicator","id":f"indicator--{i}",
             "pattern":f"[ipv4-addr:value = '10.0.0.{i}']","confidence":50}
            for i in range(1, 11)
        ]
        path = self._write_bundle(tmp_path, objects)
        result = parse_stix_json(path)
        assert len(result) == 10


# ─────────────────────────────────────────────────────────────
# Parser XML tests
# ─────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestParserXML:
    def _write_xml(self, tmp_path, content):
        path = str(tmp_path / "feed.xml")
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_extracts_ipv4(self, tmp_path):
        from app.normalization.parser_xml import parse_stix_xml
        xml = "<Indicator><Address_Value>5.6.7.8</Address_Value></Indicator>"
        path = self._write_xml(tmp_path, xml)
        result = parse_stix_xml(path)
        assert len(result) == 1
        assert result[0]["ioc_value"] == "5.6.7.8"
        assert result[0]["ioc_type"]  == "ipv4"

    def test_extracts_domain(self, tmp_path):
        from app.normalization.parser_xml import parse_stix_xml
        xml = "<Indicator><DomainName>malicious-domain.com</DomainName></Indicator>"
        path = self._write_xml(tmp_path, xml)
        result = parse_stix_xml(path)
        domains = [r for r in result if r["ioc_type"] == "domain"]
        assert any(r["ioc_value"] == "malicious-domain.com" for r in domains)

    def test_deduplicates_within_file(self, tmp_path):
        from app.normalization.parser_xml import parse_stix_xml
        xml = """
        <root>
          <Indicator><Address_Value>1.1.1.1</Address_Value></Indicator>
          <Indicator><Address_Value>1.1.1.1</Address_Value></Indicator>
        </root>"""
        path = self._write_xml(tmp_path, xml)
        result = parse_stix_xml(path)
        values = [r["ioc_value"] for r in result]
        assert values.count("1.1.1.1") == 1

    def test_empty_file(self, tmp_path):
        from app.normalization.parser_xml import parse_stix_xml
        path = self._write_xml(tmp_path, "<root></root>")
        assert parse_stix_xml(path) == []

    def test_missing_file(self):
        from app.normalization.parser_xml import parse_stix_xml
        assert parse_stix_xml("/nonexistent/file.xml") == []


# ─────────────────────────────────────────────────────────────
# IP Validator tests
# ─────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestIPValidator:
    def test_public_ips(self):
        from app.utils.ip_validator import is_public_ip
        assert is_public_ip("8.8.8.8")         is True
        assert is_public_ip("185.220.101.45")   is True
        assert is_public_ip("91.108.4.1")       is True

    def test_private_ips(self):
        from app.utils.ip_validator import is_public_ip
        assert is_public_ip("192.168.1.1")  is False
        assert is_public_ip("10.0.0.1")     is False
        assert is_public_ip("172.16.0.1")   is False

    def test_loopback(self):
        from app.utils.ip_validator import is_public_ip
        assert is_public_ip("127.0.0.1") is False

    def test_invalid(self):
        from app.utils.ip_validator import is_public_ip
        assert is_public_ip("not-an-ip")  is False
        assert is_public_ip("")           is False
        assert is_public_ip("999.0.0.1")  is False


# ─────────────────────────────────────────────────────────────
# Correlation Engine tests
# ─────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestCorrelationEngine:
    def test_source_ip_match(self, db_with_iocs, sample_event):
        from app.correlation.engine import correlate_event
        results = correlate_event(sample_event)
        assert len(results) >= 1
        match = results[0]
        assert match["matched_ip"] == "185.220.101.45"
        assert match["match_type"] == "source_ip"
        assert match["decision"]   == "Potential Incoming Attack"

    def test_risk_score_present(self, db_with_iocs, sample_event):
        from app.correlation.engine import correlate_event
        results = correlate_event(sample_event)
        assert len(results) > 0
        assert results[0]["risk_score"] > 0
        assert results[0]["risk_score"] <= 100

    def test_severity_present(self, db_with_iocs, sample_event):
        from app.correlation.engine import correlate_event
        results = correlate_event(sample_event)
        assert results[0]["severity"] in ["Critical","High","Medium","Low"]

    def test_mitre_tactic_present(self, db_with_iocs, sample_event):
        from app.correlation.engine import correlate_event
        results = correlate_event(sample_event)
        assert results[0]["mitre_tactic"] != ""
        assert results[0]["mitre_tactic"] is not None

    def test_private_ip_skipped(self, db_with_iocs):
        from app.correlation.engine import correlate_event
        event = {"event_id":"e2","source_ip":"192.168.1.1",
                 "destination_ip":"10.0.0.1","timestamp":"2024-01-01"}
        results = correlate_event(event)
        assert results == []

    def test_no_match_returns_empty(self, db_with_iocs):
        from app.correlation.engine import correlate_event
        event = {"event_id":"e3","source_ip":"8.8.8.8",
                 "destination_ip":"1.1.1.1","timestamp":"2024-01-01"}
        results = correlate_event(event)
        assert results == []

    def test_both_ips_matched(self, db_with_iocs):
        from app.correlation.engine import correlate_event
        # Both IPs are in db_with_iocs
        event = {"event_id":"e4","source_ip":"185.220.101.45",
                 "destination_ip":"91.108.4.1","timestamp":"2024-01-01"}
        results = correlate_event(event)
        assert all(r["match_type"] == "both" for r in results)
        assert all(r["decision"]   == "Active Malicious Communication" for r in results)

    def test_deduplication(self, db_with_iocs, sample_event):
        """Same event correlated twice should not double-insert."""
        from app.correlation.engine import correlate_event
        import sqlite3
        correlate_event(sample_event)
        correlate_event(sample_event)  # second time
        conn = sqlite3.connect(db_with_iocs)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM correlation_results WHERE event_id=?",
            (sample_event["event_id"],)
        )
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 1  # not 2

    def test_event_saved_to_db(self, db_with_iocs, sample_event):
        """Event should appear in event_logs after correlation."""
        from app.correlation.engine import correlate_event
        import sqlite3
        correlate_event(sample_event)
        conn = sqlite3.connect(db_with_iocs)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT event_id FROM event_logs WHERE event_id=?",
            (sample_event["event_id"],)
        )
        row = cursor.fetchone()
        conn.close()
        assert row is not None
