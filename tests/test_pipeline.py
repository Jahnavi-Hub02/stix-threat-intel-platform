"""
Integration tests — Report Generator + End-to-End Pipeline
"""
import os
import pytest


@pytest.mark.integration
class TestReportGenerator:
    def test_generates_pdf_file(self, tmp_path):
        from app.utils.report_generator import generate_report
        event = {"event_id":"rpt-001","source_ip":"1.2.3.4",
                 "destination_ip":"5.6.7.8","timestamp":"2024-01-01T00:00:00",
                 "source_port":None,"destination_port":443,"protocol":"TCP"}
        results = [{
            "matched_ip":"1.2.3.4","match_type":"source_ip",
            "decision":"Potential Incoming Attack",
            "risk_score":72.5,"severity":"High",
            "mitre_tactic":"Initial Access",
            "mitre_technique":"T1190","confidence":80,"ioc_type":"ipv4"
        }]
        path = generate_report(event, results, output_dir=str(tmp_path))
        assert os.path.exists(path)
        assert path.endswith(".pdf")
        assert os.path.getsize(path) > 1000  # meaningful file

    def test_benign_report(self, tmp_path):
        from app.utils.report_generator import generate_report
        event = {"event_id":"rpt-002","source_ip":"8.8.8.8",
                 "destination_ip":"1.1.1.1","timestamp":"2024-01-01T00:00:00",
                 "source_port":None,"destination_port":None,"protocol":None}
        path = generate_report(event, [], output_dir=str(tmp_path))
        assert os.path.exists(path)

    def test_report_filename_contains_event_id(self, tmp_path):
        from app.utils.report_generator import generate_report
        event = {"event_id":"special-evt-123","source_ip":"1.2.3.4",
                 "destination_ip":"5.6.7.8","timestamp":"2024-01-01"}
        path = generate_report(event, [], output_dir=str(tmp_path))
        assert "special-evt-123" in path

    def test_critical_severity_report(self, tmp_path):
        from app.utils.report_generator import generate_report
        event = {"event_id":"rpt-003","source_ip":"1.2.3.4",
                 "destination_ip":"5.6.7.8","timestamp":"2024-01-01",
                 "source_port":None,"destination_port":None,"protocol":None}
        results = [
            {"matched_ip":"1.2.3.4","match_type":"source_ip",
             "decision":"Active Malicious Communication",
             "risk_score":95.0,"severity":"Critical",
             "mitre_tactic":"Lateral Movement","mitre_technique":"T1021",
             "confidence":95,"ioc_type":"ipv4"},
        ]
        path = generate_report(event, results, output_dir=str(tmp_path))
        assert os.path.exists(path)
        assert os.path.getsize(path) > 2000


@pytest.mark.integration
class TestEndToEndPipeline:
    """
    Full pipeline test: parse feeds → store IOCs → correlate event → generate report.
    Mirrors exactly what run.py does.
    """

    def test_full_pipeline_with_json_feed(self, temp_db, tmp_path):
        import json
        from app.normalization.parser_json import parse_stix_json
        from app.database.db_manager import insert_indicators, get_db_stats
        from app.correlation.engine import correlate_event
        from app.utils.report_generator import generate_report

        # 1. Create a STIX bundle
        bundle_path = str(tmp_path / "feed.json")
        with open(bundle_path, "w") as f:
            json.dump({"type":"bundle","objects":[
                {"type":"indicator","id":"indicator--e2e-1",
                 "pattern":"[ipv4-addr:value = '200.100.50.25']","confidence":85},
                {"type":"indicator","id":"indicator--e2e-2",
                 "pattern":"[domain-name:value = 'phishing.example.com']","confidence":70},
            ]}, f)

        # 2. Parse
        indicators = parse_stix_json(bundle_path)
        assert len(indicators) == 2

        # 3. Store
        result = insert_indicators(indicators, source_label="e2e-test")
        assert result["stored"] == 2

        # 4. Correlate — known malicious source
        event = {"event_id":"e2e-001","source_ip":"200.100.50.25",
                 "destination_ip":"192.168.1.1","timestamp":"2024-01-01"}
        matches = correlate_event(event)
        assert len(matches) == 1
        assert matches[0]["ioc_type"] == "ipv4"
        assert matches[0]["risk_score"] > 0
        assert matches[0]["severity"]  in ["Critical","High","Medium","Low"]

        # 5. Stats updated
        stats = get_db_stats()
        assert stats["total_iocs"]         >= 2
        assert stats["total_events"]       >= 1
        assert stats["total_correlations"] >= 1

        # 6. Generate report
        path = generate_report(event, matches, output_dir=str(tmp_path))
        assert os.path.exists(path)

    def test_duplicate_iocs_not_double_stored(self, temp_db):
        from app.normalization.parser_json import parse_stix_json
        from app.database.db_manager import insert_indicators, get_db_stats
        import json, tempfile, os

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"type":"bundle","objects":[{
                "type":"indicator","id":"indicator--dup",
                "pattern":"[ipv4-addr:value = '77.77.77.77']","confidence":80
            }]}, f)
            path = f.name

        try:
            inds = parse_stix_json(path)
            r1 = insert_indicators(inds)
            r2 = insert_indicators(inds)  # same feed again
            assert r1["stored"]     == 1
            assert r2["stored"]     == 0
            assert r2["duplicates"] == 1
            assert get_db_stats()["total_iocs"] == 1
        finally:
            os.unlink(path)

    def test_private_ips_never_matched(self, db_with_iocs):
        from app.correlation.engine import correlate_event
        private_events = [
            {"event_id":"prv-1","source_ip":"192.168.1.1","destination_ip":"10.0.0.1","timestamp":"2024-01-01"},
            {"event_id":"prv-2","source_ip":"172.16.0.1", "destination_ip":"127.0.0.1","timestamp":"2024-01-01"},
        ]
        for event in private_events:
            assert correlate_event(event) == [], f"Private IP matched: {event}"

    def test_risk_score_range(self, db_with_iocs):
        """Risk scores must always be between 0 and 100."""
        from app.correlation.engine import correlate_event
        event = {"event_id":"risk-test","source_ip":"185.220.101.45",
                 "destination_ip":"91.108.4.1","timestamp":"2024-01-01"}
        results = correlate_event(event)
        for r in results:
            assert 0 <= r["risk_score"] <= 100, f"Score out of range: {r['risk_score']}"
