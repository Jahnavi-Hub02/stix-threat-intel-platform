"""
tests/test_ingestion.py
========================
Tests for Module 1: IOC Pipeline
Covers: STIX parser, feed config, multi-feed ingester, deduplication.
Uses monkeypatching — no real network calls made in tests.
"""
import pytest, json, os

# ── Test events and fixtures ───────────────────────────────────────────────

SAMPLE_BUNDLE = {
    "type": "bundle", "id": "bundle--test",
    "objects": [
        {"type": "indicator", "id": "indicator--001",
         "pattern": "[ipv4-addr:value = '185.220.101.45']",
         "confidence": 85, "labels": ["malware","c2"],
         "valid_from": "2026-01-01T00:00:00Z",
         "valid_until": "2026-12-31T00:00:00Z"},
        {"type": "indicator", "id": "indicator--002",
         "pattern": "[domain-name:value = 'evil-domain.com']",
         "confidence": 70, "labels": ["phishing"],
         "valid_from": "2026-01-01T00:00:00Z"},
        {"type": "indicator", "id": "indicator--003",
         "pattern": "[url:value = 'http://malware.site/payload']",
         "confidence": 60, "labels": [],
         "valid_from": "2026-01-01T00:00:00Z"},
        {"type": "indicator", "id": "indicator--004",
         "pattern": "[file:hashes.'SHA-256' = 'abc123def456']",
         "confidence": 90, "labels": ["ransomware"],
         "valid_from": "2026-01-01T00:00:00Z"},
        # Non-indicator — should be ignored
        {"type": "malware", "id": "malware--001", "name": "BadBot"},
    ]
}

MALFORMED_BUNDLE = {
    "type": "bundle",
    "objects": [
        {"type": "indicator", "id": "indicator--bad",
         "pattern": "[INVALID PATTERN]", "confidence": 50,
         "valid_from": "2026-01-01T00:00:00Z"},
    ]
}


# ══════════════════════════════════════════════════════════════════════════════
# STIX Parser Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSTIXParser:

    def test_parse_bundle_returns_list(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle(SAMPLE_BUNDLE)
        assert isinstance(result, list)

    def test_only_indicators_extracted(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle(SAMPLE_BUNDLE)
        # SAMPLE_BUNDLE has 4 valid indicators + 1 malware (ignored)
        assert len(result) == 4

    def test_ipv4_parsed_correctly(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle(SAMPLE_BUNDLE)
        ips = [r for r in result if r["ioc_type"] == "ipv4-addr"]
        assert len(ips) == 1
        assert ips[0]["ioc_value"] == "185.220.101.45"

    def test_domain_parsed_correctly(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle(SAMPLE_BUNDLE)
        domains = [r for r in result if r["ioc_type"] == "domain-name"]
        assert len(domains) == 1
        assert domains[0]["ioc_value"] == "evil-domain.com"

    def test_url_parsed_correctly(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle(SAMPLE_BUNDLE)
        urls = [r for r in result if r["ioc_type"] == "url"]
        assert len(urls) == 1
        assert "malware.site" in urls[0]["ioc_value"]

    def test_file_hash_parsed_correctly(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle(SAMPLE_BUNDLE)
        hashes = [r for r in result if r["ioc_type"] == "file-hash"]
        assert len(hashes) == 1
        assert hashes[0]["ioc_value"] == "abc123def456"

    def test_confidence_captured(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle(SAMPLE_BUNDLE)
        ip_ioc = next(r for r in result if r["ioc_type"] == "ipv4-addr")
        assert ip_ioc["confidence"] == 85

    def test_severity_derived_from_confidence(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle(SAMPLE_BUNDLE)
        # confidence=85 → "high"
        ip_ioc = next(r for r in result if r["ioc_type"] == "ipv4-addr")
        assert ip_ioc["severity"] == "high"
        # confidence=90 → "critical"
        hash_ioc = next(r for r in result if r["ioc_type"] == "file-hash")
        assert hash_ioc["severity"] == "critical"

    def test_labels_captured_as_tags(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle(SAMPLE_BUNDLE)
        ip_ioc = next(r for r in result if r["ioc_type"] == "ipv4-addr")
        assert "malware" in ip_ioc["tags"]
        assert "c2" in ip_ioc["tags"]

    def test_malformed_pattern_skipped(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle(MALFORMED_BUNDLE)
        assert len(result) == 0

    def test_empty_bundle_returns_empty_list(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle({"type": "bundle", "objects": []})
        assert result == []

    def test_missing_objects_key(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle({"type": "bundle"})
        assert result == []

    def test_stix_id_captured(self):
        from app.normalization.stix_parser import parse_stix_bundle
        result = parse_stix_bundle(SAMPLE_BUNDLE)
        ip_ioc = next(r for r in result if r["ioc_type"] == "ipv4-addr")
        assert ip_ioc["stix_id"] == "indicator--001"

    def test_severity_low_for_low_confidence(self):
        from app.normalization.stix_parser import parse_stix_bundle
        bundle = {"objects": [
            {"type":"indicator","id":"i-1","confidence":20,"labels":[],
             "pattern":"[ipv4-addr:value = '1.2.3.4']","valid_from":"2026-01-01T00:00:00Z"}
        ]}
        result = parse_stix_bundle(bundle)
        assert result[0]["severity"] == "low"

    def test_parse_file_json(self, tmp_path):
        from app.normalization.stix_parser import parse_stix_file_json
        import json
        p = tmp_path / "test.json"
        p.write_text(json.dumps(SAMPLE_BUNDLE))
        result = parse_stix_file_json(str(p))
        assert len(result) == 4


# ══════════════════════════════════════════════════════════════════════════════
# Feed Configuration Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestFeedConfiguration:

    def test_fallback_to_otx_when_no_feed_env(self, monkeypatch):
        """If no FEED_N_* vars, falls back to OTX via TAXII_SERVER_URL."""
        for k in ["FEED_1_NAME","FEED_2_NAME"]:
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("TAXII_SERVER_URL", "https://otx.alienvault.com/taxii/taxii2/")
        monkeypatch.setenv("OTX_API_KEY", "testkey123")
        from app.ingestion.taxii_client import get_configured_feeds
        feeds = get_configured_feeds()
        assert len(feeds) >= 1
        assert feeds[0]["name"] == "AlienVault OTX"
        assert feeds[0]["api_key"] == "testkey123"

    def test_multi_feed_loaded_from_env(self, monkeypatch):
        monkeypatch.setenv("FEED_1_NAME",    "Feed One")
        monkeypatch.setenv("FEED_1_URL",     "https://feed1.example.com/taxii/")
        monkeypatch.setenv("FEED_1_AUTH",    "none")
        monkeypatch.setenv("FEED_1_ENABLED", "true")
        monkeypatch.setenv("FEED_2_NAME",    "Feed Two")
        monkeypatch.setenv("FEED_2_URL",     "https://feed2.example.com/taxii/")
        monkeypatch.setenv("FEED_2_AUTH",    "api_key")
        monkeypatch.setenv("FEED_2_API_KEY", "secret456")
        monkeypatch.setenv("FEED_2_ENABLED", "true")
        # Import directly — no reload needed, get_configured_feeds reads env at call time
        from app.ingestion.taxii_client import get_configured_feeds
        feeds = get_configured_feeds()
        names = [f["name"] for f in feeds]
        assert "Feed One" in names
        assert "Feed Two" in names

    def test_disabled_feed_excluded(self, monkeypatch):
        monkeypatch.setenv("FEED_1_NAME",    "Disabled Feed")
        monkeypatch.setenv("FEED_1_URL",     "https://disabled.example.com/taxii/")
        monkeypatch.setenv("FEED_1_AUTH",    "none")
        monkeypatch.setenv("FEED_1_ENABLED", "false")
        # Clear other feed vars so only FEED_1 is considered
        for k in ["FEED_2_NAME", "FEED_3_NAME"]:
            monkeypatch.delenv(k, raising=False)
        from app.ingestion.taxii_client import get_configured_feeds
        feeds = get_configured_feeds()
        names = [f["name"] for f in feeds]
        assert "Disabled Feed" not in names

    def test_api_key_auth_sets_header(self, monkeypatch):
        monkeypatch.setenv("FEED_1_NAME",    "OTX Test")
        monkeypatch.setenv("FEED_1_URL",     "https://otx.alienvault.com/taxii/taxii2/")
        monkeypatch.setenv("FEED_1_AUTH",    "api_key")
        monkeypatch.setenv("FEED_1_API_KEY", "mykey999")
        monkeypatch.setenv("FEED_1_ENABLED", "true")
        from app.ingestion.taxii_client import TAXIIFeedClient
        client  = TAXIIFeedClient({"name":"OTX","url":"https://otx.alienvault.com/","auth_type":"api_key","api_key":"mykey999","username":"","password":""})
        session = client._session()
        assert session.headers.get("X-OTX-API-KEY") == "mykey999"

    def test_basic_auth_sets_session_auth(self):
        from app.ingestion.taxii_client import TAXIIFeedClient
        client  = TAXIIFeedClient({"name":"Test","url":"https://test.com/","auth_type":"basic","api_key":"","username":"user","password":"pass"})
        session = client._session()
        assert session.auth == ("user", "pass")

    def test_no_auth_no_key_header(self):
        from app.ingestion.taxii_client import TAXIIFeedClient
        client  = TAXIIFeedClient({"name":"Test","url":"https://test.com/","auth_type":"none","api_key":"","username":"","password":""})
        session = client._session()
        assert "X-OTX-API-KEY" not in session.headers


# ══════════════════════════════════════════════════════════════════════════════
# Multi-Feed Ingester Tests (mocked network)
# ══════════════════════════════════════════════════════════════════════════════

class TestMultiFeedIngester:

    @pytest.fixture(autouse=True)
    def patch_db(self, temp_db, monkeypatch):
        """Use the test DB from conftest."""
        pass

    def test_ingester_initialises_with_feeds(self, monkeypatch):
        monkeypatch.setenv("FEED_1_NAME",    "Mock Feed")
        monkeypatch.setenv("FEED_1_URL",     "https://mock.example.com/taxii/")
        monkeypatch.setenv("FEED_1_AUTH",    "none")
        monkeypatch.setenv("FEED_1_ENABLED", "true")
        from app.ingestion.taxii_client import MultiFeedIngester
        ingester = MultiFeedIngester()
        assert len(ingester.feeds) >= 1

    def test_ingest_all_calls_each_feed(self, monkeypatch):
        """Mock fetch_all so no real HTTP calls are made."""
        from app.ingestion.taxii_client import MultiFeedIngester, TAXIIFeedClient

        calls = []
        def mock_fetch(self_inner, added_after=None, max_per=2000):
            calls.append(self_inner.name)
            return [{"type":"indicator","id":f"i-{self_inner.name}",
                     "pattern":"[ipv4-addr:value = '1.2.3.4']",
                     "confidence":70,"labels":[],"valid_from":"2026-01-01T00:00:00Z"}]

        monkeypatch.setattr(TAXIIFeedClient, "fetch_all", mock_fetch)
        ingester = MultiFeedIngester()
        result   = ingester.ingest_all(delta_hours=0)
        assert result["total_fetched"] >= 1

    def test_deduplication_on_repeat_ingest(self, monkeypatch):
        """Same IOC value inserted twice — DB unique constraint should prevent duplicate."""
        from app.ingestion.taxii_client import MultiFeedIngester, TAXIIFeedClient

        def mock_fetch(self_inner, **kw):
            return [{"type":"indicator","id":"i-dup",
                     "pattern":"[ipv4-addr:value = '10.20.30.40']",
                     "confidence":80,"labels":[],"valid_from":"2026-01-01T00:00:00Z"}]

        monkeypatch.setattr(TAXIIFeedClient, "fetch_all", mock_fetch)
        ingester = MultiFeedIngester()
        r1 = ingester.ingest_all(delta_hours=0)
        r2 = ingester.ingest_all(delta_hours=0)
        # Second run should store 0 (all duplicates)
        assert r2["total_stored"] == 0
        # Ensure deduplication is observed by no new IOCs stored on repeat ingest
        assert r2["total_stored"] == 0, (
            f"Expected 0 new IOCs on repeat ingest, got {r2['total_stored']}"
        )

    def test_feed_error_does_not_crash_other_feeds(self, monkeypatch):
        """If one feed throws an exception, others still run."""
        from app.ingestion.taxii_client import MultiFeedIngester, TAXIIFeedClient

        call_count = {"n": 0}
        def mock_fetch(self_inner, **kw):
            call_count["n"] += 1
            if "Bad" in self_inner.name:
                raise ConnectionError("Server down")
            return []

        monkeypatch.setattr(TAXIIFeedClient, "fetch_all", mock_fetch)
        ingester       = MultiFeedIngester()
        # Inject a bad feed
        ingester.feeds = [
            {"name":"Good Feed","url":"https://good.com/","auth_type":"none","api_key":"","username":"","password":""},
            {"name":"Bad Feed", "url":"https://bad.com/", "auth_type":"none","api_key":"","username":"","password":""},
        ]
        result = ingester.ingest_all(delta_hours=0)
        assert "Bad Feed" in result["feeds"]
        assert result["feeds"]["Bad Feed"]["status"] == "error"
        assert "Good Feed" in result["feeds"]