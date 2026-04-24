"""
Unit tests — Database layer (db_manager.py)
Tests: create_tables, insert_indicators, get_all_iocs,
       get_correlation_results, get_db_stats, save_event
"""
import pytest


@pytest.mark.unit
class TestCreateTables:
    def test_tables_created(self, temp_db):
        """All 4 required tables should exist after create_tables()."""
        import sqlite3
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        assert "ioc_indicators"     in tables
        assert "event_logs"         in tables
        assert "correlation_results" in tables
        assert "ingestion_logs"     in tables

    def test_ioc_indicators_columns(self, temp_db):
        """ioc_indicators must have all upgraded columns."""
        import sqlite3
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(ioc_indicators)")
        cols = {row[1] for row in cursor.fetchall()}
        conn.close()

        required = {"id","stix_id","ioc_type","ioc_subtype","ioc_value",
                    "confidence","source","is_active","first_seen","last_seen","created_at"}
        assert required.issubset(cols), f"Missing columns: {required - cols}"

    def test_idempotent(self, temp_db):
        """Calling create_tables twice should not raise errors."""
        from app.database.db_manager import create_tables
        create_tables()  # second call
        create_tables()  # third call — still fine


@pytest.mark.unit
class TestInsertIndicators:
    def test_basic_insert(self, temp_db):
        from app.database.db_manager import insert_indicators, get_all_iocs
        iocs = [{"stix_id":"s1","ioc_type":"ipv4","ioc_subtype":"network",
                 "ioc_value":"1.2.3.4","confidence":80,"source":"Test"}]
        result = insert_indicators(iocs)
        assert result["stored"] == 1
        assert result["duplicates"] == 0
        assert len(get_all_iocs()) == 1

    def test_deduplication(self, temp_db):
        """Inserting the same IOC twice should count as duplicate."""
        from app.database.db_manager import insert_indicators
        ioc = [{"stix_id":"s1","ioc_type":"ipv4","ioc_subtype":"network",
                "ioc_value":"1.2.3.4","confidence":80,"source":"Test"}]
        r1 = insert_indicators(ioc)
        r2 = insert_indicators(ioc)
        assert r1["stored"] == 1
        assert r2["stored"] == 0
        assert r2["duplicates"] == 1

    def test_missing_stix_id_allows_multiple_iocs(self, temp_db):
        """Indicators without stix_id should still insert if ioc_value differs."""
        from app.database.db_manager import insert_indicators, get_all_iocs
        iocs = [
            {"ioc_type":"ipv4","ioc_subtype":"network",
             "ioc_value":"1.2.3.4","confidence":80,"source":"Test"},
            {"ioc_type":"domain","ioc_subtype":"network",
             "ioc_value":"example.com","confidence":70,"source":"Test"},
        ]
        result = insert_indicators(iocs)
        assert result["stored"] == 2
        assert result["duplicates"] == 0
        stored = get_all_iocs()
        assert len(stored) == 2
        assert all(i["stix_id"] is None for i in stored)

    def test_duplicate_stix_id_is_detected(self, temp_db):
        """The same stix_id with a different ioc_value should be treated as duplicate."""
        from app.database.db_manager import insert_indicators
        first = [{"stix_id":"s1","ioc_type":"ipv4","ioc_subtype":"network",
                  "ioc_value":"1.2.3.4","confidence":80,"source":"Test"}]
        second = [{"stix_id":"s1","ioc_type":"ipv4","ioc_subtype":"network",
                   "ioc_value":"1.2.3.5","confidence":80,"source":"Test"}]
        insert_indicators(first)
        result = insert_indicators(second)
        assert result["stored"] == 0
        assert result["duplicates"] == 1

    def test_multiple_types(self, temp_db):
        """Should correctly store all IOC types."""
        from app.database.db_manager import insert_indicators, get_all_iocs
        iocs = [
            {"stix_id":"i1","ioc_type":"ipv4",  "ioc_subtype":"network",
             "ioc_value":"5.6.7.8",     "confidence":90,"source":"T"},
            {"stix_id":"i2","ioc_type":"domain","ioc_subtype":"network",
             "ioc_value":"bad.com",     "confidence":70,"source":"T"},
            {"stix_id":"i3","ioc_type":"sha256","ioc_subtype":"file_hash",
             "ioc_value":"a"*64,        "confidence":95,"source":"T"},
            {"stix_id":"i4","ioc_type":"md5",   "ioc_subtype":"file_hash",
             "ioc_value":"b"*32,        "confidence":60,"source":"T"},
            {"stix_id":"i5","ioc_type":"url",   "ioc_subtype":"network",
             "ioc_value":"http://evil.com/path","confidence":85,"source":"T"},
        ]
        result = insert_indicators(iocs)
        assert result["stored"] == 5
        stored = get_all_iocs()
        types = {i["ioc_type"] for i in stored}
        assert types == {"ipv4","domain","sha256","md5","url"}

    def test_returns_dict(self, temp_db):
        """insert_indicators must always return a dict, never None."""
        from app.database.db_manager import insert_indicators
        result = insert_indicators([])
        assert isinstance(result, dict)
        assert "stored"     in result
        assert "duplicates" in result

    def test_ingestion_log_created(self, temp_db):
        """Each call to insert_indicators should write an ingestion_logs row."""
        import sqlite3
        from app.database.db_manager import insert_indicators
        insert_indicators(
            [{"stix_id":"x","ioc_type":"ipv4","ioc_subtype":"network",
              "ioc_value":"9.9.9.9","confidence":50,"source":"T"}],
            source_label="test-source"
        )
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ingestion_logs WHERE source='test-source'")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 1


@pytest.mark.unit
class TestGetAllIOCs:
    def test_returns_list_of_dicts(self, db_with_iocs):
        from app.database.db_manager import get_all_iocs
        iocs = get_all_iocs()
        assert isinstance(iocs, list)
        assert len(iocs) > 0
        assert isinstance(iocs[0], dict)

    def test_filter_by_type(self, db_with_iocs):
        from app.database.db_manager import get_all_iocs
        ipv4s = get_all_iocs(ioc_type="ipv4")
        assert all(i["ioc_type"] == "ipv4" for i in ipv4s)
        domains = get_all_iocs(ioc_type="domain")
        assert all(i["ioc_type"] == "domain" for i in domains)

    def test_pagination(self, db_with_iocs):
        from app.database.db_manager import get_all_iocs
        page1 = get_all_iocs(limit=2, offset=0)
        page2 = get_all_iocs(limit=2, offset=2)
        assert len(page1) == 2
        # Values should be different
        ids1 = {i["id"] for i in page1}
        ids2 = {i["id"] for i in page2}
        assert ids1.isdisjoint(ids2)


@pytest.mark.unit
class TestSaveEvent:
    def test_save_new_event(self, temp_db):
        from app.database.db_manager import save_event
        event = {"event_id":"e1","source_ip":"1.2.3.4","destination_ip":"5.6.7.8",
                 "source_port":1234,"destination_port":443,"protocol":"TCP",
                 "timestamp":"2024-01-01T00:00:00"}
        result = save_event(event)
        assert result is True

    def test_duplicate_event_not_saved(self, temp_db):
        from app.database.db_manager import save_event
        event = {"event_id":"e1","source_ip":"1.2.3.4","destination_ip":"5.6.7.8",
                 "timestamp":"2024-01-01T00:00:00"}
        save_event(event)
        result = save_event(event)  # second time
        assert result is False


@pytest.mark.unit
class TestGetDbStats:
    def test_stats_structure(self, db_with_iocs):
        from app.database.db_manager import get_db_stats
        stats = get_db_stats()
        assert "total_iocs"         in stats
        assert "total_events"       in stats
        assert "total_correlations" in stats
        assert "severity_breakdown" in stats
        assert "top_threats"        in stats

    def test_ioc_count_matches(self, db_with_iocs):
        from app.database.db_manager import get_db_stats, get_all_iocs
        stats  = get_db_stats()
        actual = len(get_all_iocs(limit=1000))
        assert stats["total_iocs"] == actual
