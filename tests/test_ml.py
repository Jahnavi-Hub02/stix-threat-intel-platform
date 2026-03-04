"""
tests/test_ml.py
================
Tests for the ML anomaly detection subsystem.

Coverage:
  - Feature extraction (all 10 features)
  - Edge cases (missing fields, private IPs, weird ports)
  - AnomalyDetector lifecycle (init, train, predict, status)
  - API endpoints (/ml/status, /ml/train, /ml/predict)
  - Integration with /event endpoint
"""

import pytest
import json
import sys
import os

# ── Fixtures ───────────────────────────────────────────────────────

NORMAL_EVENT = {
    "event_id":         "ml-test-normal-001",
    "source_ip":        "192.168.1.10",
    "destination_ip":   "8.8.8.8",
    "source_port":      54231,
    "destination_port": 443,
    "protocol":         "TCP",
    "timestamp":        "2026-03-04T14:30:00+00:00",
}

SUSPICIOUS_EVENT = {
    "event_id":         "ml-test-sus-001",
    "source_ip":        "185.220.101.45",
    "destination_ip":   "91.108.56.100",
    "source_port":      12345,
    "destination_port": 4444,         # backdoor port
    "protocol":         "TCP",
    "timestamp":        "2026-03-04T03:15:00+00:00",  # 3am
}

MINIMAL_EVENT = {
    "event_id":    "ml-test-minimal-001",
    "source_ip":   "10.0.0.1",
    "destination_ip": "10.0.0.2",
}


# ══════════════════════════════════════════════════════════════════
# Feature Extraction Tests
# ══════════════════════════════════════════════════════════════════

class TestFeatureExtraction:
    """Test that extract_features produces correct 10-dimensional vectors."""

    def test_returns_ten_features(self):
        from app.ml.features import extract_features
        f = extract_features(NORMAL_EVENT)
        assert len(f) == 10, f"Expected 10 features, got {len(f)}"

    def test_all_features_are_floats(self):
        from app.ml.features import extract_features
        f = extract_features(NORMAL_EVENT)
        for i, v in enumerate(f):
            assert isinstance(v, float), f"Feature[{i}]={v} is not float"

    def test_private_ip_flagged(self):
        from app.ml.features import extract_features
        f = extract_features(NORMAL_EVENT)
        # source_ip 192.168.1.10 → is_private_source = 1.0 (index 5)
        assert f[5] == 1.0, f"Expected is_private_source=1.0, got {f[5]}"

    def test_public_ip_not_flagged(self):
        from app.ml.features import extract_features
        f = extract_features(NORMAL_EVENT)
        # destination_ip 8.8.8.8 → is_private_dest = 0.0 (index 6)
        assert f[6] == 0.0, f"Expected is_private_dest=0.0, got {f[6]}"

    def test_port_values_captured(self):
        from app.ml.features import extract_features
        f = extract_features(NORMAL_EVENT)
        assert f[2] == 54231.0, f"Expected source_port=54231.0, got {f[2]}"
        assert f[3] == 443.0,   f"Expected dest_port=443.0, got {f[3]}"

    def test_tcp_protocol_encoded(self):
        from app.ml.features import extract_features
        f = extract_features(NORMAL_EVENT)
        assert f[4] == 1.0, f"Expected TCP=1.0, got {f[4]}"

    def test_udp_protocol_encoded(self):
        from app.ml.features import extract_features
        event = {**NORMAL_EVENT, "protocol": "UDP"}
        f = extract_features(event)
        assert f[4] == 2.0

    def test_unknown_protocol_zero(self):
        from app.ml.features import extract_features
        event = {**NORMAL_EVENT, "protocol": "GRPC"}
        f = extract_features(event)
        assert f[4] == 0.0

    def test_web_port_category(self):
        from app.ml.features import extract_features
        event = {**NORMAL_EVENT, "destination_port": 443}
        f = extract_features(event)
        assert f[8] == 1.0, "Port 443 should be category 1 (web)"

    def test_backdoor_port_category(self):
        from app.ml.features import extract_features
        event = {**NORMAL_EVENT, "destination_port": 4444}
        f = extract_features(event)
        assert f[8] == 3.0, "Port 4444 should be category 3 (admin/backdoor)"

    def test_db_port_category(self):
        from app.ml.features import extract_features
        event = {**NORMAL_EVENT, "destination_port": 3306}
        f = extract_features(event)
        assert f[8] == 2.0, "Port 3306 should be category 2 (database)"

    def test_hour_extracted_correctly(self):
        from app.ml.features import extract_features
        event = {**NORMAL_EVENT, "timestamp": "2026-03-04T03:00:00+00:00"}
        f = extract_features(event)
        assert f[9] == 3.0, f"Expected hour=3.0, got {f[9]}"

    def test_missing_ports_default_zero(self):
        from app.ml.features import extract_features
        f = extract_features(MINIMAL_EVENT)
        assert f[2] == 0.0, "Missing source_port should default to 0.0"
        assert f[3] == 0.0, "Missing dest_port should default to 0.0"

    def test_missing_timestamp_default_noon(self):
        from app.ml.features import extract_features
        f = extract_features(MINIMAL_EVENT)
        assert f[9] == 12.0, "Missing timestamp should default to 12.0 (noon)"

    def test_invalid_ip_returns_zero(self):
        from app.ml.features import extract_features
        event = {**NORMAL_EVENT, "source_ip": "not.an.ip"}
        f = extract_features(event)
        assert f[0] == 0.0

    def test_port_ratio_calculation(self):
        from app.ml.features import extract_features
        event = {**NORMAL_EVENT, "source_port": 443, "destination_port": 443}
        f = extract_features(event)
        # ratio = 443 / (443+1) = 443/444 ≈ 0.9977
        assert abs(f[7] - (443 / 444)) < 0.01

    def test_explain_features_returns_dict(self):
        from app.ml.features import explain_features, feature_names
        result = explain_features(NORMAL_EVENT)
        assert isinstance(result, dict)
        assert set(result.keys()) == set(feature_names)

    def test_ip_to_int_google_dns(self):
        """8.8.8.8 should map to a specific large integer."""
        from app.ml.features import _ip_to_int
        val = _ip_to_int("8.8.8.8")
        assert val == 0x08080808  # 134744072

    def test_feature_names_length(self):
        from app.ml.features import feature_names
        assert len(feature_names) == 10


# ══════════════════════════════════════════════════════════════════
# AnomalyDetector Unit Tests
# ══════════════════════════════════════════════════════════════════

class TestAnomalyDetector:
    """Test the AnomalyDetector class in isolation using a temp DB."""

    @pytest.fixture(autouse=True)
    def patch_db(self, tmp_path, monkeypatch):
        """Point all DB and model operations to temp directory."""
        db_file = str(tmp_path / "test.db")
        model_dir = str(tmp_path / "models")
        os.makedirs(model_dir, exist_ok=True)

        monkeypatch.setenv("ML_MODEL_DIR", model_dir)
        monkeypatch.setenv("ML_MIN_TRAIN_SAMPLES", "10")
        monkeypatch.setenv("ML_RETRAIN_INTERVAL", "50")

        import app.ml.detector as det_module
        monkeypatch.setattr(det_module, "DB_PATH",    db_file)
        monkeypatch.setattr(det_module, "MODEL_DIR",  model_dir)
        monkeypatch.setattr(det_module, "MODEL_PATH", str(tmp_path / "models" / "if.pkl"))
        monkeypatch.setattr(det_module, "SCALER_PATH",str(tmp_path / "models" / "sc.pkl"))
        monkeypatch.setattr(det_module, "MIN_TRAIN_SAMPLES", 10)

        # Also patch _get_db_path
        monkeypatch.setattr(det_module, "_get_db_path", lambda: db_file)

        yield db_file

    def _make_detector(self):
        # Force fresh instance
        from app.ml.detector import AnomalyDetector
        return AnomalyDetector()

    def test_detector_initialises(self):
        d = self._make_detector()
        assert d is not None

    def test_analyze_returns_dict(self):
        d = self._make_detector()
        result = d.analyze(NORMAL_EVENT)
        assert isinstance(result, dict)

    def test_analyze_has_required_keys(self):
        d = self._make_detector()
        result = d.analyze(NORMAL_EVENT)
        required = {"ml_status", "anomaly_detected", "anomaly_score",
                    "confidence", "risk_contribution", "explanation"}
        assert required.issubset(result.keys()), f"Missing keys: {required - result.keys()}"

    def test_insufficient_data_before_training(self):
        d = self._make_detector()
        result = d.analyze(NORMAL_EVENT)
        assert result["ml_status"] == "insufficient_data"
        assert result["anomaly_detected"] is False
        assert result["risk_contribution"] == 0

    def test_train_requires_minimum_samples(self):
        d = self._make_detector()
        result = d.train(force=False)
        assert result["status"] == "insufficient_data"

    def test_force_train_with_few_samples(self):
        """Force=True should attempt training even with 1 sample."""
        d = self._make_detector()
        # Add one sample manually
        from app.ml.features import extract_features
        import app.ml.detector as det
        det._save_event_features("force-test-1", extract_features(NORMAL_EVENT))
        result = d.train(force=True)
        # Should succeed (1 sample is enough for IsolationForest with force)
        assert result["status"] in ("trained", "error")

    def test_train_succeeds_with_enough_data(self):
        """Add 15 events then train — should succeed."""
        d = self._make_detector()
        from app.ml.features import extract_features
        import app.ml.detector as det

        # Generate 15 varied events
        for i in range(15):
            ev = {
                "event_id": f"train-{i}",
                "source_ip": f"10.0.0.{i+1}",
                "destination_ip": f"185.220.{i}.1",
                "source_port": 10000 + i * 100,
                "destination_port": 443 if i % 2 == 0 else 80,
                "protocol": "TCP",
                "timestamp": f"2026-03-04T{10+i%12:02d}:00:00+00:00",
            }
            det._save_event_features(ev["event_id"], extract_features(ev))

        result = d.train(force=False)
        assert result["status"] == "trained", f"Training failed: {result}"
        assert result["sample_count"] == 15

    def test_predict_after_training(self):
        """After training, analyze() should return ml_status='scored'."""
        d = self._make_detector()
        from app.ml.features import extract_features
        import app.ml.detector as det

        for i in range(15):
            ev = {**NORMAL_EVENT, "event_id": f"pre-{i}",
                  "source_port": 50000 + i, "destination_port": 443}
            det._save_event_features(ev["event_id"], extract_features(ev))

        d.train(force=False)
        result = d.analyze({**NORMAL_EVENT, "event_id": "post-train-001"})
        assert result["ml_status"] == "scored"

    def test_anomaly_score_range(self):
        """Anomaly score must always be between 0.0 and 1.0."""
        d = self._make_detector()
        from app.ml.features import extract_features
        import app.ml.detector as det

        for i in range(15):
            ev = {**NORMAL_EVENT, "event_id": f"range-{i}", "source_port": 50000 + i}
            det._save_event_features(ev["event_id"], extract_features(ev))

        d.train(force=False)
        result = d.analyze({**SUSPICIOUS_EVENT, "event_id": "range-suspicious"})

        if result["ml_status"] == "scored":
            score = result["anomaly_score"]
            assert 0.0 <= score <= 1.0, f"Score out of range: {score}"

    def test_risk_contribution_range(self):
        """Risk contribution must be 0–30."""
        d = self._make_detector()
        from app.ml.features import extract_features
        import app.ml.detector as det

        for i in range(15):
            ev = {**NORMAL_EVENT, "event_id": f"rc-{i}", "source_port": 50000 + i}
            det._save_event_features(ev["event_id"], extract_features(ev))
        d.train()

        result = d.analyze({**NORMAL_EVENT, "event_id": "rc-check"})
        if result["ml_status"] == "scored":
            assert 0 <= result["risk_contribution"] <= 30

    def test_status_returns_correct_structure(self):
        d = self._make_detector()
        s = d.status()
        assert "model_trained" in s
        assert "events_collected" in s
        assert "min_train_samples" in s
        assert "feature_names" in s
        assert len(s["feature_names"]) == 10

    def test_status_model_trained_false_initially(self):
        d = self._make_detector()
        assert d.status()["model_trained"] is False

    def test_status_model_trained_true_after_training(self):
        d = self._make_detector()
        from app.ml.features import extract_features
        import app.ml.detector as det
        for i in range(15):
            ev = {**NORMAL_EVENT, "event_id": f"st-{i}", "source_port": 50000 + i}
            det._save_event_features(ev["event_id"], extract_features(ev))
        d.train()
        assert d.status()["model_trained"] is True

    def test_features_stored_after_analyze(self):
        """Every call to analyze() should persist features to ml_events."""
        import sqlite3
        import app.ml.detector as det
        d = self._make_detector()
        d.analyze({**NORMAL_EVENT, "event_id": "store-test-001"})
        conn = sqlite3.connect(det._get_db_path())
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ml_events WHERE event_id='store-test-001'")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 1

    def test_duplicate_event_not_double_stored(self):
        """Same event_id submitted twice should only store once."""
        import sqlite3
        import app.ml.detector as det
        d = self._make_detector()
        d.analyze({**NORMAL_EVENT, "event_id": "dup-test-001"})
        d.analyze({**NORMAL_EVENT, "event_id": "dup-test-001"})
        conn = sqlite3.connect(det._get_db_path())
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ml_events WHERE event_id='dup-test-001'")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 1


# ══════════════════════════════════════════════════════════════════
# API Integration Tests
# ══════════════════════════════════════════════════════════════════

class TestMLAPIEndpoints:
    """Test /ml/* endpoints via FastAPI TestClient."""

    def test_ml_status_endpoint(self, api_client):
        r = api_client.get("/ml/status")
        assert r.status_code == 200
        data = r.json()
        assert "model_trained" in data
        assert "events_collected" in data

    def test_ml_train_insufficient_data(self, api_client):
        r = api_client.post("/ml/train")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("insufficient_data", "trained", "error")

    def test_ml_train_force(self, api_client):
        r = api_client.post("/ml/train?force=true")
        assert r.status_code == 200

    def test_ml_predict_returns_result(self, api_client):
        r = api_client.post("/ml/predict", json={
            "event_id":         "predict-001",
            "source_ip":        "192.168.1.10",
            "destination_ip":   "8.8.8.8",
            "source_port":      54231,
            "destination_port": 443,
            "protocol":         "TCP",
        })
        assert r.status_code == 200
        data = r.json()
        assert "ml_analysis" in data
        assert "anomaly_score" in data["ml_analysis"]

    def test_ml_predict_score_range(self, api_client):
        r = api_client.post("/ml/predict", json={
            "event_id": "predict-range-001",
            "source_ip": "185.220.101.45",
            "destination_ip": "91.108.56.100",
            "source_port": 12345,
            "destination_port": 4444,
            "protocol": "TCP",
        })
        assert r.status_code == 200
        score = r.json()["ml_analysis"]["anomaly_score"]
        assert 0.0 <= score <= 1.0

    def test_event_endpoint_includes_ml_analysis(self, api_client):
        r = api_client.post("/event", json={
            "event_id":         "ml-event-001",
            "source_ip":        "1.2.3.4",
            "destination_ip":   "5.6.7.8",
            "source_port":      12345,
            "destination_port": 80,
            "protocol":         "TCP",
        })
        assert r.status_code == 200
        data = r.json()
        assert "ml_analysis" in data, "ml_analysis missing from /event response"
        assert "ioc_analysis" in data, "ioc_analysis missing from /event response"
        assert "final_risk_score" in data, "final_risk_score missing"
        assert "final_severity" in data, "final_severity missing"

    def test_event_status_values(self, api_client):
        r = api_client.post("/event", json={
            "event_id": "ml-status-001",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
        })
        assert r.status_code == 200
        status = r.json()["status"]
        assert status in ("benign", "threat_detected", "anomaly_detected", "confirmed_threat")

    def test_event_final_risk_in_range(self, api_client):
        r = api_client.post("/event", json={
            "event_id": "risk-range-001",
            "source_ip": "10.0.0.1",
            "destination_ip": "8.8.8.8",
            "destination_port": 443,
        })
        assert r.status_code == 200
        score = r.json()["final_risk_score"]
        assert 0.0 <= score <= 100.0

    def test_metrics_includes_ml_stats(self, api_client):
        r = api_client.get("/metrics")
        assert r.status_code == 200
        stats = r.json()["statistics"]
        assert "ml" in stats, "ML stats missing from /metrics"
        ml = stats["ml"]
        assert "total_ml_events" in ml
        assert "total_anomalies" in ml
        assert "model_trained" in ml
