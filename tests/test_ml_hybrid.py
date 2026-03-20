"""
tests/test_ml_hybrid.py
========================
Tests for Module 2: Hybrid ML System
Covers: live feature extraction, classifier train/predict,
        Isolation Forest integration, combined analyze() output.
Uses synthetic data — no real dataset download needed.
"""
import pytest, os, json
import numpy as np

BENIGN_EVENT = {
    "event_id":"ml-benign-001","source_ip":"192.168.1.10",
    "destination_ip":"8.8.8.8","source_port":54231,
    "destination_port":443,"protocol":"TCP",
    "timestamp":"2026-03-20T14:00:00+00:00",
}
ATTACK_EVENT = {
    "event_id":"ml-attack-001","source_ip":"185.220.101.45",
    "destination_ip":"10.0.0.5","source_port":12345,
    "destination_port":4444,"protocol":"TCP",     # backdoor port
    "timestamp":"2026-03-20T03:00:00+00:00",      # 3am
}
MINIMAL_EVENT = {"event_id":"ml-min-001","source_ip":"10.0.0.1","destination_ip":"10.0.0.2"}


# ══════════════════════════════════════════════════════════════════════════════
# Classifier Feature Extraction
# ══════════════════════════════════════════════════════════════════════════════

class TestClassifierFeatures:

    def _f(self, event):
        from app.ml.classifier import extract_live_features
        return extract_live_features(event)

    def test_returns_7_features(self):       assert len(self._f(BENIGN_EVENT)) == 7
    def test_all_floats(self):               assert all(isinstance(v,float) for v in self._f(BENIGN_EVENT))
    def test_dst_port(self):                 assert self._f(BENIGN_EVENT)[0] == 443.0
    def test_tcp_encoded_1(self):            assert self._f(BENIGN_EVENT)[1] == 1.0
    def test_udp_encoded_2(self):            assert self._f({**BENIGN_EVENT,"protocol":"UDP"})[1] == 2.0
    def test_unknown_proto_0(self):          assert self._f({**BENIGN_EVENT,"protocol":"GRPC"})[1] == 0.0
    def test_private_src_flagged(self):      assert self._f(BENIGN_EVENT)[2] == 1.0  # 192.168.x
    def test_public_dst_not_flagged(self):   assert self._f(BENIGN_EVENT)[3] == 0.0  # 8.8.8.8
    def test_hour_extracted(self):           assert self._f(BENIGN_EVENT)[4] == 14.0
    def test_day_friday(self):               assert self._f(BENIGN_EVENT)[5] == 4.0  # Friday UTC (2026-03-20 is Friday)
    def test_web_port_cat_1(self):           assert self._f({**BENIGN_EVENT,"destination_port":443})[6] == 1.0
    def test_backdoor_port_cat_3(self):      assert self._f({**BENIGN_EVENT,"destination_port":4444})[6] == 3.0
    def test_db_port_cat_2(self):            assert self._f({**BENIGN_EVENT,"destination_port":3306})[6] == 2.0
    def test_mail_port_cat_4(self):          assert self._f({**BENIGN_EVENT,"destination_port":25})[6] == 4.0
    def test_missing_port_zero(self):        assert self._f(MINIMAL_EVENT)[0] == 0.0
    def test_invalid_ip_no_crash(self):
        f = self._f({**BENIGN_EVENT,"source_ip":"not.valid"})
        assert f[2] == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# Isolation Forest Feature Extraction (10 features)
# ══════════════════════════════════════════════════════════════════════════════

class TestIFFeatures:

    def _f(self, event):
        from app.ml.detector import extract_features
        return extract_features(event)

    def test_returns_10_features(self):      assert len(self._f(BENIGN_EVENT)) == 10
    def test_all_floats(self):               assert all(isinstance(v,float) for v in self._f(BENIGN_EVENT))
    def test_dst_port_captured(self):        assert self._f(BENIGN_EVENT)[0] == 443.0
    def test_missing_port_zero(self):        assert self._f(MINIMAL_EVENT)[0] == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# Classifier — Not Trained
# ══════════════════════════════════════════════════════════════════════════════

class TestClassifierNotTrained:

    @pytest.fixture(autouse=True)
    def no_model(self, tmp_path, monkeypatch):
        import app.ml.classifier as m
        monkeypatch.setattr(m, "CLF_PATH",     str(tmp_path/"rf.pkl"))
        monkeypatch.setattr(m, "SCALER_PATH",  str(tmp_path/"sc.pkl"))
        monkeypatch.setattr(m, "ENCODER_PATH", str(tmp_path/"le.pkl"))

    def test_not_trained_status(self):
        from app.ml.classifier import predict
        assert predict(BENIGN_EVENT)["classifier_status"] == "not_trained"

    def test_not_trained_no_crash(self):
        from app.ml.classifier import predict
        assert isinstance(predict(ATTACK_EVENT), dict)

    def test_not_trained_risk_zero(self):
        from app.ml.classifier import predict
        assert predict(BENIGN_EVENT)["risk_contribution"] == 0

    def test_status_trained_false(self):
        from app.ml.classifier import status
        assert status()["classifier_trained"] is False


# ══════════════════════════════════════════════════════════════════════════════
# Classifier — Train + Predict (synthetic data)
# ══════════════════════════════════════════════════════════════════════════════

class TestClassifierTrainPredict:

    @pytest.fixture
    def synthetic_csv(self, tmp_path):
        """Create a minimal NSL-KDD CSV with 200 rows."""
        import pandas as pd
        rows = []
        for i in range(200):
            label = ["normal","neptune","ipsweep"][i%3]
            rows.append({"duration":i%10,"protocol_type":["tcp","udp","icmp"][i%3],
                "service":"http","flag":"SF","src_bytes":i*100,"dst_bytes":i*50,
                "land":0,"wrong_fragment":0,"urgent":0,"hot":0,"num_failed_logins":0,
                "logged_in":1,"num_compromised":0,"root_shell":0,"su_attempted":0,
                "num_root":0,"num_file_creations":0,"num_shells":0,"num_access_files":0,
                "num_outbound_cmds":0,"is_host_login":0,"is_guest_login":0,
                "count":i%511,"srv_count":i%511,"serror_rate":0.0,"srv_serror_rate":0.0,
                "rerror_rate":0.0,"srv_rerror_rate":0.0,"same_srv_rate":1.0,
                "diff_srv_rate":0.0,"srv_diff_host_rate":0.0,"dst_host_count":i%255,
                "dst_host_srv_count":i%255,"dst_host_same_srv_rate":1.0,
                "dst_host_diff_srv_rate":0.0,"dst_host_same_src_port_rate":0.0,
                "dst_host_srv_diff_host_rate":0.0,"dst_host_serror_rate":0.0,
                "dst_host_srv_serror_rate":0.0,"dst_host_rerror_rate":0.0,
                "dst_host_srv_rerror_rate":0.0,"label":label,"difficulty":21})
        df  = pd.DataFrame(rows)
        p   = str(tmp_path/"KDDTrain.txt")
        df.to_csv(p, index=False, header=False)
        return p

    @pytest.fixture
    def trained(self, synthetic_csv, tmp_path, monkeypatch):
        import app.ml.classifier as m
        monkeypatch.setattr(m, "MODEL_DIR",    str(tmp_path))
        monkeypatch.setattr(m, "CLF_PATH",     str(tmp_path/"rf.pkl"))
        monkeypatch.setattr(m, "SCALER_PATH",  str(tmp_path/"sc.pkl"))
        monkeypatch.setattr(m, "ENCODER_PATH", str(tmp_path/"le.pkl"))
        from app.ml.classifier import train
        r = train(synthetic_csv, "nslkdd")
        assert r["status"] == "trained"
        return r

    def test_train_status_trained(self, trained):
        assert trained["status"] == "trained"

    def test_train_reports_accuracy(self, trained):
        assert 0.0 <= trained["accuracy"] <= 1.0

    def test_train_has_classes(self, trained):
        assert "BENIGN" in trained["classes"]

    def test_predict_returns_scored(self, trained):
        from app.ml.classifier import predict
        assert predict(BENIGN_EVENT)["classifier_status"] == "scored"

    def test_predict_confidence_range(self, trained):
        from app.ml.classifier import predict
        r = predict(BENIGN_EVENT)
        assert 0.0 <= r["confidence"] <= 1.0

    def test_predict_probabilities_sum_one(self, trained):
        from app.ml.classifier import predict
        probs = list(predict(BENIGN_EVENT)["all_probabilities"].values())
        assert abs(sum(probs)-1.0) < 0.01

    def test_predict_risk_range(self, trained):
        from app.ml.classifier import predict
        assert 0 <= predict(ATTACK_EVENT)["risk_contribution"] <= 40

    def test_predict_is_attack_bool(self, trained):
        from app.ml.classifier import predict
        assert isinstance(predict(BENIGN_EVENT)["is_attack"], bool)

    def test_status_trained_true(self, trained):
        from app.ml.classifier import status
        assert status()["classifier_trained"] is True

    def test_minimal_event_no_crash(self, trained):
        from app.ml.classifier import predict
        assert isinstance(predict(MINIMAL_EVENT), dict)


# ══════════════════════════════════════════════════════════════════════════════
# AnomalyDetector (Isolation Forest)
# ══════════════════════════════════════════════════════════════════════════════

class TestAnomalyDetector:

    @pytest.fixture(autouse=True)
    def patch_paths(self, tmp_path, monkeypatch):
        import app.ml.detector as det
        monkeypatch.setattr(det, "DB_PATH",    str(tmp_path/"test.db"))
        monkeypatch.setattr(det, "MODEL_PATH", str(tmp_path/"if.pkl"))
        monkeypatch.setattr(det, "SCALER_PATH",str(tmp_path/"sc.pkl"))
        monkeypatch.setattr(det, "MIN_TRAIN_SAMPLES", 10)
        monkeypatch.setattr(det, "_get_db_path", lambda: str(tmp_path/"test.db"))

    def _detector(self):
        from app.ml.detector import AnomalyDetector
        return AnomalyDetector()

    def test_init_no_crash(self):            assert self._detector() is not None
    def test_analyze_returns_dict(self):     assert isinstance(self._detector().analyze(BENIGN_EVENT), dict)

    def test_analyze_has_keys(self):
        r = self._detector().analyze(BENIGN_EVENT)
        for key in ["ml_status","anomaly_detected","anomaly_score",
                    "risk_contribution","isolation_forest","classifier"]:
            assert key in r, f"Missing key: {key}"

    def test_analyze_before_train(self):
        r = self._detector().analyze(BENIGN_EVENT)
        assert r["isolation_forest"]["if_status"] in ("insufficient_data","not_ready","scored")

    def test_features_stored_after_analyze(self, tmp_path, monkeypatch):
        import sqlite3, app.ml.detector as det
        db = str(tmp_path/"test.db")
        monkeypatch.setattr(det, "_get_db_path", lambda: db)
        d = self._detector()
        d.analyze({**BENIGN_EVENT,"event_id":"store-test-001"})
        conn = sqlite3.connect(db)
        n = conn.execute("SELECT COUNT(*) FROM ml_events WHERE event_id='store-test-001'").fetchone()[0]
        conn.close()
        assert n == 1

    def test_train_insufficient_without_force(self):
        r = self._detector().train(force=False)
        assert r["status"] == "insufficient_data"

    def test_train_succeeds_with_15_events(self, tmp_path, monkeypatch):
        import app.ml.detector as det
        db = str(tmp_path/"test.db")
        monkeypatch.setattr(det, "_get_db_path", lambda: db)
        monkeypatch.setattr(det, "MIN_TRAIN_SAMPLES", 5)
        d = self._detector()
        from app.ml.detector import extract_features, _save_features
        for i in range(15):
            ev = {**BENIGN_EVENT,"event_id":f"tr-{i}","destination_port":443+i}
            _save_features(ev["event_id"], extract_features(ev))
        r = d.train()
        assert r["status"] == "trained"

    def test_status_has_both_layers(self):
        r = self._detector().status()
        assert "isolation_forest" in r
        assert "classifier" in r


# ══════════════════════════════════════════════════════════════════════════════
# API Endpoint Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMLAPIEndpoints:

    def test_ml_status_200(self, api_client, analyst_token):
        r = api_client.get("/ml/status",
                           headers={"Authorization":f"Bearer {analyst_token}"})
        assert r.status_code == 200
        data = r.json()
        assert "isolation_forest" in data or "model_trained" in data

    def test_ml_train_200(self, api_client, analyst_token):
        r = api_client.post("/ml/train",
                            headers={"Authorization":f"Bearer {analyst_token}"})
        assert r.status_code == 200

    def test_ml_predict_200(self, api_client, analyst_token):
        r = api_client.post("/ml/predict",
            headers={"Authorization":f"Bearer {analyst_token}"},
            json={"event_id":"pred-001","source_ip":"192.168.1.1",
                  "destination_ip":"8.8.8.8","destination_port":443,"protocol":"TCP"})
        assert r.status_code == 200

    def test_event_has_ml_analysis(self, api_client, analyst_token):
        r = api_client.post("/event",
            headers={"Authorization":f"Bearer {analyst_token}"},
            json={"event_id":"ml-evt-001","source_ip":"192.168.1.1",
                  "destination_ip":"8.8.8.8","destination_port":443,"protocol":"TCP"})
        assert r.status_code == 200
        data = r.json()
        assert "ml_analysis" in data
        ml = data["ml_analysis"]
        assert "anomaly_detected" in ml
        assert "risk_contribution" in ml
        assert "classifier" in ml or "isolation_forest" in ml

    def test_event_status_valid_values(self, api_client, analyst_token):
        r = api_client.post("/event",
            headers={"Authorization":f"Bearer {analyst_token}"},
            json={"event_id":"status-001","source_ip":"10.0.0.1",
                  "destination_ip":"10.0.0.2"})
        assert r.status_code == 200
        assert r.json()["status"] in ["benign","threat_detected",
                                       "anomaly_detected","confirmed_threat"]

    def test_classifier_status_endpoint(self, api_client, analyst_token):
        r = api_client.get("/ml/classifier/status",
                           headers={"Authorization":f"Bearer {analyst_token}"})
        assert r.status_code == 200
        assert "classifier_trained" in r.json()

    def test_ml_requires_auth(self, api_client):
        r = api_client.get("/ml/status")
        assert r.status_code == 401