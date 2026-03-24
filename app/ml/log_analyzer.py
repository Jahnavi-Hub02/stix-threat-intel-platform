"""
app/ml/log_analyzer.py
=======================
Mentor requirement (Module 2): analyze a given log stream or file for
malicious patterns/activities and generate an alert if applicable.

This is the ML module's equivalent of log_checker.py from Module 1.
Module 1 checks logs against known IOCs (signature-based).
Module 2 (this file) uses the trained ML models to detect UNKNOWN threats
(anomaly detection + classification).

The two modules work together:
  Module 1 hit → known threat
  Module 2 hit → unknown/novel threat pattern

Both run on the same log file and their results are merged by the
/logs/analyze endpoint.
"""
import re
import os
import logging
from datetime import datetime, timezone
from typing import Iterator, List, Dict, Optional

logger = logging.getLogger(__name__)

# ── Extract structured event fields from a log line ──────────────────────────
# Supports common log formats: Apache/Nginx, syslog, CSV, JSON lines
_IPV4 = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_PORT = re.compile(r':(\d{2,5})\b')
_HTTP = re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP')
_TS   = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')


def _parse_log_line(line: str, line_number: int) -> Optional[Dict]:
    """
    Parse a log line into a structured event dict suitable for ML analysis.
    Returns None if the line can't be meaningfully parsed.
    """
    ips   = _IPV4.findall(line)
    ports = _PORT.findall(line)
    urls  = _HTTP.findall(line)

    if not ips:
        return None

    ts_match = _TS.search(line)
    timestamp = ts_match.group(0).replace(" ", "T") + "Z" if ts_match else datetime.now(timezone.utc).isoformat()

    return {
        "event_id":         f"log-line-{line_number}",
        "source_ip":        ips[0],
        "destination_ip":   ips[1] if len(ips) > 1 else "",
        "source_port":      int(ports[0]) if ports else 0,
        "destination_port": int(ports[1]) if len(ports) > 1 else (80 if urls else 0),
        "protocol":         "TCP",
        "timestamp":        timestamp,
        "log_line":         line.strip()[:200],
    }


def analyze_event_ml(event: Dict) -> Dict:
    """Run both ML layers on a single event dict."""
    clf_result = {"classifier_status": "not_trained", "is_attack": False,
                  "predicted_class": "UNKNOWN", "risk_contribution": 0}
    if_result  = {"if_status": "not_ready", "is_anomaly": False,
                  "anomaly_score": 0.0, "if_risk_boost": 0}

    try:
        from app.ml.classifier import predict as clf_predict
        clf_result = clf_predict(event)
    except Exception as e:
        logger.debug("Classifier skipped: %s", e)

    try:
        from app.ml.detector import get_detector
        detector = get_detector()
        det_result = detector.analyze(event)
        if_result = det_result.get("isolation_forest", if_result)
    except Exception as e:
        logger.debug("Detector skipped: %s", e)

    is_threat = clf_result.get("is_attack", False) or if_result.get("is_anomaly", False)
    risk = min(clf_result.get("risk_contribution", 0) + if_result.get("if_risk_boost", 0), 50)

    return {
        "is_threat":         is_threat,
        "risk_score":        risk,
        "classifier":        clf_result,
        "isolation_forest":  if_result,
        "explanation": (
            f"RF: {clf_result.get('predicted_class','?')} "
            f"({clf_result.get('confidence',0)*100:.0f}%) | "
            f"IF score: {if_result.get('anomaly_score',0):.2f}"
            if is_threat else "No threat detected"
        ),
    }


# ── Offline: analyze a complete log file with ML ──────────────────────────────

def analyze_log_file(filepath: str, max_lines: int = 0) -> Dict:
    """
    Analyze an entire log file using the ML models.
    Returns list of lines where ML detected a threat.

    Parameters
    ----------
    filepath  : str  Path to the log file
    max_lines : int  Max lines to check (0 = all)
    """
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}", "alerts": [], "total_alerts": 0}

    alerts  = []
    checked = 0

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, start=1):
                if max_lines and line_num > max_lines:
                    break
                checked += 1

                event = _parse_log_line(line, line_num)
                if not event:
                    continue

                ml = analyze_event_ml(event)
                if ml["is_threat"]:
                    alerts.append({
                        "timestamp":   event["timestamp"],
                        "source_file": filepath,
                        "line_number": line_num,
                        "log_line":    line.strip()[:200],
                        "source_ip":   event["source_ip"],
                        "ml_analysis": ml,
                        "severity":    "high" if ml["risk_score"] >= 30 else "medium",
                        "alert":       True,
                    })
                    logger.warning("ML ALERT line %d: %s risk=%d",
                                   line_num, ml["explanation"], ml["risk_score"])

    except Exception as e:
        logger.error("analyze_log_file error: %s", e)
        return {"error": str(e), "alerts": alerts, "total_alerts": len(alerts)}

    return {
        "alerts":         alerts,
        "lines_checked":  checked,
        "total_alerts":   len(alerts),
        "checked_at":     datetime.now(timezone.utc).isoformat(),
        "source_file":    filepath,
    }


def analyze_log_content(content: str, source_name: str = "api-upload") -> Dict:
    """Analyze log content provided as string (e.g. API upload)."""
    alerts  = []
    checked = 0

    for line_num, line in enumerate(content.splitlines(), start=1):
        checked += 1
        event = _parse_log_line(line, line_num)
        if not event:
            continue
        ml = analyze_event_ml(event)
        if ml["is_threat"]:
            alerts.append({
                "timestamp":   event["timestamp"],
                "source_file": source_name,
                "line_number": line_num,
                "log_line":    line.strip()[:200],
                "source_ip":   event["source_ip"],
                "ml_analysis": ml,
                "severity":    "high" if ml["risk_score"] >= 30 else "medium",
                "alert":       True,
            })

    return {
        "alerts":        alerts,
        "lines_checked": checked,
        "total_alerts":  len(alerts),
        "checked_at":    datetime.now(timezone.utc).isoformat(),
        "source_file":   source_name,
    }


# ── Online: stream analysis ───────────────────────────────────────────────────

def stream_analyze_log(filepath: str, poll_interval: float = 1.0) -> Iterator[Dict]:
    """
    Tail a live log file and yield ML threat alerts as they appear.
    """
    import time
    if not os.path.exists(filepath):
        logger.error("stream_analyze_log: file not found: %s", filepath)
        return

    line_num = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)  # seek to end — only analyse new lines
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            line_num += 1
            event = _parse_log_line(line, line_num)
            if not event:
                continue
            ml = analyze_event_ml(event)
            if ml["is_threat"]:
                yield {
                    "timestamp":   event["timestamp"],
                    "source_file": filepath,
                    "line_number": line_num,
                    "log_line":    line.strip()[:200],
                    "source_ip":   event["source_ip"],
                    "ml_analysis": ml,
                    "severity":    "high" if ml["risk_score"] >= 30 else "medium",
                    "alert":       True,
                }
