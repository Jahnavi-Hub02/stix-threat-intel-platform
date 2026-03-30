from app.database.db_manager import create_connection, save_event
from app.utils.ip_validator import is_public_ip
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── MITRE ATT&CK Quick Mapping ───────────────────────────────────
MITRE_MAPPING = {
    "Potential Incoming Attack": {
        "tactic": "Initial Access",
        "technique": "T1190 - Exploit Public-Facing Application"
    },
    "Potential Outbound Compromise": {
        "tactic": "Command and Control",
        "technique": "T1071 - Application Layer Protocol"
    },
    "Active Malicious Communication": {
        "tactic": "Lateral Movement",
        "technique": "T1021 - Remote Services"
    },
}

# IOC type weights for risk scoring
# Keys cover both the DB-stored shorthand (ipv4, domain) and STIX format (ipv4-addr)
IOC_TYPE_WEIGHTS = {
    "ipv4": 1.0, "ipv4-addr": 1.0,
    "domain": 0.9, "domain-name": 0.9,
    "url": 0.85,
    "md5": 0.95, "file-hash": 0.95,
    "sha256": 1.0,
    "unknown": 0.5,
}


def _calculate_risk_score(confidence: int, ioc_type: str, match_type: str) -> float:
    """Risk Score = (confidence/100) × ioc_weight × match_multiplier × 100"""
    multipliers = {"source_ip": 1.2, "destination_ip": 1.0, "both": 1.5}
    weight = IOC_TYPE_WEIGHTS.get(ioc_type, 0.5)
    multiplier = multipliers.get(match_type, 1.0)
    return min(round((confidence / 100) * weight * multiplier * 100, 2), 100.0)


def _get_severity(score: float) -> str:
    if score >= 80: return "Critical"
    if score >= 60: return "High"
    if score >= 35: return "Medium"
    return "Low"


def correlate_event(event: dict) -> list:
    """
    Correlate a network event against the IOC database.
    - Saves event to event_logs
    - Skips private/loopback IPs
    - Calculates risk score + severity
    - Maps to MITRE ATT&CK
    - Deduplicates results via UNIQUE DB constraint
    """
    save_event(event)

    conn = create_connection()
    cursor = conn.cursor()
    results = []
    matched_roles = []

    for role in ["source_ip", "destination_ip"]:
        ip = event.get(role)
        if not ip or not is_public_ip(ip):
            continue

        cursor.execute(
            "SELECT ioc_type, confidence FROM ioc_indicators WHERE ioc_value = ? AND is_active = 1",
            (ip,)
        )
        match = cursor.fetchone()

        if match:
            matched_roles.append(role)
            ioc_type = match["ioc_type"]
            confidence = match["confidence"]
            decision = "Potential Incoming Attack" if role == "source_ip" else "Potential Outbound Compromise"
            risk_score = _calculate_risk_score(confidence, ioc_type, role)
            severity = _get_severity(risk_score)
            mitre = MITRE_MAPPING.get(decision, {"tactic": "N/A", "technique": "N/A"})

            results.append({
                "event_id": event["event_id"],
                "matched_ip": ip,
                "match_type": role,
                "decision": decision,
                "risk_score": risk_score,
                "severity": severity,
                "mitre_tactic": mitre["tactic"],
                "mitre_technique": mitre["technique"],
                "confidence": confidence,
                "ioc_type": ioc_type
            })

    # Upgrade both-match to "Active Malicious Communication"
    if len(matched_roles) == 2:
        for r in results:
            r["match_type"] = "both"
            r["decision"] = "Active Malicious Communication"
            r["risk_score"] = _calculate_risk_score(r["confidence"], r["ioc_type"], "both")
            r["severity"] = _get_severity(r["risk_score"])
            mitre = MITRE_MAPPING["Active Malicious Communication"]
            r["mitre_tactic"] = mitre["tactic"]
            r["mitre_technique"] = mitre["technique"]

    # Store results — UNIQUE constraint silently skips duplicates
    for r in results:
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO correlation_results
                (event_id, matched_ip, match_type, decision,
                 risk_score, severity, mitre_tactic, source_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r["event_id"], r["matched_ip"], r["match_type"],
                r["decision"], r["risk_score"], r["severity"],
                r["mitre_tactic"], event.get("source_ip"),
            ))
        except Exception as e:
            logger.debug("Correlation insert skipped: %s", e)

    cursor.execute(
        "UPDATE event_logs SET is_processed = 1 WHERE event_id = ?",
        (event["event_id"],)
    )

    conn.commit()
    conn.close()

    logger.info("Event correlated", event_id=event["event_id"], matches=len(results))
    return results