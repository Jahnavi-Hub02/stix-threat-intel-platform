"""
app/utils/report_generator.py
==============================
Generates PDF threat intelligence reports.
Includes both IOC correlation results and ML anomaly detection analysis.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.units import mm
from datetime import datetime
import os

from app.utils.logger import get_logger
logger = get_logger(__name__)

COLOR_DARK     = colors.HexColor("#1A1A2E")
COLOR_ACCENT   = colors.HexColor("#E94560")
COLOR_LIGHT    = colors.HexColor("#F4F4F4")
COLOR_GRAY     = colors.HexColor("#CCCCCC")
COLOR_ML_GOOD  = colors.HexColor("#27AE60")
COLOR_ML_BAD   = colors.HexColor("#C0392B")
COLOR_ML_PANEL = colors.HexColor("#0D1117")
COLOR_ML_CELL  = colors.HexColor("#111827")
COLOR_ML_BLUE  = colors.HexColor("#00D4FF")
COLOR_ML_MUT   = colors.HexColor("#4A5568")

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#C0392B"),
    "High":     colors.HexColor("#E67E22"),
    "Medium":   colors.HexColor("#F1C40F"),
    "Low":      colors.HexColor("#27AE60"),
}


def generate_report(event: dict, results: list, output_dir: str = "reports", ml_result: dict = None) -> str:
    """Generate a professional PDF threat intelligence report including ML analysis."""
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))

    reports_dir = os.path.join(PROJECT_ROOT, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    file_name = os.path.join(reports_dir, f"Threat_Report_{event['event_id']}.pdf")

    doc = SimpleDocTemplate(
        file_name, pagesize=A4,
        rightMargin=20*mm, leftMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
    )
    styles = getSampleStyleSheet()
    story  = []

    # ── Style helpers (use the existing pattern from the original file) ──
    def h1(t):   return Paragraph(f'<font size="18" color="#1A1A2E"><b>{t}</b></font>', styles["Normal"])
    def h2(t):   return Paragraph(f'<font size="13" color="#1A1A2E"><b>{t}</b></font>', styles["Normal"])
    def h3(t):   return Paragraph(f'<font size="11" color="#1A1A2E"><b>{t}</b></font>', styles["Normal"])
    def body(t): return Paragraph(f'<font size="10">{t}</font>', styles["Normal"])
    def mono(t): return Paragraph(f'<font size="9" name="Courier">{t}</font>', styles["Normal"])
    def sp(h=6): return Spacer(1, h*mm)
    def hr():    return HRFlowable(width="100%", thickness=0.5, color=COLOR_GRAY)
    def hr_ml(): return HRFlowable(width="100%", thickness=0.5, color=COLOR_ML_BLUE)

    # ── Header ──────────────────────────────────────────────────────────
    story += [
        sp(4),
        h1("🛡  Threat Intelligence Report"),
        sp(2),
        body(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"),
        body("<b>Platform:</b> STIX 2.1 Threat Correlation System v2.2 (+ ML Anomaly Detection)"),
        sp(4), hr(), sp(4),
    ]

    # ── Executive Summary ────────────────────────────────────────────────
    story.append(h2("Executive Summary"))
    story.append(sp(2))

    ioc_hit    = bool(results)
    ml_anomaly = bool(ml_result and ml_result.get("anomaly_detected"))

    if ioc_hit and ml_anomaly:
        summary_txt = (
            f"<b>CONFIRMED THREAT</b>: {len(results)} IOC match(es) detected "
            f"AND ML anomaly flagged (score={ml_result.get('anomaly_score', 0):.2f}). "
            f"Both detection layers agree — immediate investigation required."
        )
    elif ioc_hit:
        sevs = [r.get("severity", "Low") for r in results]
        top  = ("Critical" if "Critical" in sevs else "High" if "High" in sevs
                else "Medium" if "Medium" in sevs else "Low")
        summary_txt = (
            f"<b>{len(results)} threat(s)</b> detected via IOC correlation. "
            f"Highest severity: <b>{top}</b>. ML layer: no anomaly."
        )
    elif ml_anomaly:
        score = ml_result.get("anomaly_score", 0)
        summary_txt = (
            f"<b>ML ANOMALY DETECTED</b> (score={score:.2f}): No known IOC match, "
            f"but behavioural analysis flagged this event as suspicious. "
            f"Investigate traffic pattern."
        )
    else:
        summary_txt = (
            "No indicators of compromise detected and ML analysis shows normal behaviour. "
            "Activity classified as <b>Benign</b>."
        )

    story += [body(summary_txt), sp(5)]

    # ── Event Details ────────────────────────────────────────────────────
    story.append(h2("Event Details"))
    story.append(sp(2))
    tbl = Table([
        ["Field", "Value"],
        ["Event ID",         event.get("event_id", "N/A")],
        ["Source IP",        event.get("source_ip", "N/A")],
        ["Destination IP",   event.get("destination_ip", "N/A")],
        ["Source Port",      str(event.get("source_port", "N/A"))],
        ["Destination Port", str(event.get("destination_port", "N/A"))],
        ["Protocol",         event.get("protocol", "N/A")],
        ["Timestamp",        event.get("timestamp", "N/A")],
    ], colWidths=[55*mm, 115*mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), COLOR_DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0, 1), (-1,-1), [colors.white, COLOR_LIGHT]),
        ("GRID",          (0, 0), (-1,-1), 0.3, COLOR_GRAY),
        ("LEFTPADDING",   (0, 0), (-1,-1), 8),
        ("TOPPADDING",    (0, 0), (-1,-1), 5),
    ]))
    story += [tbl, sp(6)]

    # ── IOC Correlation Results ──────────────────────────────────────────
    story.append(h2("IOC Correlation Results"))
    story.append(sp(2))
    if results:
        rows = [["Matched IP", "Match Type", "Decision", "Risk Score", "Severity", "MITRE Tactic"]]
        for r in results:
            rows.append([
                r.get("matched_ip",   "N/A"),
                r.get("match_type",   "N/A").replace("_", " ").title(),
                r.get("decision",     "N/A"),
                f"{r.get('risk_score', 0):.1f}/100",
                r.get("severity",     "Low"),
                r.get("mitre_tactic", "N/A"),
            ])
        rtbl = Table(rows, colWidths=[30*mm, 27*mm, 40*mm, 22*mm, 20*mm, 31*mm])
        rstyle = [
            ("BACKGROUND",    (0, 0), (-1, 0), COLOR_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1,-1), [colors.white, COLOR_LIGHT]),
            ("GRID",          (0, 0), (-1,-1), 0.3, COLOR_GRAY),
            ("LEFTPADDING",   (0, 0), (-1,-1), 6),
            ("TOPPADDING",    (0, 0), (-1,-1), 5),
        ]
        for i, r in enumerate(results, 1):
            c = SEVERITY_COLORS.get(r.get("severity", "Low"), colors.gray)
            rstyle += [("TEXTCOLOR", (4,i), (4,i), c), ("FONTNAME", (4,i), (4,i), "Helvetica-Bold")]
        rtbl.setStyle(TableStyle(rstyle))
        story += [rtbl, sp(6)]

        # MITRE ATT&CK
        story.append(h2("MITRE ATT&CK Mapping"))
        story.append(sp(2))
        seen_t = set()
        for r in results:
            t = r.get("mitre_tactic", "N/A")
            if t not in seen_t:
                seen_t.add(t)
                story += [
                    body(f"<b>Tactic:</b> {t}"),
                    body(f"<b>Technique:</b> {r.get('mitre_technique', 'N/A')}"),
                    sp(2),
                ]
        story.append(sp(4))
    else:
        story += [body("✅ No IOC matches found in the threat intelligence database."), sp(5)]

    # ── ML Anomaly Detection Section ─────────────────────────────────────
    if ml_result and ml_result.get("ml_status") not in (None, "error", "unavailable"):
        story += [sp(2), h2("ML Anomaly Detection (Isolation Forest)"), sp(2), hr_ml(), sp(3)]

        ml_status  = ml_result.get("ml_status", "unknown")
        ml_score   = ml_result.get("anomaly_score", 0.0)
        ml_flag    = ml_result.get("anomaly_detected", False)
        ml_conf    = ml_result.get("confidence", "none")
        ml_boost   = ml_result.get("risk_contribution", 0)
        ml_explain = ml_result.get("explanation", "")

        verdict_color = COLOR_ML_BAD if ml_flag else COLOR_ML_GOOD
        verdict_text  = "⚠  ANOMALY DETECTED" if ml_flag else "✓  NORMAL BEHAVIOUR"

        # Score bar (text-based progress representation)
        bar_filled = int(ml_score * 20)
        bar_empty  = 20 - bar_filled
        score_bar  = "█" * bar_filled + "░" * bar_empty

        ml_rows = [
            ["Verdict",          verdict_text],
            ["Anomaly Score",    f"{ml_score:.4f}   [{score_bar}]   (0.0=normal → 1.0=anomalous)"],
            ["Confidence",       ml_conf.upper()],
            ["Risk Contribution",f"+{ml_boost} points added to final risk score"],
            ["ML Status",        ml_status.upper()],
            ["Analysis",         ml_explain],
        ]

        # Add training info if present
        if ml_result.get("events_collected") is not None:
            needed = ml_result.get("events_needed", 0)
            total  = ml_result.get("events_collected", 0)
            ml_rows.append(["Training Data", f"{total} events collected" +
                             (f" ({needed} more needed)" if needed > 0 else " — model active")])

        ml_tbl = Table(ml_rows, colWidths=[45*mm, 125*mm])
        ml_style = TableStyle([
            ("FONTSIZE",      (0, 0), (-1,-1), 9),
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR",     (0, 0), (0, -1), COLOR_DARK),
            ("ROWBACKGROUNDS",(0, 0), (-1,-1), [colors.white, COLOR_LIGHT]),
            ("GRID",          (0, 0), (-1,-1), 0.3, COLOR_GRAY),
            ("LEFTPADDING",   (0, 0), (-1,-1), 8),
            ("TOPPADDING",    (0, 0), (-1,-1), 5),
            ("BOTTOMPADDING", (0, 0), (-1,-1), 5),
            ("VALIGN",        (0, 0), (-1,-1), "TOP"),
            # Colour the verdict cell
            ("TEXTCOLOR",     (1, 0), (1, 0), verdict_color),
            ("FONTNAME",      (1, 0), (1, 0), "Helvetica-Bold"),
        ])
        ml_tbl.setStyle(ml_style)
        story += [ml_tbl, sp(4)]

        # Feature vector breakdown
        features = ml_result.get("features")
        if features:
            story += [h3("Feature Vector (10 dimensions fed to Isolation Forest)"), sp(2)]
            feat_rows = [["Feature", "Value", "Description"]]
            feat_descriptions = {
                "source_ip_int":      "Source IP as 32-bit integer",
                "dest_ip_int":        "Destination IP as 32-bit integer",
                "source_port":        "Source port number",
                "dest_port":          "Destination port number",
                "protocol_encoded":   "TCP=1, UDP=2, ICMP=3, other=0",
                "is_private_source":  "1 if source IP is RFC-1918 private",
                "is_private_dest":    "1 if destination IP is RFC-1918 private",
                "port_ratio":         "src_port / (dst_port + 1)",
                "dest_port_category": "1=web, 2=db, 3=admin/backdoor, 4=mail, 0=other",
                "hour_of_day":        "Hour (0-23 UTC) from event timestamp",
            }
            for k, v in features.items():
                feat_rows.append([
                    k,
                    str(round(float(v), 4)) if v is not None else "N/A",
                    feat_descriptions.get(k, ""),
                ])
            feat_tbl = Table(feat_rows, colWidths=[45*mm, 25*mm, 100*mm])
            feat_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), COLOR_DARK),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1,-1), 8),
                ("ROWBACKGROUNDS",(0, 1), (-1,-1), [colors.white, COLOR_LIGHT]),
                ("GRID",          (0, 0), (-1,-1), 0.3, COLOR_GRAY),
                ("LEFTPADDING",   (0, 0), (-1,-1), 6),
                ("TOPPADDING",    (0, 0), (-1,-1), 4),
                ("BOTTOMPADDING", (0, 0), (-1,-1), 4),
            ]))
            story += [feat_tbl, sp(4)]

    # ── Recommendations ──────────────────────────────────────────────────
    story.append(h2("Recommended Actions"))
    story.append(sp(2))

    if results:
        ips  = list({r.get("matched_ip") for r in results})
        sevs = [r.get("severity", "Low") for r in results]
        recs = [
            f"Investigate immediately: <b>{', '.join(ips)}</b>",
            "Block identified IPs at perimeter firewall and WAF.",
            "Perform endpoint forensic scan on affected hosts.",
            "Review proxy and firewall logs for additional connections.",
            "Escalate to Tier-2 SOC analyst if severity is High or Critical.",
        ]
        if "Critical" in sevs:
            recs.insert(0, "🚨 <b>CRITICAL</b>: Initiate incident response procedure immediately.")
    elif ml_anomaly:
        recs = [
            "⚠ Investigate the anomalous traffic pattern — no known IOC match but behaviour is suspicious.",
            "Cross-reference source/destination IPs with threat intelligence feeds.",
            "Review firewall and proxy logs for similar patterns.",
            "Consider adding this IP to a watchlist for ongoing monitoring.",
        ]
    else:
        recs = [
            "Continue standard network monitoring.",
            "Ensure IOC feeds are updated regularly.",
            "No immediate escalation required.",
        ]

    for rec in recs:
        story += [body(f"• {rec}"), sp(1)]

    # ── Footer ───────────────────────────────────────────────────────────
    story += [
        sp(5), hr(), sp(3),
        body(
            f'<i>Auto-generated by STIX 2.1 Threat Intelligence Platform — '
            f'Report ID: {event.get("event_id", "N/A")} — '
            f'{datetime.now().strftime("%Y-%m-%d")}</i>'
        ),
    ]

    doc.build(story)
    logger.info("Report generated", filename=file_name)
    return file_name