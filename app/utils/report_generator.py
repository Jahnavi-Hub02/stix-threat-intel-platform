from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.units import mm
from datetime import datetime
import os


# ─────────────────────────────────────────────
# Color palette for the report
# ─────────────────────────────────────────────
COLOR_DARK = colors.HexColor("#1A1A2E")
COLOR_ACCENT = colors.HexColor("#E94560")
COLOR_LIGHT_GRAY = colors.HexColor("#F4F4F4")
COLOR_MED_GRAY = colors.HexColor("#CCCCCC")

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#C0392B"),
    "High": colors.HexColor("#E67E22"),
    "Medium": colors.HexColor("#F1C40F"),
    "Low": colors.HexColor("#27AE60"),
}


def _severity_color(severity: str):
    return SEVERITY_COLORS.get(severity, colors.gray)


def generate_report(event: dict, results: list, output_dir: str = ".") -> str:
    """
    Generate a professional multi-section PDF threat intelligence report.

    Handles any number of results with automatic page overflow.
    Returns the path to the generated PDF.
    """
    os.makedirs(output_dir, exist_ok=True)
    file_name = os.path.join(output_dir, f"Threat_Report_{event['event_id']}.pdf")

    doc = SimpleDocTemplate(
        file_name,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm
    )

    styles = getSampleStyleSheet()
    story = []

    # ── Helper builders ──────────────────────────────────────────────────────

    def h1(text):
        return Paragraph(f'<font size="18" color="#1A1A2E"><b>{text}</b></font>', styles["Normal"])

    def h2(text):
        return Paragraph(f'<font size="13" color="#1A1A2E"><b>{text}</b></font>', styles["Normal"])

    def body(text):
        return Paragraph(f'<font size="10">{text}</font>', styles["Normal"])

    def divider():
        return HRFlowable(width="100%", thickness=0.5, color=COLOR_MED_GRAY)

    def spacer(h=6):
        return Spacer(1, h * mm)

    # ── Cover Header ─────────────────────────────────────────────────────────
    story.append(spacer(4))
    story.append(h1("🛡  Threat Intelligence Report"))
    story.append(spacer(2))
    story.append(body(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"))
    story.append(body(f"<b>Platform:</b> STIX 2.1 Threat Correlation System"))
    story.append(spacer(4))
    story.append(divider())
    story.append(spacer(4))

    # ── Executive Summary ────────────────────────────────────────────────────
    story.append(h2("Executive Summary"))
    story.append(spacer(2))

    if results:
        severities = [r.get("severity", "Low") for r in results]
        top_severity = "Critical" if "Critical" in severities else \
                       "High" if "High" in severities else \
                       "Medium" if "Medium" in severities else "Low"
        summary_text = (
            f"<b>{len(results)} threat indicator(s)</b> matched during correlation. "
            f"Highest severity detected: <b>{top_severity}</b>. "
            f"Immediate investigation is recommended."
        )
    else:
        summary_text = (
            "No indicators of compromise were detected for the submitted event. "
            "The network activity appears benign based on current threat intelligence."
        )

    story.append(body(summary_text))
    story.append(spacer(5))

    # ── Event Details ────────────────────────────────────────────────────────
    story.append(h2("Event Details"))
    story.append(spacer(2))

    event_data = [
        ["Field", "Value"],
        ["Event ID", event.get("event_id", "N/A")],
        ["Source IP", event.get("source_ip", "N/A")],
        ["Destination IP", event.get("destination_ip", "N/A")],
        ["Source Port", str(event.get("source_port", "N/A"))],
        ["Destination Port", str(event.get("destination_port", "N/A"))],
        ["Protocol", event.get("protocol", "N/A")],
        ["Timestamp", event.get("timestamp", "N/A")],
    ]

    event_table = Table(event_data, colWidths=[55 * mm, 115 * mm])
    event_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 1), (-1, -1), COLOR_LIGHT_GRAY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_GRAY]),
        ("GRID", (0, 0), (-1, -1), 0.3, COLOR_MED_GRAY),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(event_table)
    story.append(spacer(6))

    # ── Correlation Results ──────────────────────────────────────────────────
    story.append(h2("Correlation Results"))
    story.append(spacer(2))

    if results:
        result_data = [[
            "Matched IP", "Match Type", "Decision",
            "Risk Score", "Severity", "MITRE Tactic"
        ]]

        for r in results:
            result_data.append([
                r.get("matched_ip", "N/A"),
                r.get("match_type", "N/A").replace("_", " ").title(),
                r.get("decision", "N/A"),
                f"{r.get('risk_score', 0.0):.1f} / 100",
                r.get("severity", "Low"),
                r.get("mitre_tactic", "N/A"),
            ])

        result_table = Table(result_data, colWidths=[30*mm, 27*mm, 40*mm, 22*mm, 20*mm, 31*mm])

        # Build per-row severity colors
        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, COLOR_MED_GRAY),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_GRAY]),
        ]

        for i, r in enumerate(results, start=1):
            sev_color = _severity_color(r.get("severity", "Low"))
            table_style.append(("TEXTCOLOR", (4, i), (4, i), sev_color))
            table_style.append(("FONTNAME", (4, i), (4, i), "Helvetica-Bold"))

        result_table.setStyle(TableStyle(table_style))
        story.append(result_table)

    else:
        story.append(body("✅ No IOC matches found. Activity classified as <b>Benign</b>."))

    story.append(spacer(6))

    # ── MITRE ATT&CK Detail ──────────────────────────────────────────────────
    if results:
        story.append(h2("MITRE ATT&CK Mapping"))
        story.append(spacer(2))

        seen_tactics = set()
        for r in results:
            tactic = r.get("mitre_tactic", "N/A")
            technique = r.get("mitre_technique", "N/A")

            if tactic not in seen_tactics:
                seen_tactics.add(tactic)
                story.append(body(f"<b>Tactic:</b> {tactic}"))
                story.append(body(f"<b>Technique:</b> {technique}"))
                story.append(spacer(2))

        story.append(spacer(4))

    # ── Recommended Actions ──────────────────────────────────────────────────
    story.append(h2("Recommended Actions"))
    story.append(spacer(2))

    if results:
        severities = [r.get("severity", "Low") for r in results]
        matched_ips = list({r.get("matched_ip") for r in results})

        recommendations = [
            f"Immediately investigate the following IP(s): <b>{', '.join(matched_ips)}</b>",
            "Block identified IPs at the perimeter firewall and WAF.",
            "Perform endpoint forensic scan on hosts that communicated with matched IPs.",
            "Review firewall and proxy logs for additional connections to these IPs.",
            "Escalate to Tier-2 SOC analyst if severity is High or Critical.",
        ]

        if "Critical" in severities:
            recommendations.insert(0, "🚨 <b>CRITICAL ALERT</b>: Initiate incident response procedure immediately.")

        for rec in recommendations:
            story.append(body(f"• {rec}"))
            story.append(spacer(1))
    else:
        recs = [
            "Continue standard monitoring of network activity.",
            "Ensure IOC feeds are updated regularly (recommended: every 30 minutes).",
            "No immediate escalation required for this event."
        ]
        for rec in recs:
            story.append(body(f"• {rec}"))
            story.append(spacer(1))

    story.append(spacer(5))
    story.append(divider())
    story.append(spacer(3))
    story.append(body(
        f'<i>This report was auto-generated by the STIX 2.1 Threat Intelligence Correlation Platform. '
        f'Report ID: {event.get("event_id", "N/A")} — {datetime.now().strftime("%Y-%m-%d")}</i>'
    ))

    # ── Build PDF ────────────────────────────────────────────────────────────
    doc.build(story)
    print(f"[Report] PDF generated: {file_name}")
    return file_name
