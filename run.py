"""
STIX 2.1 Threat Intelligence Correlation Platform — CLI Runner
==============================================================
Run this directly to:
  1. Initialize the database
  2. Ingest IOCs from JSON + XML feeds
  3. Correlate a sample event
  4. Generate a PDF report

Usage:
    python run.py
"""

import json
import os
from app.database import create_tables, insert_indicators
from app.normalization import parse_stix_json, parse_stix_xml
from app.correlation import correlate_event
from app.utils import generate_report, get_logger

logger = get_logger(__name__)


BANNER = """
╔══════════════════════════════════════════════════════════╗
║   STIX 2.1 Threat Intelligence Correlation Platform      ║
║   Version 2.5.0                                          ║
╚══════════════════════════════════════════════════════════╝
"""


def run():
    print(BANNER)

    # ── Step 1: Initialize DB ────────────────────────────────────────────────
    print("=" * 55)
    print("[1/4] Initializing database tables...")
    create_tables()
    print("  ✓ Database tables created/verified")

    # ── Step 2: Ingest IOC feeds ─────────────────────────────────────────────
    print("\n[2/4] Ingesting threat intelligence feeds...")

    json_path = "data/TI_GOV.json"
    xml_path = "data/certin_ti_gov.xml"

    json_indicators = []
    xml_indicators = []

    if os.path.exists(json_path):
        json_indicators = parse_stix_json(json_path)
        print(f"  JSON feed: {len(json_indicators)} indicators extracted")
    else:
        print(f"  JSON feed: NOT FOUND ({json_path})")

    if os.path.exists(xml_path):
        xml_indicators = parse_stix_xml(xml_path)
        print(f"  XML feed: {len(xml_indicators)} indicators extracted")
    else:
        print(f"  XML feed: NOT FOUND ({xml_path})")

    all_indicators = json_indicators + xml_indicators
    print(f"  Total indicators: {len(all_indicators)}")

    if all_indicators:
        result = insert_indicators(all_indicators) or {"stored": 0, "duplicates": 0}
        print(f"  DB result → Stored: {result['stored']}, Duplicates skipped: {result['duplicates']}")

    # ── Step 3: Correlate sample event ───────────────────────────────────────
    print("\n[3/4] Correlating sample event...")

    sample_event = {
        "event_id": "evt-001",
        "source_ip": "185.220.101.45",
        "destination_ip": "192.168.1.100",
        "timestamp": "2024-01-15T14:32:00Z"
    }

    print(f"  Event: {sample_event['event_id']}")
    print(f"    Source:      {sample_event['source_ip']}")
    print(f"    Destination: {sample_event['destination_ip']}")

    results = correlate_event(sample_event)

    if results:
        print(f"  ✓ {len(results)} match(es) found!")
        for r in results:
            print(f"    - {r['matched_ip']} ({r['match_type']}): {r['decision']}")
    else:
        print(f"  ✗ No matches found")

    # ── Step 4: Generate report ──────────────────────────────────────────────
    print("\n[4/4] Generating threat report...")
    report_file = generate_report(sample_event, results)
    print(f"  ✓ Report created: {report_file}")

    print("\n" + "=" * 55)
    print("✓ Pipeline complete!")


if __name__ == "__main__":
    run()