"""
app/normalization/parser_xml.py
================================
LEGACY — retained for backward compatibility with static XML sample files.

The mentor-preferred ingestion path is STIX 2.x JSON via taxii2client.
Use stix_parser.parse_stix_bundle() for all new JSON-format data.
Use this module ONLY when the source is a STIX 1.x / CybOX XML file.
"""
import xml.etree.ElementTree as ET
import re


def parse_stix_xml(file_path: str) -> list:
    """
    Parse a STIX 1.x / CybOX XML feed and extract IPv4 and domain indicators.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[Parser XML] File not found: {file_path}")
        return []
    except Exception as e:
        print(f"[Parser XML] Read error: {e}")
        return []

    try:
        root = ET.fromstring(f"<root>{content}</root>")
    except ET.ParseError as e:
        print(f"[Parser XML] Parse error: {e}")
        return []

    indicators = []
    seen = set()

    for elem in root.iter():
        tag = (elem.tag or "").lower()
        text = (elem.text or "").strip()

        if not text:
            continue

        if "address_value" in tag:
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", text) and text not in seen:
                seen.add(text)
                indicators.append({
                    "stix_id": "xml-generated", "ioc_type": "ipv4",
                    "ioc_subtype": "network", "ioc_value": text,
                    "confidence": 60, "source": "XML Feed"
                })

        elif "domain" in tag and "." in text:
            if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", text) and text not in seen:
                seen.add(text)
                indicators.append({
                    "stix_id": "xml-generated", "ioc_type": "domain",
                    "ioc_subtype": "network", "ioc_value": text,
                    "confidence": 60, "source": "XML Feed"
                })

    print(f"[Parser XML] {len(indicators)} indicators extracted.")
    return indicators