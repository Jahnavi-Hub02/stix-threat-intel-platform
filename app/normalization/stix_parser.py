"""
app/normalization/stix_parser.py
Parses STIX 2.1 JSON bundles into normalised IOC dicts ready for DB insert.
Handles pattern extraction for: ipv4-addr, domain-name, url, file-hash, email-addr.
"""
import re, logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Regex to extract type and value from STIX patterns like:
#   [ipv4-addr:value = '185.220.101.45']
#   [domain-name:value = 'evil.com']
#   [url:value = 'http://evil.com/payload']
#   [file:hashes.'SHA-256' = 'abc123...']
PATTERN_RE = re.compile(
    r"\[(\w[\w-]*\w):(?:value|hashes\.'[\w-]+')\s*=\s*['\"]([^'\"]+)['\"]\]",
    re.IGNORECASE,
)

SEVERITY_MAP = {range(90, 101): "critical", range(70, 90): "high",
                range(40, 70):  "medium",   range(0, 40):  "low"}

def _confidence_to_severity(confidence: int) -> str:
    for r, sev in SEVERITY_MAP.items():
        if confidence in r:
            return sev
    return "low"

def _parse_pattern(pattern: str):
    """Extract (ioc_type, ioc_value) from a STIX indicator pattern string."""
    m = PATTERN_RE.search(pattern or "")
    if not m:
        return None, None
    raw_type  = m.group(1).lower()
    ioc_value = m.group(2).strip()
    type_map  = {"ipv4-addr":"ipv4-addr","domain-name":"domain-name",
                 "url":"url","file":"file-hash","email-addr":"email-addr"}
    return type_map.get(raw_type, raw_type), ioc_value

def parse_stix_bundle(bundle: Dict[str, Any]) -> List[Dict]:
    """
    Parse a STIX 2.1 bundle dict and return a list of normalised IOC dicts.
    Only processes objects with type == "indicator".
    """
    objects    = bundle.get("objects", [])
    indicators = [o for o in objects if o.get("type") == "indicator"]
    iocs       = []

    for obj in indicators:
        try:
            ioc_type, ioc_value = _parse_pattern(obj.get("pattern", ""))
            if not ioc_type or not ioc_value:
                continue

            confidence = int(obj.get("confidence", 50))
            iocs.append({
                "stix_id":    obj.get("id", ""),
                "ioc_type":   ioc_type,
                "ioc_value":  ioc_value,
                "confidence": confidence,
                "severity":   _confidence_to_severity(confidence),
                "source":     obj.get("created_by_ref", "unknown"),
                "first_seen": obj.get("valid_from", ""),
                "last_seen":  obj.get("valid_until", ""),
                "tags":       ",".join(obj.get("labels", [])),
            })
        except Exception as e:
            logger.debug("Skipping indicator %s: %s", obj.get("id","?"), e)

    logger.info("Parsed %d IOCs from %d indicator objects", len(iocs), len(indicators))
    return iocs


def parse_stix_file_json(filepath: str) -> List[Dict]:
    """Parse a STIX 2.1 JSON file from disk."""
    import json
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return parse_stix_bundle(data)


def parse_stix_file_xml(filepath: str) -> List[Dict]:
    """
    Parse a STIX 1.x XML file (legacy format).
    Extracts observable IPs and domains and normalises to same IOC dict format.
    """
    import xml.etree.ElementTree as ET
    tree = ET.parse(filepath)
    root = tree.getroot()
    ns   = {"cybox": "http://cybox.mitre.org/cybox-2",
            "addr":  "http://cybox.mitre.org/objects#AddressObject-2",
            "dn":    "http://cybox.mitre.org/objects#DomainNameObject-1"}
    iocs = []
    for ip in root.findall(".//addr:Address_Value", ns):
        val = (ip.text or "").strip()
        if val:
            iocs.append({"stix_id":"","ioc_type":"ipv4-addr","ioc_value":val,
                         "confidence":50,"severity":"medium","source":"xml-file",
                         "first_seen":"","last_seen":"","tags":""})
    for dn in root.findall(".//dn:Value", ns):
        val = (dn.text or "").strip()
        if val:
            iocs.append({"stix_id":"","ioc_type":"domain-name","ioc_value":val,
                         "confidence":50,"severity":"medium","source":"xml-file",
                         "first_seen":"","last_seen":"","tags":""})
    return iocs
