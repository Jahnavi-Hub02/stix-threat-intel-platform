import json
import re


def _extract_from_pattern(pattern: str):
    """Extract (ioc_type, ioc_subtype, ioc_value) from a STIX pattern string."""
    extractors = [
        (r"ipv4-addr:value\s*=\s*'([^']+)'",          "ipv4",   "network"),
        (r"domain-name:value\s*=\s*'([^']+)'",         "domain", "network"),
        (r"url:value\s*=\s*'([^']+)'",                 "url",    "network"),
        (r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'",   "sha256", "file_hash"),
        (r"file:hashes\.MD5\s*=\s*'([^']+)'",          "md5",    "file_hash"),
    ]
    for pattern_re, ioc_type, subtype in extractors:
        m = re.search(pattern_re, pattern)
        if m:
            return ioc_type, subtype, m.group(1)
    return None, None, None


def parse_stix_json(file_path: str) -> list:
    """
    Parse a STIX 2.x JSON bundle and extract all supported indicators.
    Supports: IPv4, domain, URL, SHA-256, MD5.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[Parser JSON] File not found: {file_path}")
        return []
    except json.JSONDecodeError as e:
        print(f"[Parser JSON] Invalid JSON: {e}")
        return []

    indicators = []
    skipped = 0

    for obj in data.get("objects", []):
        if obj.get("type") != "indicator":
            continue

        pattern = obj.get("pattern", "")
        if not pattern:
            skipped += 1
            continue

        ioc_type, ioc_subtype, ioc_value = _extract_from_pattern(pattern)

        if ioc_value:
            indicators.append({
                "stix_id":     obj.get("id", "unknown"),
                "ioc_type":    ioc_type,
                "ioc_subtype": ioc_subtype,
                "ioc_value":   ioc_value,
                "confidence":  obj.get("confidence", 50),
                "source":      "JSON Feed"
            })
        else:
            skipped += 1

    print(f"[Parser JSON] {len(indicators)} indicators extracted, {skipped} skipped.")
    return indicators
