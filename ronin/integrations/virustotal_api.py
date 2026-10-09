from urllib.parse import urlparse
import base64
from .base import request_json

BASE = "https://www.virustotal.com/api/v3"


def lookup(value: str, ioc_type: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    if ioc_type in {"ipv4", "ipv6"}:
        endpoint = f"ip_addresses/{value}"
    elif ioc_type == "domain":
        endpoint = f"domains/{value}"
    elif ioc_type in {"md5", "sha1", "sha256"}:
        endpoint = f"files/{value}"
    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        endpoint = f"urls/{url_id}"
    else:
        raise ValueError(f"Unsupported VirusTotal IOC type: {ioc_type}")

    data = request_json("GET", f"{BASE}/{endpoint}", headers=headers)
    attrs = data.get("data", {}).get("attributes", {})
    return {
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": attrs.get("last_analysis_stats", {}),
        "categories": attrs.get("categories", {}),
        "meaningful_name": attrs.get("meaningful_name"),
    }
