from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$"
)
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def classify_ioc(value: str) -> tuple[str, str]:
    value = value.strip()
    if not value:
        raise ValueError("IOC cannot be empty")

    parsed = urlparse(value)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        return "url", value

    try:
        ip = ipaddress.ip_address(value)
        return ("ipv4" if ip.version == 4 else "ipv6"), str(ip)
    except ValueError:
        pass

    compact = value.lower()
    if len(compact) in HASH_LENGTHS and HEX_RE.fullmatch(compact):
        return HASH_LENGTHS[len(compact)], compact

    domain = value.rstrip(".").lower()
    if DOMAIN_RE.fullmatch(domain):
        return "domain", domain

    raise ValueError(f"Unsupported or invalid IOC: {value}")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
