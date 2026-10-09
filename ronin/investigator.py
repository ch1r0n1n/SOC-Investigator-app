from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable
# Now that the API keys are saved we call the modules.
from .config import Settings
from .integrations import abuseipdb_api, censys_api, certspotter_api, shodan_api, virustotal_api
from .integrations.base import IntegrationError
from .validators import classify_ioc


def provider_plan(ioc_type: str) -> list[str]:
    if ioc_type in {"ipv4", "ipv6"}:
        return ["virustotal", "shodan", "censys", "abuseipdb"]
    if ioc_type == "domain":
        return ["virustotal", "certspotter"]
    if ioc_type == "url":
        return ["virustotal"]
    if ioc_type in {"md5", "sha1", "sha256"}:
        return ["virustotal"]
    return []


def investigate(value: str, settings: Settings) -> dict:
    ioc_type, normalized = classify_ioc(value)
    report = {
        "indicator": normalized,
        "type": ioc_type,
        "investigated_at": datetime.now(timezone.utc).isoformat(),
        "results": {},
    }

    calls: dict[str, Callable[[], dict]] = {
        "virustotal": lambda: virustotal_api.lookup(normalized, ioc_type, settings.virustotal_api_key),
        "shodan": lambda: shodan_api.lookup_ip(normalized, settings.shodan_api_key),
        "censys": lambda: censys_api.lookup_ip(normalized, settings.censys_api_id, settings.censys_api_secret),
        "certspotter": lambda: certspotter_api.lookup_domain(normalized, settings.certspotter_api_key),
        "abuseipdb": lambda: abuseipdb_api.lookup_ip(normalized, settings.abuseipdb_api_key),
    }

    for provider in provider_plan(ioc_type):
        # Cert Spotter can be queried without a key; a key is still supported for higher limits.
        configured = settings.configured(provider) or provider == "certspotter"
        if not configured:
            report["results"][provider] = {"status": "skipped", "reason": "API credentials not configured"}
            continue
        try:
            report["results"][provider] = {"status": "ok", "data": calls[provider]()}
        except (IntegrationError, ValueError) as exc:
            report["results"][provider] = {"status": "error", "error": str(exc)}

    report["risk"] = score_report(report)
    return report


def score_report(report: dict) -> dict:
    score = 0
    reasons: list[str] = []
    results = report.get("results", {})

    vt = results.get("virustotal", {}).get("data", {})
    stats = vt.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    if malicious:
        points = min(60, malicious * 5)
        score += points
        reasons.append(f"VirusTotal: {malicious} malicious detections")
    if suspicious:
        score += min(15, suspicious * 3)
        reasons.append(f"VirusTotal: {suspicious} suspicious detections")

    abuse = results.get("abuseipdb", {}).get("data", {})
    confidence = int(abuse.get("abuse_confidence_score", 0) or 0)
    if confidence:
        score += round(confidence * 0.4)
        reasons.append(f"AbuseIPDB confidence: {confidence}%")

    score = min(100, score)
    level = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    return {"score": score, "level": level, "reasons": reasons}
