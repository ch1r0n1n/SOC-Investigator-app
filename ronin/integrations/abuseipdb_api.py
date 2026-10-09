from .base import request_json


def lookup_ip(ip: str, api_key: str) -> dict:
    data = request_json(
        "GET",
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
    ).get("data", {})
    return {
        "ip": data.get("ipAddress", ip),
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
    }
