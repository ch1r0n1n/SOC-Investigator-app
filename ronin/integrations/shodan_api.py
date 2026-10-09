from .base import request_json


def lookup_ip(ip: str, api_key: str) -> dict:
    data = request_json("GET", f"https://api.shodan.io/shodan/host/{ip}", params={"key": api_key})
    return {
        "ip": data.get("ip_str", ip),
        "organization": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "country": data.get("country_name"),
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "vulnerabilities": sorted(list(data.get("vulns", []))) if isinstance(data.get("vulns"), (list, dict)) else [],
    }
