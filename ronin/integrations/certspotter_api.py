from .base import request_json


def lookup_domain(domain: str, api_key: str = "") -> dict:
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    data = request_json(
        "GET",
        "https://api.certspotter.com/v1/issuances",
        headers=headers,
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names,issuer"},
    )
    names = sorted({name for cert in data for name in cert.get("dns_names", []) if isinstance(name, str)})
    return {"certificate_count": len(data), "dns_names": names[:200]}
