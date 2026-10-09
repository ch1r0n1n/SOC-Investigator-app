from .base import request_json


def lookup_ip(ip: str, api_id: str, api_secret: str) -> dict:
    data = request_json(
        "GET", f"https://search.censys.io/api/v2/hosts/{ip}", auth=(api_id, api_secret)
    )
    result = data.get("result", {})
    services = result.get("services", []) or []
    return {
        "ip": result.get("ip", ip),
        "location": result.get("location", {}),
        "autonomous_system": result.get("autonomous_system", {}),
        "services": [
            {"port": s.get("port"), "service_name": s.get("service_name"), "transport_protocol": s.get("transport_protocol")}
            for s in services
        ],
    }
