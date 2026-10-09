from __future__ import annotations

from typing import Any
import requests


class IntegrationError(RuntimeError):
    pass


def request_json(method: str, url: str, *, timeout: int = 15, **kwargs: Any) -> Any:
    try:
        response = requests.request(method, url, timeout=timeout, **kwargs)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        raise IntegrationError(str(exc)) from exc
    except ValueError as exc:
        raise IntegrationError("Provider returned invalid JSON") from exc
