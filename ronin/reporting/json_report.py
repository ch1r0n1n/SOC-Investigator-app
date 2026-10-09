from __future__ import annotations

import json
import re
from pathlib import Path


def save_report(report: dict, directory: str | Path = "reports/investigations") -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", report["indicator"])[:100]
    path = directory / f"{safe}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return path
