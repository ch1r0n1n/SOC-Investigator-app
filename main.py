from __future__ import annotations

import argparse
import json
import sys

from ronin.config import load_settings
from ronin.investigator import investigate
from ronin.reporting.json_report import save_report
from ronin.validators import classify_ioc

BANNER = r"""
================================================
             RONIN IOC INVESTIGATOR
================================================
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Multi-source IOC enrichment for SOC investigations")
    parser.add_argument("ioc", nargs="?", help="IP, domain, URL, MD5, SHA-1, or SHA-256")
    parser.add_argument("--config", default="config.ini", help="Path to config.ini")
    parser.add_argument("--classify", action="store_true", help="Classify only; do not call APIs")
    parser.add_argument("--no-save", action="store_true", help="Do not save the JSON report")
    args = parser.parse_args()

    print(BANNER)
    value = args.ioc or input("Enter IOC: ").strip()

    try:
        if args.classify:
            kind, normalized = classify_ioc(value)
            print(json.dumps({"indicator": normalized, "type": kind}, indent=2))
            return 0

        report = investigate(value, load_settings(args.config))
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    print(f"Indicator: {report['indicator']}")
    print(f"Type:      {report['type'].upper()}")
    print("\nProviders:")
    for provider, result in report["results"].items():
        print(f"  {provider:<12} {result['status'].upper()}")

    risk = report["risk"]
    print(f"\nRisk Score: {risk['score']}/100 ({risk['level']})")
    for reason in risk["reasons"]:
        print(f"  - {reason}")

    if not args.no_save:
        path = save_report(report)
        print(f"\nReport saved: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
