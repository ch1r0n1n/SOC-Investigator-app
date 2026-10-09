from __future__ import annotations

import configparser
import os
from dataclasses import dataclass
from pathlib import Path

# We drop the API keys down hurr
@dataclass(frozen=True)
class Settings:
    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    certspotter_api_key: str = ""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    def configured(self, provider: str) -> bool:
        provider = provider.lower()
        required = {
            "shodan": (self.shodan_api_key,),
            "censys": (self.censys_api_id, self.censys_api_secret),
            "certspotter": (self.certspotter_api_key,),
            "virustotal": (self.virustotal_api_key,),
            "abuseipdb": (self.abuseipdb_api_key,),
        }
        return all(required.get(provider, ()))


def load_settings(path: str | Path = "config.ini") -> Settings:
    parser = configparser.ConfigParser()
    path = Path(path)
    if path.exists():
        parser.read(path)

    section = parser["API_KEYS"] if parser.has_section("API_KEYS") else {}

    def get(name: str) -> str:
        # Environment variables take precedence over config.ini.
        return os.getenv(name, section.get(name, "")).strip()

    return Settings(
        shodan_api_key=get("SHODAN_API_KEY"),
        censys_api_id=get("CENSYS_API_ID"),
        censys_api_secret=get("CENSYS_API_SECRET"),
        certspotter_api_key=get("CERTSPOTTER_API_KEY"),
        virustotal_api_key=get("VIRUSTOTAL_API_KEY"),
        abuseipdb_api_key=get("ABUSEIPDB_API_KEY"),
    )
