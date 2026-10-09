# RONIN IOC Investigator

A small Python SOC investigation tool that classifies indicators, routes them to relevant intelligence providers, normalizes results, calculates a transparent risk score, and saves a JSON investigation report.

## Supported indicators

- IPv4 / IPv6
- Domains
- HTTP/HTTPS URLs
- MD5, SHA-1, SHA-256 hashes

## Integrations

- VirusTotal
- Shodan
- Censys
- Cert Spotter
- AbuseIPDB

Providers are called only when relevant to the IOC type. Missing API credentials are skipped instead of crashing the investigation.

## Setup

```bash
python -m venv .venv
# Windows
.venv\\Scripts\\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

Copy the example configuration:

```bash
# Windows
copy config.example.ini config.ini
# macOS/Linux
cp config.example.ini config.ini
```

Add your API credentials to `config.ini`. **Never commit `config.ini`.** Environment variables with the same names can also be used and take precedence.

## Usage

Interactive:

```bash
python main.py
```

Direct investigation:

```bash
python main.py 8.8.8.8
python main.py example.com
python main.py https://example.com/login
```

Classification only (no network/API calls):

```bash
python main.py --classify 8.8.8.8
```

Run tests:

```bash
pytest -q
```

## Security notes

- Real credentials belong only in `config.ini` or environment variables.
- `config.ini` is ignored by Git.
- Reports are ignored by default because investigation data may be sensitive.
- API errors are captured per provider so one failed service does not terminate the investigation.

## Roadmap

Potential next releases: URLScan/OTX/GreyNoise, RDAP/DNS enrichment, bulk IOC import, analyst recommendations, MITRE ATT&CK mapping, HTML reports, case history, async provider calls, and a desktop/web UI.

## Responsible use

Use the tool for defensive security investigations and systems/data you are authorized to analyze. Third-party APIs have their own terms, quotas, and acceptable-use policies.
