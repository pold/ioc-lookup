# IOC Screenshot Tool

Takes a list of IOCs (IPs, file hashes, domains, URLs), looks them up on
**VirusTotal** (via [vt-cli](https://github.com/virustotal/vt-cli)) and
**AbuseIPDB**, and produces:

- a **results CSV** – one row per IOC, and
- **PNG screenshots** of each result page, for evidence in reports and tickets.

## Results CSV

| Column | Content |
|---|---|
| `IOCs` | The indicator |
| `Type` | `IP`, `MD5`, `SHA1`, `SHA256`, `Domain`, `URL` or `Unknown` |
| `VirusTotal` | Detections as `malicious/total` (e.g. `10/92`), `Not found`, or `N/A` |
| `VT Link` | VirusTotal GUI link for the IOC |
| `AbuseIPDB` | `score% (N reports)` with an API key, otherwise `N/A`; empty for non-IPs |
| `AbuseIPDB link` | AbuseIPDB check page; empty for non-IPs |
| `VT Labels` | What flagging vendors call it, e.g. `phishing (6); malware (3)` |
| `VT Category` | Domain/URL categories, or a file's suggested threat label (e.g. `trojan.emotet/heodo`) |
| `VT Reputation` | VirusTotal community score (negative = bad) |
| `VT Tags` | VirusTotal tags (e.g. `peexe`, `via-tor`) |
| `Country` | Country code (IPs, domains) |
| `AS Owner` | `AS<number> <owner>` (IPs) |
| `Network` | CIDR block (IPs) |
| `File Info` | `type | name | size` (file hashes) |
| `VT Last Analysis` | Date of the last VirusTotal scan (UTC) |
| `AbuseIPDB ISP` | ISP name |
| `AbuseIPDB Usage Type` | e.g. `Data Center/Web Hosting/Transit` |
| `Tor Exit Node` | `Yes` / `No` |
| `AbuseIPDB Last Reported` | Date of the most recent abuse report |

The `VT …`, `Country`, `AS Owner`, `Network` and `File Info` columns need vt-cli
with an API key (empty on the web-page fallback); the `AbuseIPDB …` detail
columns need an AbuseIPDB key.

Where the numbers come from:

- **VirusTotal** – `vt-cli` (`last_analysis_stats`). If vt-cli isn't installed,
  has no API key, or errors, the score is read from the VirusTotal web page
  loaded for the screenshot instead.
- **AbuseIPDB** – the AbuseIPDB v2 API (`ABUSEIPDB_API_KEY`). The web page is
  behind Cloudflare, so without a key the column is `N/A`.

## Requirements

- Python 3.10+
- Playwright + Chromium (for screenshots)
- vt-cli + a VirusTotal API key (recommended)

```bash
pip install playwright playwright-stealth
playwright install chromium

brew install virustotal-cli        # or build from github.com/virustotal/vt-cli
```

`playwright-stealth` is optional (1.x and 2.x are both supported) but helps
avoid bot detection.

### API keys (`.env`)

Copy `.env.example` to `.env` (next to `screenshooter.py`, git-ignored) and fill in:

```ini
ABUSEIPDB_API_KEY=your-abuseipdb-key
VTCLI_APIKEY=your-virustotal-key
```

Precedence: command-line flag (`--abuseipdb-key`, `--vt-key`) → real environment
variable → `.env` → `~/.vt.toml` (VirusTotal only, from `vt init`).

## Usage

```bash
# IOCs from a CSV file (first column by default) → screenshots + log/iocs_results.csv
python3 screenshooter.py --csv log/iocs.csv

# Results CSV only, no browser (fast; needs vt-cli with an API key)
python3 screenshooter.py --csv log/iocs.csv --no-screenshots

# Pick the CSV column by header name or 0-based index
python3 screenshooter.py --csv alerts.csv --column src_ip

# IOCs as arguments
python3 screenshooter.py 8.8.8.8 44d88612fea8a8f36de82e1278abb02f

# One IOC per line via stdin
python3 screenshooter.py < iocs.txt
```

Arguments and `--csv` can be combined; stdin is only read when neither is given.

### Options

| Option | Description | Default |
|---|---|---|
| `iocs` | IPs / hashes / domains as positional arguments | – |
| `-c, --csv FILE` | CSV file to read IOCs from | – |
| `--column NAME\|INDEX` | CSV column to use (header name or 0-based index) | first column |
| `-o, --output-dir DIR` | Output directory for PNGs and the results CSV | `./screenshots` |
| `-r, --results FILE` | Results CSV path | next to `--csv` input as `<name>_results.csv`, else `<output-dir>/<timestamp>_results.csv` |
| `-w, --wait N` | Seconds to wait after page load before screenshotting | `5` |
| `--vt-key KEY` | VirusTotal API key passed to vt-cli | `VTCLI_APIKEY` / `~/.vt.toml` |
| `--vt-bin PATH` | Path to the `vt` binary | `vt` on `PATH` |
| `--abuseipdb-key KEY` | AbuseIPDB API key for live data | `ABUSEIPDB_API_KEY` |
| `--no-screenshots` | Skip the browser; only write the results CSV | off |
| `--no-headless` | Show the browser window (solve CAPTCHAs / debug) | off |

### Input CSV format

```csv
ioc,type,note
8.8.8.8,ip,google dns
44d88612fea8a8f36de82e1278abb02f,md5,eicar
```

The first row is treated as a header if it is matched by `--column NAME`, or if
its value doesn't look like an IOC (IPv4, MD5/SHA1/SHA256, or something dotted
like a domain). Blank cells are skipped.

## Output

```
screenshots/
├── 20261019_143654_results.csv
├── 20261019_143654_8.8.8.8_virustotal.png
├── 20261019_143654_8.8.8.8_abuseipdb.png
└── 20261019_143654_44d88612fea8a8f36de82e1278abb02f_virustotal.png
```

The results CSV is written with a UTF-8 BOM so Excel opens it cleanly, and is
saved even if the run is interrupted part-way.

## Notes

- Only IPv4 addresses get AbuseIPDB results; everything else is VirusTotal only.
- The free VirusTotal API allows 4 lookups/minute and 500/day; vt-cli errors
  past that limit and the tool falls back to the web page score.
- If screenshots show a CAPTCHA or half-loaded page, raise `--wait` and/or run
  with `--no-headless` to click through the challenge manually.
- Get an AbuseIPDB API key at <https://www.abuseipdb.com/account/api>.
