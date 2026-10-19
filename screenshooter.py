#!/usr/bin/env python3
"""
IOC Screenshot Tool
Takes a list of IPs or hashes, screenshots VirusTotal + AbuseIPDB results,
and writes a results CSV (IOCs, Type, VirusTotal, VT Link, AbuseIPDB, AbuseIPDB link).

VirusTotal: detections via vt-cli (falls back to the web page),
            real browser screenshot (headless Chromium via Playwright)
AbuseIPDB:  API data with a key; API-rendered screenshot when Cloudflare blocks the browser
"""

import argparse
import asyncio
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
import urllib.error
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

try:
    from playwright_stealth import stealth_async          # playwright-stealth 1.x
except ImportError:
    try:
        from playwright_stealth import Stealth            # playwright-stealth 2.x

        async def stealth_async(page):
            await Stealth().apply_stealth_async(page)
    except ImportError:
        stealth_async = None
HAS_STEALTH = stealth_async is not None


# ── site config ──────────────────────────────────────────────────────────────

# AbuseIPDB: use public JSON API instead of scraping (avoids Cloudflare block)
ABUSEIPDB_API = 'https://api.abuseipdb.com/api/v2/check'

IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
HASH_RE = re.compile(r'^([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$')


def is_ip(value: str) -> bool:
    return bool(IP_RE.match(value.strip()))


def load_dotenv(path: Path):
    """Load KEY=VALUE lines into os.environ; real env vars take precedence."""
    if not path.is_file():
        return
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        value = value.strip().strip('"\'')
        if value:
            os.environ.setdefault(key.strip(), value)


HASH_TYPES = {32: 'MD5', 40: 'SHA1', 64: 'SHA256'}

# IOC type → (vt-cli subcommand, VirusTotal GUI path)
VT_TARGETS = {
    'IP':     ('ip', 'ip-address'),
    'MD5':    ('file', 'file'),
    'SHA1':   ('file', 'file'),
    'SHA256': ('file', 'file'),
    'Domain': ('domain', 'domain'),
    'URL':    ('url', None),
}


def ioc_type(value: str) -> str:
    if is_ip(value):
        return 'IP'
    if HASH_RE.match(value):
        return HASH_TYPES[len(value)]
    if value.lower().startswith(('http://', 'https://')):
        return 'URL'
    if '.' in value:
        return 'Domain'
    return 'Unknown'


def vt_link(ioc: str, kind: str) -> str:
    gui_path = VT_TARGETS.get(kind, (None, None))[1]
    if gui_path:
        return f'https://www.virustotal.com/gui/{gui_path}/{ioc}'
    return f'https://www.virustotal.com/gui/search/{urllib.parse.quote(ioc, safe="")}'


def looks_like_ioc(value: str) -> bool:
    """IP, MD5/SHA1/SHA256 hash, or anything dotted (domain/URL)."""
    value = value.strip()
    return is_ip(value) or bool(HASH_RE.match(value)) or '.' in value


def read_csv_iocs(path: Path, column: str | None) -> list[str]:
    """
    Read IOCs from one column of a CSV file.
    `column` is a header name or 0-based index (default: first column).
    The first row is skipped as a header when it is matched by name or
    does not look like an IOC.
    """
    with open(path, newline='', encoding='utf-8-sig') as f:
        rows = [row for row in csv.reader(f) if row]
    if not rows:
        return []

    header = [cell.strip() for cell in rows[0]]
    has_header = False
    if column is None:
        idx = 0
    elif column.isdigit():
        idx = int(column)
    elif column in header:
        idx = header.index(column)
        has_header = True
    else:
        raise ValueError(f'column "{column}" not found in CSV header: {header}')

    if not has_header and idx < len(rows[0]) and not looks_like_ioc(rows[0][idx]):
        has_header = True

    return [row[idx].strip() for row in rows[1 if has_header else 0:]
            if idx < len(row) and row[idx].strip()]


def sanitize(value: str) -> str:
    return re.sub(r'[^\w.\-]', '_', value)


# ── AbuseIPDB HTML renderer ───────────────────────────────────────────────────

def fetch_abuseipdb(ip: str, api_key: str) -> dict | None:
    """Query the AbuseIPDB v2 check API; returns the parsed JSON or None on error."""
    try:
        req = urllib.request.Request(
            f'{ABUSEIPDB_API}?ipAddress={ip}&maxAgeInDays=90&verbose',
            headers={'Key': api_key, 'Accept': 'application/json'},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as exc:
        print(f'  [WARN]  AbuseIPDB API error: {exc}', file=sys.stderr)
        return None


def abuseipdb_summary(data: dict | None) -> str:
    if not data or 'data' not in data:
        return 'N/A'
    d = data['data']
    return f"{d.get('abuseConfidenceScore', '?')}% ({d.get('totalReports', 0)} reports)"


def abuseipdb_details(data: dict | None) -> dict:
    d = (data or {}).get('data') or {}
    if not d:
        return {}
    return {
        'AbuseIPDB ISP': d.get('isp') or '',
        'AbuseIPDB Usage Type': d.get('usageType') or '',
        'Tor Exit Node': 'Yes' if d.get('isTor') else 'No',
        'AbuseIPDB Last Reported': (d.get('lastReportedAt') or '')[:10],
    }


# ── VirusTotal via vt-cli ─────────────────────────────────────────────────────

# Engines that couldn't scan don't count toward the "x/total" ratio shown on the VT GUI
VT_UNCOUNTED_STATS = {'type-unsupported', 'failure', 'confirmed-timeout'}


def vt_summary(obj: dict) -> dict:
    """Flatten a vt-cli object into result CSV columns."""
    stats = obj.get('last_analysis_stats', {})
    total = sum(v for k, v in stats.items() if k not in VT_UNCOUNTED_STATS)

    # What the flagging vendors call it, e.g. "phishing (6); malware (3)"
    labels = Counter(
        (r.get('result') or r.get('category')).lower().removesuffix(' site')
        for r in obj.get('last_analysis_results', {}).values()
        if r.get('category') in ('malicious', 'suspicious')
    )

    # Domains/URLs have vendor categories; files have a threat classification
    threat = obj.get('popular_threat_classification', {})
    categories = sorted(set(obj.get('categories', {}).values()))
    if threat.get('suggested_threat_label'):
        categories.insert(0, threat['suggested_threat_label'])

    asn = obj.get('asn')
    as_owner = obj.get('as_owner', '')
    size = obj.get('size')
    file_info = [obj.get('type_description'), obj.get('meaningful_name'),
                 f'{size} bytes' if size else None]
    last = obj.get('last_analysis_date')

    return {
        'VirusTotal': f"{stats.get('malicious', 0)}/{total}",
        'VT Labels': '; '.join(f'{label} ({n})' for label, n in labels.most_common()),
        'VT Category': '; '.join(categories),
        'VT Reputation': obj.get('reputation', ''),
        'VT Tags': ', '.join(obj.get('tags', [])),
        'Country': obj.get('country', ''),
        'AS Owner': f'AS{asn} {as_owner}'.strip() if asn else as_owner,
        'Network': obj.get('network', ''),
        'File Info': ' | '.join(str(x) for x in file_info if x),
        'VT Last Analysis': datetime.fromtimestamp(last, timezone.utc).strftime('%Y-%m-%d') if last else '',
    }


def vt_cli_report(ioc: str, kind: str, vt_bin: str, vt_key: str | None) -> dict | None:
    """
    Look up an IOC with vt-cli (github.com/virustotal/vt-cli) and return result columns.
    Returns None when vt-cli can't answer, so the caller can fall back.
    """
    subcommand = VT_TARGETS.get(kind, (None, None))[0]
    if not subcommand:
        return None
    cmd = [vt_bin, subcommand, ioc, '--format', 'json', '--silent',
           '--exclude', 'last_https_certificate.**,rdap.**,whois,last_dns_records.**']
    if vt_key:
        cmd += ['--apikey', vt_key]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f'  [WARN]  vt-cli failed: {exc}', file=sys.stderr)
        return None
    if proc.returncode != 0:
        # vt-cli prints usage help after the error; keep the "Error: ..." line
        lines = proc.stderr.strip().splitlines() or ['unknown error']
        err = next((l for l in lines if l.startswith('Error')), lines[0])
        if 'NotFound' in err:
            return {'VirusTotal': 'Not found'}
        print(f'  [WARN]  vt-cli: {err}', file=sys.stderr)
        return None
    try:
        objects = json.loads(proc.stdout or '[]')
    except json.JSONDecodeError:
        return None
    if not objects:
        return {'VirusTotal': 'Not found'}
    return vt_summary(objects[0])


async def vt_page_score(page) -> str | None:
    """Fallback: read the detection ratio off the VirusTotal page already loaded."""
    try:
        text = await page.get_by_text(re.compile(r'security vendors.*flagged')).first.inner_text(timeout=3000)
    except Exception:
        return None
    match = re.search(r'(\d+)\s*/\s*(\d+)', text)
    if match:
        return f'{match.group(1)}/{match.group(2)}'
    return '0' if text.strip().lower().startswith('no ') else None


def abuseipdb_html(ip: str, data: dict | None, check_url: str) -> str:
    """Render an AbuseIPDB-style HTML report for screenshotting."""
    if data and 'data' in data:
        d = data['data']
        score = d.get('abuseConfidenceScore', '—')
        total = d.get('totalReports', '—')
        country = d.get('countryCode', '—')
        isp = d.get('isp', '—')
        domain = d.get('domain', '—')
        usage = d.get('usageType', '—')
        is_tor = 'Yes' if d.get('isTor') else 'No'
        last_reported = d.get('lastReportedAt', '—') or '—'
        color = '#dc3545' if isinstance(score, int) and score > 25 else '#28a745'
        score_label = f'{score}%'
    else:
        score, total, country, isp, domain = '—', '—', '—', '—', '—'
        usage, is_tor, last_reported = '—', '—', '—'
        color = '#6c757d'
        score_label = 'N/A'

    rows = [
        ('IP Address', ip),
        ('Abuse Score', f'<span style="color:{color};font-weight:bold">{score_label}</span>'),
        ('Total Reports', total),
        ('Country', country),
        ('ISP', isp),
        ('Domain', domain),
        ('Usage Type', usage),
        ('Is Tor Exit Node', is_tor),
        ('Last Reported', last_reported),
    ]
    tbody = ''.join(
        f'<tr><td class="label">{k}</td><td>{v}</td></tr>' for k, v in rows
    )
    note = ''
    if data is None:
        note = '''
        <div class="note">
          ⚠️ Could not fetch live data (AbuseIPDB API key not configured).
          Visit <a href="{url}">{url}</a> for full details.
        </div>'''.format(url=check_url)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AbuseIPDB – {ip}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background:#f8f9fa; margin:0; padding:32px; }}
  .card {{ background:#fff; border:1px solid #dee2e6; border-radius:8px;
           max-width:740px; margin:auto; padding:32px; box-shadow:0 2px 8px rgba(0,0,0,.07); }}
  .logo {{ display:flex; align-items:center; gap:12px; margin-bottom:24px; }}
  .logo img {{ height:40px; }}
  .logo h1 {{ font-size:22px; color:#212529; margin:0; }}
  .logo span {{ font-size:13px; color:#6c757d; display:block; }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  td {{ padding:10px 14px; border-bottom:1px solid #f1f3f5; vertical-align:top; }}
  td.label {{ color:#6c757d; width:38%; font-weight:500; }}
  tr:last-child td {{ border-bottom:none; }}
  .source {{ font-size:12px; color:#adb5bd; margin-top:20px; text-align:right; }}
  .note {{ background:#fff3cd; border:1px solid #ffc107; border-radius:6px;
           padding:12px 16px; margin-top:20px; font-size:13px; color:#856404; }}
  a {{ color:#0d6efd; }}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div>
      <h1>AbuseIPDB</h1>
      <span>IP Address Report</span>
    </div>
  </div>
  <table>{tbody}</table>
  {note}
  <div class="source">Source: {check_url}</div>
</div>
</body>
</html>"""


# ── browser screenshot ────────────────────────────────────────────────────────

async def screenshot_url(page, url: str, output_path: Path, wait_seconds: int) -> bool:
    try:
        await page.goto(url, wait_until='domcontentloaded', timeout=30_000)
        await page.wait_for_timeout(wait_seconds * 1000)
        await page.screenshot(path=str(output_path), full_page=True)
        print(f'  [OK]  {output_path.name}')
        return True
    except PlaywrightTimeout:
        print(f'  [TIMEOUT]  {url}', file=sys.stderr)
        return False
    except Exception as exc:
        print(f'  [ERROR]  {url}: {exc}', file=sys.stderr)
        return False


async def screenshot_html(page, html: str, output_path: Path) -> bool:
    try:
        await page.set_content(html, wait_until='domcontentloaded')
        await page.wait_for_timeout(500)
        await page.screenshot(path=str(output_path), full_page=True)
        print(f'  [OK]  {output_path.name}')
        return True
    except Exception as exc:
        print(f'  [ERROR]  rendering HTML for {output_path.name}: {exc}', file=sys.stderr)
        return False


# ── main runner ───────────────────────────────────────────────────────────────

RESULT_COLUMNS = [
    'IOCs', 'Type', 'VirusTotal', 'VT Link', 'AbuseIPDB', 'AbuseIPDB link',
    # VirusTotal details (vt-cli only)
    'VT Labels', 'VT Category', 'VT Reputation', 'VT Tags',
    'Country', 'AS Owner', 'Network', 'File Info', 'VT Last Analysis',
    # AbuseIPDB details (API key only)
    'AbuseIPDB ISP', 'AbuseIPDB Usage Type', 'Tor Exit Node', 'AbuseIPDB Last Reported',
]


def write_results_csv(rows: list[dict], path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8-sig') as f:   # BOM so Excel opens it cleanly
        writer = csv.DictWriter(f, fieldnames=RESULT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


async def run(iocs: list[str], output_dir: Path, wait_seconds: int, headless: bool,
              abuseipdb_key: str | None, vt_bin: str | None, vt_key: str | None,
              screenshots: bool, results_path: Path | None) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    results_path = results_path or output_dir / f'{timestamp}_results.csv'
    rows = []

    if not vt_bin:
        print('[INFO]  vt-cli not found; VirusTotal score will be read from the web page'
              + ('' if screenshots else ' (disabled with --no-screenshots)') + '.')

    pw = browser = page = None
    if screenshots:
        pw = await async_playwright().start()
        browser = await pw.chromium.launch(headless=headless)
        context = await browser.new_context(
            viewport={'width': 1440, 'height': 900},
            user_agent=(
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/124.0.0.0 Safari/537.36'
            ),
        )
        page = await context.new_page()
        if HAS_STEALTH:
            await stealth_async(page)

    try:
        for raw_ioc in iocs:
            ioc = raw_ioc.strip()
            if not ioc:
                continue
            kind = ioc_type(ioc)
            print(f'\n--- IOC: {ioc} ({kind}) ---')
            safe = sanitize(ioc)
            vt_url = vt_link(ioc, kind)
            check_url = f'https://www.abuseipdb.com/check/{ioc}' if kind == 'IP' else ''

            # ── VirusTotal: vt-cli first, page text as fallback ──
            vt_info = (vt_cli_report(ioc, kind, vt_bin, vt_key) if vt_bin else None) or {}
            if page:
                out = output_dir / f'{timestamp}_{safe}_virustotal.png'
                if await screenshot_url(page, vt_url, out, wait_seconds) and not vt_info:
                    vt_info = {'VirusTotal': await vt_page_score(page)}

            # ── AbuseIPDB (IP only) ──
            abuse_data = fetch_abuseipdb(ioc, abuseipdb_key) if kind == 'IP' and abuseipdb_key else None
            if page and kind == 'IP':
                out = output_dir / f'{timestamp}_{safe}_abuseipdb.png'

                # Try real browser first (stealth helps bypass Cloudflare)
                browser_ok = await screenshot_url(page, check_url, out, wait_seconds)

                # Detect Cloudflare block by checking output file size (< 60 KB = likely blocked page)
                if browser_ok and out.exists() and out.stat().st_size < 60_000:
                    print('  [INFO]  AbuseIPDB returned a bot-check page; falling back to API report.')
                    browser_ok = False

                if not browser_ok:
                    if not abuseipdb_key:
                        print('  [INFO]  No AbuseIPDB API key; rendering placeholder report.')
                    await screenshot_html(page, abuseipdb_html(ioc, abuse_data, check_url), out)

            row = {
                **vt_info,
                **abuseipdb_details(abuse_data),
                'IOCs': ioc,
                'Type': kind,
                'VirusTotal': vt_info.get('VirusTotal') or 'N/A',
                'VT Link': vt_url,
                'AbuseIPDB': abuseipdb_summary(abuse_data) if kind == 'IP' else '',
                'AbuseIPDB link': check_url,
            }
            print(f"  [RESULT]  VT {row['VirusTotal']}" + (f" | AbuseIPDB {row['AbuseIPDB']}" if kind == 'IP' else ''))
            rows.append(row)
    finally:
        # Always keep whatever results were gathered, even if interrupted
        write_results_csv(rows, results_path)
        if browser:
            await browser.close()
        if pw:
            await pw.stop()
    return results_path


def main():
    # VTCLI_APIKEY from .env is inherited by the vt-cli subprocess
    load_dotenv(Path(__file__).resolve().parent / '.env')

    parser = argparse.ArgumentParser(
        description='Look up IOCs on VirusTotal (via vt-cli) / AbuseIPDB, '
                    'save screenshots and a results CSV.'
    )
    parser.add_argument('iocs', nargs='*',
                        help='IPs or hashes (also readable from stdin)')
    parser.add_argument('-c', '--csv', type=Path, default=None,
                        help='CSV file to read IOCs from')
    parser.add_argument('--column', default=None,
                        help='CSV column name or 0-based index (default: first column)')
    parser.add_argument('-o', '--output-dir', default='screenshots',
                        help='Directory for PNG and results CSV output (default: ./screenshots)')
    parser.add_argument('-r', '--results', type=Path, default=None,
                        help='Results CSV path (default: <input>_results.csv next to --csv, '
                             'else <output-dir>/<timestamp>_results.csv)')
    parser.add_argument('-w', '--wait', type=int, default=5,
                        help='Seconds to wait after page load (default: 5)')
    parser.add_argument('--abuseipdb-key', default=os.environ.get('ABUSEIPDB_API_KEY'),
                        help='AbuseIPDB API key for live data (default: ABUSEIPDB_API_KEY in .env/env)')
    parser.add_argument('--vt-key', default=None,
                        help='VirusTotal API key passed to vt-cli '
                             '(default: VTCLI_APIKEY in .env/env, or ~/.vt.toml from `vt init`)')
    parser.add_argument('--vt-bin', default=shutil.which('vt'),
                        help='Path to the vt-cli binary (default: `vt` on PATH)')
    parser.add_argument('--no-screenshots', action='store_true',
                        help='Skip the browser; only write the results CSV')
    parser.add_argument('--no-headless', action='store_true',
                        help='Show browser window (useful for CAPTCHA/debugging)')
    args = parser.parse_args()

    iocs = list(args.iocs)
    if args.csv:
        try:
            iocs += read_csv_iocs(args.csv, args.column)
        except (OSError, ValueError) as exc:
            parser.error(f'cannot read CSV: {exc}')
    if not iocs and not sys.stdin.isatty():
        iocs = [line.strip() for line in sys.stdin if line.strip()]
    if not iocs:
        parser.error('Provide at least one IOC as argument, via --csv, or via stdin.')

    # Default: results next to the input CSV, e.g. log/iocs.csv → log/iocs_results.csv
    if args.results is None and args.csv:
        args.results = args.csv.with_name(f'{args.csv.stem}_results.csv')

    results_path = asyncio.run(run(
        iocs,
        Path(args.output_dir),
        args.wait,
        headless=not args.no_headless,
        abuseipdb_key=args.abuseipdb_key,
        vt_bin=args.vt_bin,
        vt_key=args.vt_key,
        screenshots=not args.no_screenshots,
        results_path=args.results,
    ))
    if not args.no_screenshots:
        print(f'\nScreenshots saved to: {Path(args.output_dir).resolve()}')
    print(f'Results CSV: {results_path.resolve()}')


if __name__ == '__main__':
    main()
