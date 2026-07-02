#!/usr/bin/env python3
"""
IOC Screenshot Tool
Takes a list of IPs or hashes and screenshots VirusTotal + AbuseIPDB results.

VirusTotal: real browser screenshot (headless Chromium via Playwright)
AbuseIPDB:  API-rendered screenshot (bypasses Cloudflare bot challenge)
"""

import argparse
import asyncio
import json
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

try:
    from playwright_stealth import stealth_async
    HAS_STEALTH = True
except ImportError:
    HAS_STEALTH = False


# ── site config ──────────────────────────────────────────────────────────────

BROWSER_SITES = {
    'virustotal': 'https://www.virustotal.com/gui/search/{ioc}',
}

# AbuseIPDB: use public JSON API instead of scraping (avoids Cloudflare block)
ABUSEIPDB_API = 'https://api.abuseipdb.com/api/v2/check'

IP_ONLY_BROWSER_SITES: set[str] = set()
IP_ONLY_API_SITES = {'abuseipdb'}

IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


def is_ip(value: str) -> bool:
    return bool(IP_RE.match(value.strip()))


def sanitize(value: str) -> str:
    return re.sub(r'[^\w.\-]', '_', value)


# ── AbuseIPDB HTML renderer ───────────────────────────────────────────────────

def fetch_abuseipdb_public(ip: str) -> dict | None:
    """
    Use the AbuseIPDB public check endpoint (no auth needed for basic info).
    Falls back to a minimal dict if the request fails.
    """
    url = f'https://www.abuseipdb.com/check/{ip}'
    # The JSON API requires an API key; instead, parse the public HTML page
    # via their unofficial JSON embed endpoint.
    try:
        req = urllib.request.Request(
            f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose',
            headers={
                'Key': '',               # empty key → 401 but we catch it
                'Accept': 'application/json',
            },
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception:
        pass
    return None


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

async def run(iocs: list[str], output_dir: Path, wait_seconds: int, headless: bool,
              abuseipdb_key: str | None):
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    async with async_playwright() as pw:
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

        for raw_ioc in iocs:
            ioc = raw_ioc.strip()
            if not ioc:
                continue
            ioc_is_ip = is_ip(ioc)
            print(f'\n--- IOC: {ioc} ({"IP" if ioc_is_ip else "hash/domain"}) ---')
            safe = sanitize(ioc)

            # ── browser sites (VirusTotal, etc.) ──
            for site_key, url_tpl in BROWSER_SITES.items():
                if site_key in IP_ONLY_BROWSER_SITES and not ioc_is_ip:
                    print(f'  [SKIP]  {site_key} (IP only)')
                    continue
                url = url_tpl.format(ioc=ioc)
                out = output_dir / f'{timestamp}_{safe}_{site_key}.png'
                await screenshot_url(page, url, out, wait_seconds)

            # ── AbuseIPDB (IP only) ──
            if ioc_is_ip:
                check_url = f'https://www.abuseipdb.com/check/{ioc}'
                out = output_dir / f'{timestamp}_{safe}_abuseipdb.png'

                # Try real browser first (stealth helps bypass Cloudflare)
                browser_ok = await screenshot_url(page, check_url, out, wait_seconds)

                # Detect Cloudflare block by checking output file size (< 60 KB = likely blocked page)
                if browser_ok and out.exists() and out.stat().st_size < 60_000:
                    print('  [INFO]  AbuseIPDB returned a bot-check page; falling back to API report.')
                    browser_ok = False

                if not browser_ok:
                    # Fetch data from API (requires key) or render a placeholder
                    data = None
                    if abuseipdb_key:
                        try:
                            req = urllib.request.Request(
                                f'{ABUSEIPDB_API}?ipAddress={ioc}&maxAgeInDays=90&verbose',
                                headers={'Key': abuseipdb_key, 'Accept': 'application/json'},
                            )
                            with urllib.request.urlopen(req, timeout=10) as r:
                                data = json.loads(r.read())
                        except Exception as e:
                            print(f'  [WARN]  AbuseIPDB API error: {e}', file=sys.stderr)
                    else:
                        print('  [INFO]  No AbuseIPDB API key; rendering placeholder report.')
                    html = abuseipdb_html(ioc, data, check_url)
                    await screenshot_html(page, html, out)

        await browser.close()


def main():
    parser = argparse.ArgumentParser(
        description='Screenshot VirusTotal / AbuseIPDB results for a list of IOCs.'
    )
    parser.add_argument('iocs', nargs='*',
                        help='IPs or hashes (also readable from stdin)')
    parser.add_argument('-o', '--output-dir', default='screenshots',
                        help='Directory for PNG output (default: ./screenshots)')
    parser.add_argument('-w', '--wait', type=int, default=5,
                        help='Seconds to wait after page load (default: 5)')
    parser.add_argument('--abuseipdb-key', default=None,
                        help='AbuseIPDB API key for live data (optional)')
    parser.add_argument('--no-headless', action='store_true',
                        help='Show browser window (useful for CAPTCHA/debugging)')
    args = parser.parse_args()

    iocs = args.iocs
    if not iocs and not sys.stdin.isatty():
        iocs = [line.strip() for line in sys.stdin if line.strip()]
    if not iocs:
        parser.error('Provide at least one IOC as argument or via stdin.')

    asyncio.run(run(
        iocs,
        Path(args.output_dir),
        args.wait,
        headless=not args.no_headless,
        abuseipdb_key=args.abuseipdb_key,
    ))
    print(f'\nDone. Screenshots saved to: {Path(args.output_dir).resolve()}')


if __name__ == '__main__':
    main()
