#!/usr/bin/env python3
"""
Tells IndexNow-enabled search engines (Bing, Yandex, Seznam, Naver…) which pages
exist after a deploy, so they re-crawl them quickly.

Reads the live sitemap, then submits its URLs to https://api.indexnow.org.
The key is public by design: it is served at https://securityexplorer.org/<key>.txt
to prove ownership of the site.

Usage:  python3 scripts/indexnow.py
Runs automatically in the GitHub Pages workflow after each deploy.
"""
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

SITE = 'https://securityexplorer.org'
HOST = 'securityexplorer.org'
ENDPOINT = 'https://api.indexnow.org/indexnow'
UA = 'SecurityExplorer-IndexNow/1.0'

root = pathlib.Path(__file__).resolve().parent.parent
keys = [p.stem for p in root.glob('*.txt') if re.fullmatch(r'[0-9a-f]{32}', p.stem)]
if len(keys) != 1:
    sys.exit(f'Expected exactly one IndexNow key file at the site root, found {len(keys)}.')
key = keys[0]


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Cache-Control': 'no-cache'})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode('utf-8')


# Wait until the new deploy (with the key file) is live.
for attempt in range(10):
    try:
        if fetch(f'{SITE}/{key}.txt').strip() == key:
            break
    except urllib.error.URLError:
        pass
    time.sleep(15)
else:
    sys.exit('Key file is not live yet; skipping IndexNow submission.')

urls = re.findall(r'<loc>([^<]+)</loc>', fetch(f'{SITE}/sitemap.xml'))
if not urls:
    sys.exit('No URLs found in the sitemap.')

body = json.dumps({'host': HOST, 'key': key, 'keyLocation': f'{SITE}/{key}.txt', 'urlList': urls}).encode()
req = urllib.request.Request(ENDPOINT, data=body, method='POST',
                             headers={'Content-Type': 'application/json; charset=utf-8', 'User-Agent': UA})
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print(f'IndexNow accepted {len(urls)} URLs (HTTP {r.status}).')
except urllib.error.HTTPError as e:
    # 202 = accepted, key pending validation; 4xx = problem with the request or key.
    sys.exit(f'IndexNow returned HTTP {e.code}: {e.read().decode(errors="replace")[:300]}')
