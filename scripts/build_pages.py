#!/usr/bin/env python3
"""
Pre-builds one HTML page per route so every module has a real, indexable URL
(e.g. /m/sqli/) with its own <title>, description and canonical link, plus
404.html, sitemap.xml and robots.txt. The pages share the same app shell;
the JavaScript router renders the content.

Usage:  python3 scripts/build_pages.py [site_dir]
Runs automatically in the GitHub Pages workflow before deploy. Output files
are generated, not committed (see .gitignore).
"""
import html
import json
import pathlib
import re
import sys

SITE_URL = 'https://securityexplorer.org'
SITE_NAME = 'Security Explorer'
AUTHOR = 'Muktesh Adusumilli'

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
template = (root / 'index.html').read_text(encoding='utf-8')
# Safe to re-run: drop anything a previous build added to the shell.
template = re.sub(r'\n<link rel="canonical" href="[^"]*">|\n<meta property="og:url" content="[^"]*">|\n<script type="application/ld\+json">.*?</script>', '', template, flags=re.S)

JS_STR = r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")"""


def js_string(raw):
    body = raw[1:-1]
    return re.sub(r"\\(.)", r"\1", body)


def field(block, name):
    m = re.search(r'\b' + name + r':\s*' + JS_STR, block)
    return js_string(m.group(1)) if m else ''


def plain(text, limit=158):
    text = re.sub(r'`([^`]*)`', r'\1', text)
    text = ' '.join(text.split())
    if len(text) > limit:
        text = text[:limit].rsplit(' ', 1)[0].rstrip(',.;:') + '…'
    return text


# Topics and learning paths from the registry.
registry = (root / 'js' / 'registry.js').read_text(encoding='utf-8')
domains = []
for m in re.finditer(r"\{ id: '([\w-]+)', name: " + JS_STR + r", short: " + JS_STR + r", icon: '[\w-]+',\s*blurb: " + JS_STR, registry):
    domains.append({'id': m.group(1), 'name': js_string(m.group(2)), 'blurb': js_string(m.group(4))})
paths = re.findall(r"\{ id: '([\w-]+)', level: '\w+', title: " + JS_STR, registry)

# Modules from every module file.
modules = []
for f in sorted((root / 'js' / 'modules').glob('*.js')):
    for block in f.read_text(encoding='utf-8').split('SE.register({')[1:]:
        steps = len(re.findall(r'^\s{6}title: ', block, flags=re.M))
        modules.append({
            'id': field(block, 'id'), 'domain': field(block, 'domain'),
            'name': field(block, 'name'), 'full': field(block, 'full'),
            'summary': field(block, 'summary'), 'steps': steps, 'level': field(block, 'level'),
        })
live_domains = {m['domain'] for m in modules}
domains = [d for d in domains if d['id'] in live_domains]


def jsonld(data):
    return '<script type="application/ld+json">' + json.dumps(data, ensure_ascii=False).replace('</', '<\\/') + '</script>'


def page(path, title, description, extra_head=''):
    url = SITE_URL + path
    full_title = f'{title} · {SITE_NAME}' if title else f'{SITE_NAME}: interactive security walkthroughs'
    t, d, u = html.escape(full_title), html.escape(description), html.escape(url)
    out = re.sub(r'<title>.*?</title>', f'<title>{t}</title>\n<link rel="canonical" href="{u}">', template, count=1, flags=re.S)
    out = re.sub(r'(<meta name="description" content=")[^"]*', r'\g<1>' + d.replace('\\', r'\\'), out, count=1)
    out = re.sub(r'(<meta property="og:title" content=")[^"]*', r'\g<1>' + t.replace('\\', r'\\'), out, count=1)
    out = re.sub(r'(<meta property="og:description" content=")[^"]*', r'\g<1>' + d.replace('\\', r'\\'), out, count=1)
    out = out.replace('<meta property="og:type" content="website">',
                      f'<meta property="og:type" content="website">\n<meta property="og:url" content="{u}">', 1)
    if extra_head:
        out = out.replace('</head>', extra_head + '\n</head>', 1)
    return out


def write(path, content):
    target = root / path.strip('/') / 'index.html' if path != '/' else None
    if target is None:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding='utf-8')


routes = []  # (path, title, description, indexable, structured data)
home_desc = 'Interactive, step-by-step walkthroughs of how web, API, network, crypto and AI attacks work, and how to defend against them.'
routes.append(('/modules/', 'Modules', f'{len(modules)} interactive walkthroughs of attacks, protocols and defenses. Pick one and press play.', True, None))
for d in domains:
    routes.append((f"/modules/{d['id']}/", d['name'], plain(d['blurb']), True, None))
routes.append(('/paths/', 'Learning paths', 'Short, ordered sets of security modules that build on each other, from networking basics to AI security.', True, None))
for pid, ptitle in paths:
    routes.append((f'/paths/{pid}/', js_string(ptitle), 'A learning path on Security Explorer.', False, None))
routes.append(('/glossary/', 'Glossary', 'Plain-language definitions of security and networking terms, with links to interactive walkthroughs.', True, None))
routes.append(('/about/', 'About', 'What Security Explorer is, how to use a module, and how it handles your privacy.', True, None))
for m in modules:
    desc = plain(m['summary'] or m['full'])
    ld = {
        '@context': 'https://schema.org', '@type': 'LearningResource',
        'name': m['name'], 'alternativeHeadline': m['full'], 'description': desc,
        'url': f"{SITE_URL}/m/{m['id']}/", 'inLanguage': 'en',
        'learningResourceType': 'Interactive walkthrough', 'educationalLevel': m['level'] or 'Beginner',
        'isAccessibleForFree': True, 'teaches': m['name'],
        'author': {'@type': 'Person', 'name': AUTHOR},
        'isPartOf': {'@type': 'WebSite', 'name': SITE_NAME, 'url': SITE_URL + '/'},
    }
    routes.append((f"/m/{m['id']}/", m['name'], desc, True, ld))
    for n in range(1, m['steps'] + 1):
        routes.append((f"/m/{m['id']}/{n}/", f"{m['name']} (step {n})", desc, False, None))

for path, title, desc, _, ld in routes:
    html_out = page(path, title, desc, jsonld(ld) if ld else '')
    # Step pages point their canonical at the module page.
    step = re.match(r'^/m/([\w-]+)/\d+/$', path)
    if step:
        html_out = html_out.replace(f'href="{SITE_URL}{path}"', f'href="{SITE_URL}/m/{step.group(1)}/"', 1)
    write(path, html_out)

# Home keeps its own file, with canonical + og:url added.
home_ld = {
    '@context': 'https://schema.org', '@type': 'WebSite', 'name': SITE_NAME, 'url': SITE_URL + '/',
    'description': home_desc, 'inLanguage': 'en', 'isAccessibleForFree': True,
    'author': {'@type': 'Person', 'name': AUTHOR},
}
(root / 'index.html').write_text(page('/', '', home_desc, jsonld(home_ld)), encoding='utf-8')
(root / '404.html').write_text(
    page('/404', 'Not found', home_desc).replace(
        f'<link rel="canonical" href="{SITE_URL}/404">', '<meta name="robots" content="noindex">', 1),
    encoding='utf-8')

urls = ['/'] + [p for p, _, _, idx, _ in routes if idx]
(root / 'sitemap.xml').write_text(
    '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    + ''.join(f'  <url><loc>{SITE_URL}{u}</loc></url>\n' for u in urls)
    + '</urlset>\n', encoding='utf-8')
(root / 'robots.txt').write_text(f'User-agent: *\nAllow: /\n\nSitemap: {SITE_URL}/sitemap.xml\n', encoding='utf-8')

print(f'Built {len(routes)} pages ({len(urls)} in sitemap) for {len(modules)} modules across {len(domains)} topics.')
