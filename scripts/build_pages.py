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
import hashlib
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


# Cache-busting: add ?v=<content hash> to local CSS/JS so browsers never mix a new page
# with an old cached script after a deploy.
def fingerprint(match):
    attr, path = match.group(1), match.group(2)
    f = root / path.lstrip('/')
    if not f.is_file():
        return match.group(0)
    digest = hashlib.sha256(f.read_bytes()).hexdigest()[:10]
    return f'{attr}="{path}?v={digest}"'


template = re.sub(r'(src|href)="(/(?:js|css)/[^"?]+\.(?:js|css))(?:\?v=[0-9a-f]+)?"', fingerprint, template)
# Safe to re-run: drop anything a previous build added to the shell.
template = re.sub(r'<div id="page" class="wrap page prerender">\n.*?\n</div>', '<div id="page" class="wrap page" hidden></div>', template, count=1, flags=re.S)
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
path_info = []
for m in re.finditer(r"\{ id: '([\w-]+)', level: '(\w+)', title: " + JS_STR + r",\s*desc: " + JS_STR + r",\s*modules: \[([^\]]*)\]", registry):
    path_info.append({'id': m.group(1), 'level': m.group(2), 'title': js_string(m.group(3)),
                      'desc': js_string(m.group(4)), 'modules': re.findall(r"'([\w-]+)'", m.group(5))})

# Modules from every module file.
modules = []
for f in sorted((root / 'js' / 'modules').glob('*.js')):
    for block in f.read_text(encoding='utf-8').split('SE.register({')[1:]:
        steps = len(re.findall(r'^\s{6}title: ', block, flags=re.M))
        step_list = []
        for chunk in re.split(r'\n\s{6}title: ', block)[1:]:
            t = re.match(JS_STR, chunk)
            sub = re.search(r'\bsub: ' + JS_STR, chunk.split('text:')[0])
            txt = re.search(r'\btext: ' + JS_STR, chunk)
            step_list.append({'title': js_string(t.group(1)) if t else '',
                              'sub': js_string(sub.group(1)) if sub else '',
                              'text': js_string(txt.group(1)) if txt else ''})
        dm = re.search(r'\bdefenses: \[(.*?)\n\s{2}\],', block, flags=re.S)
        fm = re.search(r'\bfacts: \[(.*?)\],\n', block, flags=re.S)
        modules.append({
            'id': field(block, 'id'), 'domain': field(block, 'domain'),
            'name': field(block, 'name'), 'full': field(block, 'full'),
            'summary': field(block, 'summary'), 'steps': steps, 'level': field(block, 'level'),
            'kind': field(block, 'kind'), 'step_list': step_list,
            'defenses': [js_string(x) for x in re.findall(JS_STR, dm.group(1))] if dm else [],
            'facts': [(js_string(a), js_string(b)) for a, b in re.findall(r'\[' + JS_STR + r', ' + JS_STR + r'\]', fm.group(1))] if fm else [],
        })
live_domains = {m['domain'] for m in modules}
by_id = {m['id']: m for m in modules}
glossary = [(js_string(a), js_string(b)) for a, b in re.findall(
    r"^\s*\[" + JS_STR + r", " + JS_STR + r", \[", (root / 'js' / 'glossary.js').read_text(encoding='utf-8'), flags=re.M)]
domains = [d for d in domains if d['id'] in live_domains]


E = html.escape


def rich(text):
    """Escape text and turn `code` spans into <code>."""
    return re.sub(r'`([^`]*)`', r'<code>\1</code>', E(text))


KIND_DEF = {'attack': 'How to defend', 'protocol': 'Security notes', 'defense': 'Best practices'}


def crumbs(*links):
    return '<nav class="crumbs-inline">' + ' / '.join(f'<a href="{u}">{E(t)}</a>' if u else E(t) for t, u in links) + '</nav>'


def mod_link(m, with_summary=False):
    extra = f' – {E(m["full"])}' if m['full'] else ''
    summ = f'<br>{rich(plain(m["summary"], 220))}' if with_summary and m['summary'] else ''
    return f'<li><a href="/m/{m["id"]}/">{E(m["name"])}</a>{extra}{summ}</li>'


def body_module(m):
    d = next((x for x in domains if x['id'] == m['domain']), None)
    out = [crumbs(('Home', '/'), ('Modules', '/modules/'), (d['name'], f"/modules/{d['id']}/") if d else ('', ''), (m['name'], None)),
           f'<h1>{E(m["name"])}</h1>', f'<p><strong>{E(m["full"])}</strong></p>', f'<p>{rich(m["summary"])}</p>',
           f'<p>{E(m["level"] or "Beginner")} · {len(m["step_list"])} steps</p>']
    if m['facts']:
        out.append('<table>' + ''.join(f'<tr><th>{E(a)}</th><td>{E(b)}</td></tr>' for a, b in m['facts']) + '</table>')
    out.append('<h2>Step by step</h2><ol>')
    for i, st in enumerate(m['step_list'], 1):
        sub = f' <small>{E(st["sub"])}</small>' if st['sub'] else ''
        out.append(f'<li><h3><a href="/m/{m["id"]}/{i}/">{E(st["title"])}</a>{sub}</h3><p>{rich(st["text"])}</p></li>')
    out.append('</ol>')
    if m['defenses']:
        out.append(f'<h2>{KIND_DEF.get(m["kind"], "How to defend")}</h2><ul>' + ''.join(f'<li>{rich(x)}</li>' for x in m['defenses']) + '</ul>')
    if d:
        out.append(f'<p>More in <a href="/modules/{d["id"]}/">{E(d["name"])}</a>.</p>')
    return '\n'.join(out)


def body_topic(d):
    ms = [m for m in modules if m['domain'] == d['id']]
    return '\n'.join([crumbs(('Home', '/'), ('Modules', '/modules/'), (d['name'], None)), f'<h1>{E(d["name"])}</h1>',
                      f'<p>{E(d["blurb"])}</p>', '<ul>' + ''.join(mod_link(m, True) for m in ms) + '</ul>'])


def body_catalog():
    out = [crumbs(('Home', '/'), ('Modules', None)), '<h1>All modules</h1>',
           f'<p>{len(modules)} interactive walkthroughs of attacks, protocols and defenses across {len(domains)} topics.</p>']
    for d in domains:
        out.append(f'<h2><a href="/modules/{d["id"]}/">{E(d["name"])}</a></h2><p>{E(d["blurb"])}</p><ul>'
                   + ''.join(mod_link(m) for m in modules if m['domain'] == d['id']) + '</ul>')
    return '\n'.join(out)


def body_path(pi):
    ms = [by_id[i] for i in pi['modules'] if i in by_id]
    return (f'<h2><a href="/paths/{pi["id"]}/">{E(pi["title"])}</a></h2><p>{E(pi["level"])} · {E(pi["desc"])}</p><ol>'
            + ''.join(mod_link(m) for m in ms) + '</ol>')


def body_paths():
    return '\n'.join([crumbs(('Home', '/'), ('Learning paths', None)), '<h1>Learning paths</h1>',
                      '<p>Short, ordered sets of modules that build on each other.</p>'] + [body_path(x) for x in path_info])


def body_glossary():
    return '\n'.join([crumbs(('Home', '/'), ('Glossary', None)), '<h1>Glossary</h1>',
                      '<p>Plain-language definitions of security and networking terms.</p>',
                      '<dl>' + ''.join(f'<dt>{E(t)}</dt><dd>{rich(dd)}</dd>' for t, dd in sorted(glossary, key=lambda g: g[0].lower())) + '</dl>'])


def body_home():
    return '\n'.join([
        '<h1>Security concepts, one packet at a time.</h1>',
        f'<p>{E(home_desc)} {len(modules)} free, interactive modules. No sign-up.</p>',
        '<p><a href="/modules/">Browse all modules</a> · <a href="/paths/">Learning paths</a> · <a href="/glossary/">Glossary</a></p>',
        '<h2>Topics</h2><ul>' + ''.join(f'<li><a href="/modules/{d["id"]}/">{E(d["name"])}</a>: {E(d["blurb"])}</li>' for d in domains) + '</ul>',
        '<h2>Learning paths</h2><ul>' + ''.join(f'<li><a href="/paths/{x["id"]}/">{E(x["title"])}</a>: {E(x["desc"])}</li>' for x in path_info) + '</ul>',
    ])


STATIC = {
    '/about/': lambda: '\n'.join([crumbs(('Home', '/'), ('About', None)), '<h1>About Security Explorer</h1>',
        '<p>A free learning site that shows how attacks, protocols and defenses really work, one message at a time. '
        'Each module plays out a scenario step by step, explains what is happening and why, and ends with the defense.</p>',
        '<p>Content follows public standards such as the OWASP Top 10, MITRE ATT&amp;CK, MITRE ATLAS, NIST and IETF RFCs. '
        'No accounts, ads or cookies. Created by Muktesh Adusumilli.</p>']),
    '/contact/': lambda: '\n'.join([crumbs(('Home', '/'), ('Contact', None)), '<h1>Contact</h1>',
        '<p>Questions, ideas for new modules, or a mistake you spotted: send a note through the contact form.</p>']),
}


def jsonld(data):
    return '<script type="application/ld+json">' + json.dumps(data, ensure_ascii=False).replace('</', '<\\/') + '</script>'


def page(path, title, description, extra_head='', body=''):
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
    if body:
        out = out.replace('<div id="page" class="wrap page" hidden></div>',
                          f'<div id="page" class="wrap page prerender">\n{body}\n</div>', 1)
    return out


def write(path, content):
    target = root / path.strip('/') / 'index.html' if path != '/' else None
    if target is None:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding='utf-8')


routes = []  # (path, title, description, indexable, structured data)
home_desc = 'Interactive, step-by-step walkthroughs of how web, API, network, identity, crypto and AI attacks work, how SOC teams respond, and how to defend against them.'
routes.append(('/modules/', 'Modules', f'{len(modules)} interactive walkthroughs of attacks, protocols and defenses. Pick one and press play.', True, None))
for d in domains:
    routes.append((f"/modules/{d['id']}/", d['name'], plain(d['blurb']), True, None))
routes.append(('/paths/', 'Learning paths', 'Short, ordered sets of security modules that build on each other, from networking basics to AI security.', True, None))
for pid, ptitle in paths:
    routes.append((f'/paths/{pid}/', js_string(ptitle), 'A learning path on Security Explorer.', False, None))
routes.append(('/glossary/', 'Glossary', 'Plain-language definitions of security and networking terms, with links to interactive walkthroughs.', True, None))
routes.append(('/contact/', 'Contact', 'Send a question, suggest a new security topic, or report a mistake on Security Explorer.', True, None))
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

def body_for(path):
    if path in STATIC:
        return STATIC[path]()
    if path == '/modules/':
        return body_catalog()
    if path == '/paths/':
        return body_paths()
    if path == '/glossary/':
        return body_glossary()
    mt = re.match(r'^/modules/([\w-]+)/$', path)
    if mt:
        d = next((x for x in domains if x['id'] == mt.group(1)), None)
        return body_topic(d) if d else ''
    mp = re.match(r'^/paths/([\w-]+)/$', path)
    if mp:
        pi = next((x for x in path_info if x['id'] == mp.group(1)), None)
        return body_path(pi) if pi else ''
    mm = re.match(r'^/m/([\w-]+)/(?:\d+/)?$', path)
    if mm and mm.group(1) in by_id:
        return body_module(by_id[mm.group(1)])
    return ''


for path, title, desc, _, ld in routes:
    html_out = page(path, title, desc, jsonld(ld) if ld else '', body_for(path))
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
(root / 'index.html').write_text(page('/', '', home_desc, jsonld(home_ld), body_home()), encoding='utf-8')
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
