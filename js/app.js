/* Security Explorer: app engine (no build step, no dependencies). */
(() => {
  'use strict';
  const SE = window.SE, ICONS = window.SE_ICONS, CFG = window.SE_CONFIG || {};
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const fmt = (s) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');
  const NS = 'http://www.w3.org/2000/svg';
  const SITE = CFG.siteName || 'Security Explorer';
  const EVIL = new Set(['attacker', 'c2']);
  const GOOD = new Set(['shield', 'ids', 'siem', 'gateway']);
  const KIND_NAME = { attack: 'Attack', protocol: 'How it works', defense: 'Defense' };
  const DEF_TITLE = { attack: 'How to defend', protocol: 'Security notes', defense: 'Best practices' };
  const LEVELS = ['Beginner', 'Intermediate', 'Advanced'];

  const order = SE.domains.map((d) => d.id);
  const MODS = SE.modules.slice().sort((a, b) => order.indexOf(a.domain) - order.indexOf(b.domain));
  const byId = Object.fromEntries(MODS.map((m) => [m.id, m]));
  const domainOf = (id) => SE.domains.find((d) => d.id === id);
  const modsIn = (d) => MODS.filter((m) => m.domain === d);
  const LIVE = SE.domains.filter((d) => modsIn(d.id).length);
  const minutes = (m) => Math.max(2, Math.round(m.steps.length * 0.8));
  const pathMods = (p) => p.modules.map((id) => byId[id]).filter(Boolean);

  const st = { mod: null, step: -1, shown: 0, playing: false, speed: 1, view: 'network', token: 0, tab: 'all', level: 'all', quiz: null };

  /* ---------- progress (stored only in this browser) ---------- */
  const PROG_KEY = 'se-progress';
  let progress = {};
  try { progress = JSON.parse(localStorage.getItem(PROG_KEY)) || {}; } catch (_) { progress = {}; }
  const saveProgress = () => { try { localStorage.setItem(PROG_KEY, JSON.stringify(progress)); } catch (_) { /* storage unavailable */ } };
  const isDone = (id) => !!(progress[id] && progress[id].done);
  function markDone(id) { if (!isDone(id)) { progress[id] = { ...(progress[id] || {}), done: true }; saveProgress(); } }
  const doneTag = (id) => (isDone(id) ? ' <span class="done-tag" title="Completed">✓ Done</span>' : '');

  /* ---------- helpers ---------- */
  function prepare(m) {
    if (m.flat) return m;
    m.nodeMap = Object.fromEntries(m.nodes.map((n) => [n.id, n]));
    m.flat = []; m.stepStart = [];
    let t = 0, n = 0;
    m.steps.forEach((s, i) => {
      m.stepStart.push(m.flat.length);
      s.packets.forEach((p, j) => {
        if (n > 0) t += j === 0 ? 0.18 + ((n * 53) % 40) / 100 : 0.004 + ((n * 37) % 17) / 1000;
        m.flat.push({ ...p, step: i, no: ++n, time: t });
      });
    });
    m.stepStart.push(m.flat.length);
    return m;
  }
  const size = (b) => (typeof b !== 'number' ? esc(b) : b === 0 ? '–' : b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const nodeCls = (n) => (n.evil || EVIL.has(n.type) ? 'evil' : n.good || GOOD.has(n.type) ? 'good' : '');
  const icon = (type) => ICONS[type] || ICONS.server;
  const ext = 'target="_blank" rel="noopener"';
  function linkify(v) {
    return esc(v)
      .replace(/CWE-(\d+)/g, (x, n) => `<a href="https://cwe.mitre.org/data/definitions/${n}.html" ${ext}>${x}</a>`)
      .replace(/AML\.T(\d{4})(?:\.(\d{3}))?/g, (x) => `<a href="https://atlas.mitre.org/techniques/${x}" ${ext}>${x}</a>`)
      .replace(/(?<![.\/])\bT(\d{4})(?:\.(\d{3}))?\b/g, (x, a, b) => `<a href="https://attack.mitre.org/techniques/T${a}/${b ? b + '/' : ''}" ${ext}>${x}</a>`)
      .replace(/RFC (\d{3,5})/g, (x, n) => `<a href="https://www.rfc-editor.org/rfc/rfc${n}" ${ext}>${x}</a>`);
  }
  function nodeSVG(n) {
    return `<g class="node ${nodeCls(n)}" data-id="${n.id}" transform="translate(${n.x},${n.y})">
      <title>${esc(n.label)} ${esc(n.sub || '')}</title>
      <rect class="tile" x="-38" y="-38" width="76" height="76" rx="14"/>
      <g class="ico" transform="translate(-22,-22) scale(0.9167)">${icon(n.type)}</g>
      <text class="lbl" y="58">${esc(n.label)}</text><text class="sub" y="74">${esc(n.sub || '')}</text></g>`;
  }
  // Crop the 900x500 layout to the nodes actually used, keeping a minimum height/width ratio.
  function fitBox(m, ratio) {
    const xs = m.nodes.map((n) => n.x), ys = m.nodes.map((n) => n.y);
    const x0 = Math.min(...xs) - 100, w = Math.max(...xs) - Math.min(...xs) + 200;
    let y0 = Math.min(...ys) - 70, h = Math.max(...ys) - Math.min(...ys) + 170;
    if (h < w * ratio) { y0 -= (w * ratio - h) / 2; h = w * ratio; }
    return `${x0} ${Math.round(y0)} ${w} ${Math.round(h)}`;
  }
  const kindTag = (m) => `<span class="kind kind-${m.kind}">${KIND_NAME[m.kind] || esc(m.kind)}</span>`;

  /* ---------- routing ---------- */
  let lastPath = location.pathname;
  function route() {
    closeDrawer(); closePalette(); closeNav();
    lastPath = location.pathname;
    const parts = location.pathname.split('/').filter(Boolean);
    const [a, b, c] = parts;
    if (!a) return showPage(homeHTML(), '', 'home');
    if (a === 'modules') {
      if (b && !LIVE.some((d) => d.id === b)) return showPage(notFoundHTML(), 'Not found');
      return showPage(catalogHTML(b), b ? domainOf(b).name : 'Modules', 'modules');
    }
    if (a === 'paths') {
      showPage(pathsHTML(), 'Learning paths', 'paths');
      if (b) $(`#path-${CSS.escape(b)}`)?.scrollIntoView();
      return;
    }
    if (a === 'glossary') {
      showPage(glossaryHTML(), 'Glossary', 'glossary');
      const h = decodeURIComponent(location.hash.slice(1));
      if (h) ($(`#${CSS.escape(h)}`) || $(`#g-${CSS.escape(h)}`))?.scrollIntoView();
      return;
    }
    if (a === 'about') return showPage(aboutHTML(), 'About', 'about');
    if (a === 'm' && byId[b]) return openModule(byId[b], parseInt(c, 10) || 0);
    showPage(notFoundHTML(), 'Not found');
  }
  function syncHash() {
    const m = st.mod; if (!m) return;
    history.replaceState(null, '', `/m/${m.id}${st.step >= 0 ? '/' + (st.step + 1) : ''}`);
  }
  function setNav(key) {
    $$('#mainNav [data-nav]').forEach((a) => a.classList.toggle('on', a.dataset.nav === key));
  }

  /* ---------- pages ---------- */
  function showPage(html, title, nav) {
    stop(); st.mod = null;
    $('#explorer').hidden = true;
    const p = $('#page'); p.hidden = false; p.innerHTML = html;
    document.title = title ? `${title} · ${SITE}` : `${SITE}: interactive security walkthroughs`;
    document.body.dataset.view = 'page';
    setNav(nav);
    window.scrollTo(0, 0);
  }

  function homeHTML() {
    const start = byId.sqli || MODS[0];
    const feat = byId.ssrf || start;
    const si = Math.min(2, feat.steps.length - 1);
    const total = MODS.reduce((a, m) => a + m.steps.length, 0);
    return `
      <section class="hero">
        <div class="hero-copy">
          <h1>Security concepts, one packet at a time.</h1>
          <p class="lead">Step-by-step walkthroughs of real attacks, protocols and defenses. Each module shows who sends what to whom, explains why it works, and finishes with how to fix it.</p>
          <div class="hero-actions">
            <a class="btn primary lg" href="/modules">Browse modules</a>
            <a class="btn lg" href="/m/${start.id}">Try ${esc(start.name)}</a>
          </div>
          <p class="hero-note">${MODS.length} modules and ${total} steps across ${LIVE.length} topics. Nothing to install, no sign-up.</p>
        </div>
        <a class="preview" href="/m/${feat.id}/${si + 1}">
          <div class="preview-top"><span class="dots"><i></i><i></i><i></i></span><span>${esc(feat.name)}</span></div>
          ${previewSVG(feat, si)}
          <div class="preview-cap"><span>Step ${si + 1} of ${feat.steps.length}</span><b>${esc(feat.steps[si].title)}</b></div>
        </a>
      </section>

      <section class="section">
        <div class="section-head"><h2>Learning paths</h2><a href="/paths">See all paths</a></div>
        <div class="grid-3">${SE.paths.slice(0, 3).map(pathCard).join('')}</div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Browse by topic</h2><a href="/modules">All modules</a></div>
        <div class="topics">${LIVE.map(topicRow).join('')}</div>
      </section>

      <section class="section split">
        <div>
          <h2>How a module works</h2>
          <p>Press play and watch the exchange happen on a network diagram, or switch to a sequence diagram. The side panel explains each step in plain language, and the packet table below works like a simplified Wireshark: click a row marked “payload” to see what was actually sent.</p>
          <p>Every attack ends on the fix, with links to the matching CWE, OWASP and MITRE entries so you can go deeper.</p>
        </div>
        <ul class="legend-list">
          ${Object.entries(SE.kinds).map(([k, v]) => `<li class="k-${k}"><span class="swatch"></span>${esc(v.label)}</li>`).join('')}
        </ul>
      </section>`;
  }

  function previewSVG(m, si) {
    prepare(m);
    const pk = m.steps[si].packets.filter((p) => p.f !== p.t);
    const map = m.nodeMap, slot = 1.1, T = pk.length * slot + 1.2;
    const pairs = new Set(pk.map((p) => [p.f, p.t].sort().join('|')));
    let h = `<svg viewBox="${fitBox(m, 0.5)}" class="preview-svg" aria-hidden="true">`;
    pairs.forEach((k) => { const [a, b] = k.split('|').map((i) => map[i]); h += `<line class="edge on" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>`; });
    h += m.nodes.map(nodeSVG).join('');
    pk.forEach((p, i) => {
      const A = map[p.f], B = map[p.t];
      const s = +((i * slot) / T).toFixed(4), e = +((i * slot + 0.9) / T).toFixed(4);
      const op = s === 0 ? `values="1;0" keyTimes="0;${e}"` : `values="0;1;0" keyTimes="0;${s};${e}"`;
      h += `<g class="pkt k-${p.kind}" opacity="0"><circle class="halo" r="14"/><circle r="7"/>
        <animateMotion dur="${T}s" repeatCount="indefinite" path="M${A.x} ${A.y} L${B.x} ${B.y}" keyPoints="0;0;1;1" keyTimes="0;${s};${e};1" calcMode="linear"/>
        <animate attributeName="opacity" dur="${T}s" repeatCount="indefinite" calcMode="discrete" ${op}/></g>`;
    });
    return h + '</svg>';
  }

  function pathCard(p) {
    const ms = pathMods(p);
    return `<a class="card path-card" href="/paths/${p.id}">
      <span class="eyebrow">${esc(p.level)} path</span>
      <h3>${esc(p.title)}</h3>
      <p>${esc(p.desc)}</p>
      <span class="card-foot">${ms.length} modules · about ${ms.reduce((a, m) => a + minutes(m), 0)} min${ms.some((m) => isDone(m.id)) ? ` · ${ms.filter((m) => isDone(m.id)).length}/${ms.length} done` : ''}</span>
    </a>`;
  }
  function topicRow(d) {
    const n = modsIn(d.id).length;
    return `<a class="topic" href="/modules/${d.id}">
      <span class="topic-ico"><svg viewBox="0 0 48 48" aria-hidden="true">${icon(d.icon)}</svg></span>
      <span class="topic-text"><b>${esc(d.name)}</b><small>${esc(d.blurb)}</small></span>
      <span class="topic-count">${n} module${n === 1 ? '' : 's'}</span>
    </a>`;
  }
  function mcard(m) {
    return `<a class="card mcard" href="/m/${m.id}">
      <div class="mcard-meta">${kindTag(m)}<span>${esc(domainOf(m.domain).short)}</span></div>
      <h3>${esc(m.name)}</h3>
      <p>${esc(m.full)}</p>
      <div class="card-foot"><span>${esc(m.level || '')}${doneTag(m.id)}</span><span>${m.steps.length} steps · ${minutes(m)} min</span></div>
    </a>`;
  }

  function catalogHTML(dom) {
    const d = dom && domainOf(dom);
    const list = MODS.filter((m) => (!dom || m.domain === dom) && (st.level === 'all' || m.level === st.level));
    return `
      <header class="page-head">
        <p class="crumbs-inline"><a href="/">Home</a> / ${d ? '<a href="/modules">Modules</a> / ' : ''}<span>${d ? esc(d.name) : 'Modules'}</span></p>
        <h1>${d ? esc(d.name) : 'All modules'}</h1>
        <p class="lead">${d ? esc(d.blurb) : `${MODS.length} interactive walkthroughs across ${LIVE.length} topics. Pick one, press play.`}</p>
      </header>
      <div class="filters">
        <div class="filter-row" role="group" aria-label="Topic">
          <a class="chip ${!dom ? 'on' : ''}" href="/modules">All topics</a>
          ${LIVE.map((x) => `<a class="chip ${x.id === dom ? 'on' : ''}" href="/modules/${x.id}">${esc(x.short)}</a>`).join('')}
        </div>
        <div class="filter-row" role="group" aria-label="Level">
          ${['all', ...LEVELS].map((l) => `<button class="chip ${st.level === l ? 'on' : ''}" data-level="${l}" type="button">${l === 'all' ? 'Any level' : l}</button>`).join('')}
        </div>
      </div>
      <p class="result-count">${list.length} module${list.length === 1 ? '' : 's'}</p>
      ${list.length ? `<div class="grid-cards">${list.map(mcard).join('')}</div>` : '<p class="muted">No modules match these filters yet.</p>'}`;
  }

  function pathsHTML() {
    return `
      <header class="page-head">
        <p class="crumbs-inline"><a href="/">Home</a> / <span>Learning paths</span></p>
        <h1>Learning paths</h1>
        <p class="lead">Short, ordered sets of modules. Each one builds on the last, so it's worth going top to bottom.</p>
      </header>
      ${SE.paths.map((p) => {
        const ms = pathMods(p);
        if (!ms.length) return '';
        const done = ms.filter((m) => isDone(m.id)).length, nextUp = ms.find((m) => !isDone(m.id)) || ms[0];
        return `<section class="path" id="path-${p.id}">
          <div class="path-head">
            <div><span class="eyebrow">${esc(p.level)}${done ? ` · ${done} of ${ms.length} done` : ''}</span><h2>${esc(p.title)}</h2><p>${esc(p.desc)}</p>
              ${done ? `<div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="${ms.length}" aria-valuenow="${done}"><span style="width:${Math.round((done / ms.length) * 100)}%"></span></div>` : ''}</div>
            <a class="btn" href="/m/${nextUp.id}">${done === 0 ? 'Start path' : done === ms.length ? 'Review path' : 'Continue'}</a>
          </div>
          <ol class="path-list">${ms.map((m, i) => `<li><a href="/m/${m.id}">
            <span class="idx${isDone(m.id) ? ' done' : ''}">${isDone(m.id) ? '✓' : i + 1}</span>
            <span class="t"><b>${esc(m.name)}</b><small>${esc(m.full)}</small></span>
            <span class="meta">${kindTag(m)}<span>${minutes(m)} min</span></span></a></li>`).join('')}</ol>
        </section>`;
      }).join('')}
      ${Object.keys(progress).length ? '<p class="reset-row"><button class="link-btn" data-act="reset-progress" type="button">Reset my progress</button></p>' : ''}`;
  }

  function glossaryHTML() {
    const items = SE.glossary.slice().sort((a, b) => a.term.localeCompare(b.term));
    const letters = [...new Set(items.map((g) => g.term[0].toUpperCase()))];
    return `
      <header class="page-head">
        <p class="crumbs-inline"><a href="/">Home</a> / <span>Glossary</span></p>
        <h1>Glossary</h1>
        <p class="lead">Plain-language definitions of the terms used across the site, with links to the modules that show them in action.</p>
      </header>
      <div class="gloss-tools">
        <input id="glossFilter" type="search" placeholder="Filter terms, e.g. TTL" aria-label="Filter glossary terms" autocomplete="off">
        <nav class="gloss-letters" aria-label="Jump to letter">${letters.map((l) => `<a href="#gl-${l}">${l}</a>`).join('')}</nav>
      </div>
      <div class="gloss">${items.map((g, i) => {
        const L = g.term[0].toUpperCase(), first = i === 0 || items[i - 1].term[0].toUpperCase() !== L;
        const see = g.see.map((id) => byId[id]).filter(Boolean);
        return `${first ? `<h2 class="gloss-letter" id="gl-${L}">${L}</h2>` : ''}<dl class="gloss-item" id="g-${g.id}" data-text="${esc((g.term + ' ' + g.def).toLowerCase())}">
          <dt>${esc(g.term)}</dt><dd>${fmt(g.def)}${see.length ? `<span class="gloss-see">See: ${see.map((m) => `<a href="/m/${m.id}">${esc(m.name)}</a>`).join(', ')}</span>` : ''}</dd></dl>`;
      }).join('')}</div>
      <p class="muted gloss-empty" hidden>No terms match.</p>`;
  }

  function aboutHTML() {
    const k = (s) => `<kbd>${s}</kbd>`;
    return `
      <article class="prose">
        <p class="crumbs-inline"><a href="/">Home</a> / <span>About</span></p>
        <h1>About ${esc(SITE)}</h1>
        <p class="lead">${esc(SITE)} is a free, open learning site for anyone getting into security: students, developers, analysts and people switching careers.</p>
        <p>Most security material either describes an attack in a paragraph or drops you straight into a lab. This site sits in between. Each module plays out one attack, protocol or defense message by message, so you can see what each machine sends, read why it matters, and look at the actual request or payload. Attack modules always finish with the fix.</p>

        <h2>Using a module</h2>
        <ul>
          <li><b>Play</b> runs the whole walkthrough. <b>Next step</b> moves one step at a time.</li>
          <li>Switch between the <b>Network</b> diagram and a <b>Sequence</b> diagram at the top of the stage.</li>
          <li>Rows in the packet table marked “payload” can be expanded to show the raw message.</li>
          <li>Every step has its own link, e.g. <code>securityexplorer.org/m/sqli/3</code>, so you can share exactly what you're looking at.</li>
        </ul>
        <table class="kv about-keys">
          <tr><th>${k('Space')}</th><td>Play / pause</td></tr>
          <tr><th>${k('→')} ${k('←')}</th><td>Next / previous step</td></tr>
          <tr><th>${k('/')} or ${k(isMac() ? '⌘' : 'Ctrl')} ${k('K')}</th><td>Search modules</td></tr>
          <tr><th>${k('Esc')}</th><td>Close search or the module list</td></tr>
        </table>

        <h2>Colours in the diagrams</h2>
        <ul class="legend-list">${Object.entries(SE.kinds).map(([kk, v]) => `<li class="k-${kk}"><span class="swatch"></span>${esc(v.label)}</li>`).join('')}</ul>

        <h2>Use it responsibly</h2>
        <p>Everything here explains how things work so you can build and defend systems better. Only test systems you own or have written permission to test. If you want hands-on practice, use purpose-built labs and capture-the-flag platforms.</p>

        <h2>Sources</h2>
        <p>Modules reference these public standards and knowledge bases. Codes in each module link straight to the matching entry.</p>
        <ul>
          <li><a href="https://owasp.org/www-project-top-ten/" ${ext}>OWASP Top 10</a>, <a href="https://owasp.org/API-Security/" ${ext}>OWASP API Security Top 10</a> and <a href="https://genai.owasp.org/" ${ext}>OWASP Top 10 for LLM Applications</a></li>
          <li><a href="https://cwe.mitre.org/" ${ext}>MITRE CWE</a>, <a href="https://attack.mitre.org/" ${ext}>MITRE ATT&amp;CK</a> and <a href="https://atlas.mitre.org/" ${ext}>MITRE ATLAS</a></li>
          <li><a href="https://www.rfc-editor.org/" ${ext}>IETF RFCs</a> for protocol details</li>
        </ul>
        <p>IP addresses and domains in the examples come from ranges reserved for documentation, so they don't point at anyone's real systems.</p>

        <h2>Privacy</h2>
        <p>No accounts, ads or cookies. Visits are counted anonymously with <a href="https://www.goatcounter.com/" ${ext}>GoatCounter</a>, which doesn't use cookies or collect personal data. Your theme choice, completed modules and quiz scores are saved only in your own browser, never sent anywhere.</p>      </article>`;
  }

  const notFoundHTML = () => `
    <div class="empty-state">
      <p class="eyebrow">404</p>
      <h1>We couldn't find that page</h1>
      <p class="lead">The link may be out of date, or the module may have been renamed.</p>
      <a class="btn primary" href="/modules">Browse modules</a>
    </div>`;

  /* ---------- drawer ---------- */
  function openDrawer() {
    st.tab = st.mod?.domain || 'all';
    renderDrawer();
    $('#drawer').classList.add('open'); $('#drawer').setAttribute('aria-hidden', 'false'); $('#scrim').hidden = false;
    setTimeout(() => $('#list .item.cur')?.scrollIntoView({ block: 'center' }), 260);
  }
  function closeDrawer() {
    $('#drawer').classList.remove('open'); $('#drawer').setAttribute('aria-hidden', 'true'); $('#scrim').hidden = true;
  }
  function renderDrawer() {
    $('#tabs').innerHTML = [{ id: 'all', short: 'All' }, ...LIVE].map((d) =>
      `<button class="chip${st.tab === d.id ? ' on' : ''}" data-tab="${d.id}" type="button">${esc(d.short)}</button>`).join('');
    const doms = st.tab === 'all' ? LIVE : LIVE.filter((d) => d.id === st.tab);
    $('#list').innerHTML = doms.map((d) => `<div class="dom">${esc(d.name)}</div>` + modsIn(d.id).map((m) => {
      const cur = st.mod === m;
      return `<a class="item${cur ? ' cur' : ''}" href="/m/${m.id}"><span class="kind-dot kind-${m.kind}"></span><span><b>${esc(m.name)}${isDone(m.id) ? ' <span class="done-tag">✓</span>' : ''}</b><small>${esc(m.full)}</small></span></a>` +
        (cur ? `<ol class="substeps">${m.steps.map((s, i) => `<li><button data-step="${i}" class="${i === st.step ? 'cur' : ''}" type="button">${i + 1}. ${esc(s.title)}</button></li>`).join('')}</ol>` : '');
    }).join('')).join('');
  }

  /* ---------- search palette ---------- */
  let palIdx = 0, palItems = [];
  function search(q) {
    q = q.trim().toLowerCase();
    if (!q) return MODS.slice(0, 8);
    return MODS.map((m) => {
      const hay = [m.name, m.full, m.domain, domainOf(m.domain)?.name, m.level, ...(m.tags || []), ...(m.facts || []).map((f) => f[1])].join(' ').toLowerCase();
      const score = m.name.toLowerCase().startsWith(q) ? 4 : m.name.toLowerCase().includes(q) ? 3 : m.full.toLowerCase().includes(q) ? 2 : hay.includes(q) ? 1 : 0;
      return { m, score };
    }).filter((r) => r.score).sort((a, b) => b.score - a.score).slice(0, 10).map((r) => r.m);
  }
  function openPalette() {
    $('#palette').hidden = false; document.body.classList.add('no-scroll');
    $('#palInput').value = ''; renderPalette(); $('#palInput').focus();
  }
  function closePalette() { $('#palette').hidden = true; document.body.classList.remove('no-scroll'); }
  function renderPalette() {
    const q = $('#palInput').value;
    palItems = search(q); palIdx = 0;
    $('#palList').innerHTML = (q.trim() ? '' : '<li class="pal-label">Suggested</li>') + (palItems.length
      ? palItems.map((m, i) => `<li><a href="/m/${m.id}" class="${i === 0 ? 'sel' : ''}" data-i="${i}"><span class="kind-dot kind-${m.kind}"></span><span class="t"><b>${esc(m.name)}</b><small>${esc(m.full)}</small></span><span class="pal-meta">${esc(domainOf(m.domain).short)}</span></a></li>`).join('')
      : `<li class="pal-empty">No modules match “${esc(q)}”.</li>`);
  }
  function movePalette(d) {
    if (!palItems.length) return;
    palIdx = (palIdx + d + palItems.length) % palItems.length;
    $$('#palList a').forEach((a, i) => a.classList.toggle('sel', i === palIdx));
    $(`#palList a[data-i="${palIdx}"]`)?.scrollIntoView({ block: 'nearest' });
  }

  /* ---------- explorer ---------- */
  function openModule(m, stepNo) {
    $('#page').hidden = true; $('#explorer').hidden = false;
    document.body.dataset.view = 'explorer';
    setNav('modules');
    if (st.mod !== m) {
      stop(); st.mod = prepare(m); st.step = -1; st.shown = 0; st.quiz = null;
      document.title = `${m.name} · ${SITE}`;
      renderCrumbs(); renderDiagram(); renderLegend(); renderRows();
      window.scrollTo(0, 0);
    }
    if (stepNo > 0 && stepNo <= m.steps.length) showStepInstant(stepNo - 1);
    else { stop(); st.step = -1; st.shown = 0; renderRows(); refresh(); }
  }
  function renderCrumbs() {
    const m = st.mod, d = domainOf(m.domain);
    $('#crumbs').innerHTML = `<a href="/modules">Modules</a><span>/</span><a href="/modules/${d.id}">${esc(d.name)}</a><span>/</span><b>${esc(m.name)}</b>`;
  }
  function renderDiagram() {
    const m = st.mod, pairs = new Set();
    m.flat.forEach((p) => { if (p.f !== p.t) pairs.add([p.f, p.t].sort().join('|')); });
    let h = '<g class="edges">';
    pairs.forEach((k) => {
      const [a, b] = k.split('|').map((id) => m.nodeMap[id]);
      h += `<line class="edge" data-k="${k}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>`;
    });
    $('#diagram').setAttribute('viewBox', fitBox(m, 0.42));
    $('#diagram').innerHTML = h + '</g><g class="nodes">' + m.nodes.map(nodeSVG).join('') + '</g><g id="fly"></g>';
  }
  function renderLegend() {
    const used = new Set(st.mod.flat.map((p) => p.kind));
    $('#legend').innerHTML = Object.entries(SE.kinds).filter(([k]) => used.has(k)).map(([k, v]) => `<span class="k-${k}">${esc(v.label)}</span>`).join('');
  }
  function highlight() {
    const m = st.mod, i = st.step, step = m.steps[i];
    const focus = new Set(step ? step.focus || step.packets.flatMap((p) => [p.f, p.t]) : []);
    const edges = new Set(step ? step.packets.filter((p) => p.f !== p.t).map((p) => [p.f, p.t].sort().join('|')) : []);
    $$('#diagram .node').forEach((g) => {
      g.classList.toggle('on', focus.has(g.dataset.id));
      g.classList.toggle('dim', i >= 0 && !focus.has(g.dataset.id));
    });
    $$('#diagram .edge').forEach((e) => e.classList.toggle('on', edges.has(e.dataset.k)));
  }
  function renderStepper() {
    $('#stepper').innerHTML = st.mod.steps.map((s, i) =>
      `<li class="${i < st.step ? 'done' : ''}${i === st.step ? ' cur' : ''}"><button data-step="${i}" type="button"><span class="n">${i + 1}</span>${esc(s.title)}</button></li>`).join('');
    const cur = $('#stepper .cur');
    if (cur) { const ol = $('#stepper'); ol.scrollLeft = cur.offsetLeft - ol.clientWidth / 2 + cur.clientWidth / 2; }
  }
  function renderDetails() {
    const m = st.mod, d = domainOf(m.domain), el = $('#details');
    if (st.quiz && st.step === m.steps.length - 1 && SE.quizzes?.[m.id]) return renderQuiz();
    if (st.step < 0) {
      el.innerHTML = `
        <p class="eyebrow">${esc(d?.name)}</p>
        <h1 class="d-title">${esc(m.name)}</h1>
        <p class="subt">${esc(m.full)}</p>
        <div class="badges">${kindTag(m)}${m.level ? `<span class="badge">${esc(m.level)}</span>` : ''}<span class="badge">${m.steps.length} steps · ${minutes(m)} min</span></div>
        <p>${fmt(m.summary)}</p>
        <button class="btn primary block" data-act="start" type="button">Start walkthrough</button>
        <h2 class="d-sub">Key facts</h2>
        <table class="kv">${(m.facts || []).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${linkify(v)}</td></tr>`).join('')}</table>
        ${m.defenses?.length ? `<div class="box"><h2>${DEF_TITLE[m.kind] || 'Defenses'}</h2><ul>${m.defenses.map((x) => `<li>${fmt(x)}</li>`).join('')}</ul></div>` : ''}`;
      return;
    }
    const s = m.steps[st.step], last = st.step === m.steps.length - 1;
    const next = MODS[MODS.indexOf(m) + 1];
    const quiz = SE.quizzes?.[m.id], best = progress[m.id]?.quiz;
    el.innerHTML = `
      <div class="d-head"><p class="eyebrow">Step ${st.step + 1} of ${m.steps.length}</p><button class="link-btn" data-act="overview" type="button">Overview</button></div>
      <h1 class="d-title">${esc(s.title)}</h1>
      <p class="subt">${esc(s.sub || '')}</p>
      <p>${fmt(s.text)}</p>
      ${s.fields?.length ? `<table class="kv">${s.fields.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${fmt(v)}</td></tr>`).join('')}</table>` : ''}
      ${s.defend ? `<div class="box"><h2>Defender's note</h2><p>${fmt(s.defend)}</p></div>` : ''}
      ${last ? `${quiz ? `<button class="btn primary block" data-act="quiz" type="button">${best != null ? `Retake the quiz · best ${best}/${quiz.length}` : `Check your understanding · ${quiz.length} questions`}</button>` : ''}
        <div class="d-actions"><button class="btn" data-act="overview" type="button">Review the defenses</button>${next ? `<a class="btn${quiz ? '' : ' primary'}" href="/m/${next.id}">Next: ${esc(next.name)}</a>` : ''}</div>` : ''}`;
  }

  function renderQuiz() {
    const m = st.mod, qs = SE.quizzes[m.id], z = st.quiz, el = $('#details');
    const next = MODS[MODS.indexOf(m) + 1];
    if (z.i >= qs.length) {
      const best = Math.max(z.score, progress[m.id]?.quiz ?? 0);
      progress[m.id] = { ...(progress[m.id] || {}), done: true, quiz: best }; saveProgress();
      el.innerHTML = `
        <div class="d-head"><p class="eyebrow">Quiz complete</p><button class="link-btn" data-act="quiz-exit" type="button">Back to the step</button></div>
        <h1 class="d-title">${z.score} of ${qs.length} correct</h1>
        <p class="subt">${z.score === qs.length ? 'Perfect score. Nicely done.' : 'Review the steps and try again any time.'}</p>
        <div class="d-actions"><button class="btn" data-act="quiz" type="button">Try again</button>${next ? `<a class="btn primary" href="/m/${next.id}">Next: ${esc(next.name)}</a>` : ''}</div>`;
      return;
    }
    const [q, opts, ans, why] = qs[z.i], picked = z.picked;
    el.innerHTML = `
      <div class="d-head"><p class="eyebrow">Question ${z.i + 1} of ${qs.length}</p><button class="link-btn" data-act="quiz-exit" type="button">Exit quiz</button></div>
      <h1 class="d-title quiz-q">${fmt(q)}</h1>
      <div class="quiz-opts" role="group" aria-label="Answers">${opts.map((o, i) => {
        const cls = picked == null ? '' : i === ans ? ' right' : i === picked ? ' wrong' : ' dim';
        return `<button class="quiz-opt${cls}" data-ans="${i}" type="button"${picked != null ? ' disabled' : ''}>${fmt(o)}</button>`;
      }).join('')}</div>
      ${picked != null ? `<div class="box${picked === ans ? '' : ' warn'}"><h2>${picked === ans ? 'Correct' : 'Not quite'}</h2><p>${fmt(why)}</p></div>
      <button class="btn primary block" data-act="quiz-next" type="button">${z.i + 1 < qs.length ? 'Next question' : 'See your score'}</button>` : ''}`;
    if (picked != null) $('#details [data-act="quiz-next"]')?.focus();
  }

  function rowHTML(p, isNew) {
    const m = st.mod, F = m.nodeMap[p.f], T = m.nodeMap[p.t];
    return `<tr class="row k-${p.kind}${p.raw ? ' has-raw' : ''}${isNew ? ' new' : ''}" data-no="${p.no}"${p.raw ? ' tabindex="0"' : ''}>
      <td><span class="no">${p.no}</span></td><td>${p.time.toFixed(3)}</td>
      <td title="${esc(F.sub)}">${esc(F.label)}</td><td title="${esc(T.sub)}">${esc(T.label)}</td>
      <td><span class="proto">${esc(p.proto)}</span></td><td class="info">${esc(p.info)}${p.raw ? ' <span class="raw-tag">payload</span>' : ''}</td><td class="num">${size(p.size)}</td></tr>`;
  }
  function renderRows() {
    const shown = st.mod.flat.slice(0, st.shown);
    $('#rows').innerHTML = shown.length ? shown.map((p) => rowHTML(p)).join('') : '<tr class="empty"><td colspan="7">Nothing on the wire yet. Press play to start.</td></tr>';
    renderSequence();
  }
  function appendRow(p) {
    $('#rows .empty')?.remove();
    $('#rows').insertAdjacentHTML('beforeend', rowHTML(p, true));
    const w = $('.table-wrap'); w.scrollTop = w.scrollHeight;
    renderSequence();
  }
  function toggleRaw(tr) {
    const p = st.mod.flat[+tr.dataset.no - 1];
    if (tr.classList.toggle('open')) tr.insertAdjacentHTML('afterend', `<tr class="raw"><td colspan="7"><pre>${esc(p.raw)}</pre></td></tr>`);
    else if (tr.nextElementSibling?.classList.contains('raw')) tr.nextElementSibling.remove();
  }

  function renderSequence() {
    const box = $('#seq'); if (box.hidden || !st.mod) return;
    const m = st.mod, used = [];
    m.flat.forEach((p) => [p.f, p.t].forEach((id) => { if (!used.includes(id)) used.push(id); }));
    const lane = 190, pad = 90, top = 70, rowH = 36;
    const shown = m.flat.slice(0, st.shown);
    const W = pad * 2 + lane * (used.length - 1), H = top + Math.max(shown.length, 1) * rowH + 30;
    const x = (id) => pad + used.indexOf(id) * lane;
    let h = `<svg xmlns="${NS}" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><defs>` +
      Object.keys(SE.kinds).map((k) => `<marker id="ah-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" style="fill:var(--k-${k})"/></marker>`).join('') + '</defs>';
    used.forEach((id) => {
      const n = m.nodeMap[id];
      h += `<line class="life" x1="${x(id)}" y1="40" x2="${x(id)}" y2="${H - 8}"/><g class="phead ${nodeCls(n)}" transform="translate(${x(id)},24)"><rect x="-80" y="-16" width="160" height="32" rx="8"/><text y="4">${esc(n.label)}</text></g>`;
    });
    if (!shown.length) h += `<text class="seq-empty" x="${pad}" y="${top + 16}">Messages appear here as the walkthrough plays.</text>`;
    shown.forEach((p, k) => {
      const y = top + k * rowH + 14, label = `${p.no}. ${p.proto} · ${p.info}`;
      if (p.f === p.t) {
        const X = x(p.f);
        h += `<g class="k-${p.kind}"><path class="arrow" d="M${X} ${y - 8} h26 v14 h-22" marker-end="url(#ah-${p.kind})"/><text class="alabel" x="${X + 32}" y="${y + 3}"><title>${esc(label)}</title>${esc(trim(label, 40))}</text></g>`;
      } else {
        const x1 = x(p.f), x2 = x(p.t), dir = Math.sign(x2 - x1);
        h += `<g class="k-${p.kind}"><line class="arrow" x1="${x1}" y1="${y}" x2="${x2 - dir * 2}" y2="${y}" marker-end="url(#ah-${p.kind})"/><text class="alabel c" x="${(x1 + x2) / 2}" y="${y - 6}"><title>${esc(label)}</title>${esc(trim(label, Math.floor(Math.abs(x2 - x1) / 6.8)))}</text></g>`;
      }
    });
    box.innerHTML = h + '</svg>';
    box.scrollTop = box.scrollHeight;
  }
  const trim = (s, n) => (s.length > n ? s.slice(0, Math.max(n - 1, 4)) + '…' : s);

  function refresh() {
    if (st.mod && st.step === st.mod.steps.length - 1) markDone(st.mod.id);
    renderStepper(); renderDetails(); highlight(); updatePlay(); syncHash();
    if ($('#drawer').classList.contains('open')) renderDrawer();
  }
  function setView(v) {
    st.view = v;
    $$('.seg button').forEach((b) => { b.classList.toggle('on', b.dataset.view === v); b.setAttribute('aria-selected', b.dataset.view === v); });
    $('#diagram').toggleAttribute('hidden', v !== 'network');
    $('#seq').toggleAttribute('hidden', v !== 'sequence');
    renderSequence();
  }

  /* ---------- playback ---------- */
  function fly(p, tok) {
    const m = st.mod, A = m.nodeMap[p.f], B = m.nodeMap[p.t], dur = 900 / st.speed;
    const layer = $('#fly');
    if (st.view !== 'network' || !layer) return sleep(dur * 0.6);
    if (p.f === p.t) {
      const g = $(`#diagram .node[data-id="${p.f}"]`);
      g?.classList.add('pulse', `k-${p.kind}`);
      return sleep(dur * 0.9).then(() => g?.classList.remove('pulse', `k-${p.kind}`));
    }
    return new Promise((resolve) => {
      const g = document.createElementNS(NS, 'g');
      g.setAttribute('class', `pkt k-${p.kind}`);
      g.innerHTML = `<circle class="halo" r="13"/><circle r="6.5"/><text y="-17">${esc(p.proto)}</text>`;
      layer.appendChild(g);
      const t0 = performance.now();
      const tick = (now) => {
        if (tok !== st.token) { g.remove(); return resolve(); }
        const u = Math.min(1, (now - t0) / dur), e = u < 0.5 ? 2 * u * u : 1 - Math.pow(-2 * u + 2, 2) / 2;
        g.setAttribute('transform', `translate(${A.x + (B.x - A.x) * e},${A.y + (B.y - A.y) * e})`);
        if (u < 1) return requestAnimationFrame(tick);
        g.remove();
        const nb = $(`#diagram .node[data-id="${p.t}"]`);
        nb?.classList.remove('hit'); void nb?.getBoundingClientRect(); nb?.classList.add('hit');
        resolve();
      };
      requestAnimationFrame(tick);
    });
  }
  async function runStep(i) {
    const tok = ++st.token, m = st.mod;
    st.quiz = null;
    const f = $('#fly'); if (f) f.innerHTML = '';
    const start = m.stepStart[i], end = m.stepStart[i + 1];
    st.step = i;
    if (st.shown < start || st.shown > end) { st.shown = start; renderRows(); }
    refresh();
    for (let k = st.shown; k < end; k++) {
      await fly(m.flat[k], tok);
      if (tok !== st.token) return;
      st.shown = k + 1; appendRow(m.flat[k]);
      await sleep(180 / st.speed);
      if (tok !== st.token) return;
    }
    if (!st.playing) return;
    await sleep(1600 / st.speed);
    if (tok !== st.token || !st.playing) return;
    if (i + 1 < m.steps.length) runStep(i + 1);
    else { st.playing = false; updatePlay(); }
  }
  function showStepInstant(i) { stop(); st.quiz = null; st.step = i; st.shown = st.mod.stepStart[i + 1]; renderRows(); refresh(); }
  function stop() { st.playing = false; st.token++; const f = $('#fly'); if (f) f.innerHTML = ''; updatePlay(); }
  function play() {
    const m = st.mod; if (!m) return;
    st.playing = true;
    const end = st.step >= 0 ? m.stepStart[st.step + 1] : 0;
    if (st.step < 0) runStep(0);
    else if (st.shown < end) runStep(st.step);
    else if (st.step + 1 < m.steps.length) runStep(st.step + 1);
    else { st.shown = 0; renderRows(); runStep(0); }
  }
  const togglePlay = () => (st.playing ? stop() : play());
  function stepFwd() { if (!st.mod) return; stop(); if (st.step + 1 < st.mod.steps.length) runStep(st.step + 1); }
  function stepBack() {
    if (!st.mod) return;
    if (st.step <= 0) { stop(); st.step = -1; st.shown = 0; renderRows(); refresh(); } else showStepInstant(st.step - 1);
  }
  function reset() { stop(); st.step = -1; st.shown = 0; renderRows(); refresh(); }
  function updatePlay() {
    const b = $('#playBtn'); if (!b) return;
    b.innerHTML = st.playing
      ? '<svg viewBox="0 0 24 24" class="i"><path d="M8 5v14M16 5v14"/></svg><span>Pause</span>'
      : '<svg viewBox="0 0 24 24" class="i fill"><path d="M7 5v14l11-7z"/></svg><span>Play</span>';
  }

  /* ---------- chrome ---------- */
  const isMac = () => /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  function closeNav() { $('#siteHeader').classList.remove('nav-open'); $('#navToggle').setAttribute('aria-expanded', 'false'); }
  function initChrome() {
    $('#kbdHint').textContent = isMac() ? '⌘K' : 'Ctrl K';
    $('#year').textContent = new Date().getFullYear();
    $('#footerTopics').innerHTML = LIVE.map((d) => `<a href="/modules/${d.id}">${esc(d.name)}</a>`).join('');
  }

  /* ---------- events ---------- */
  document.addEventListener('click', (e) => {
    const link = e.target.closest('a[href^="/"]');
    if (link && !link.target && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey && e.button === 0) {
      e.preventDefault();
      return navigate(link.getAttribute('href'));
    }
    const t = e.target.closest('button, a, tr.row');
    if (!t) return;
    if (t.dataset.level) { st.level = t.dataset.level; return route(); }
    if (t.dataset.tab) { st.tab = t.dataset.tab; return renderDrawer(); }
    if (t.dataset.step !== undefined && st.mod) { closeDrawer(); return showStepInstant(+t.dataset.step); }
    if (t.dataset.view) return setView(t.dataset.view);
    if (t.dataset.ans !== undefined && st.quiz) {
      if (st.quiz.picked == null) {
        st.quiz.picked = +t.dataset.ans;
        if (st.quiz.picked === SE.quizzes[st.mod.id][st.quiz.i][2]) st.quiz.score++;
      }
      return renderDetails();
    }
    if (t.dataset.act === 'quiz') { stop(); st.quiz = { i: 0, picked: null, score: 0 }; return renderDetails(); }
    if (t.dataset.act === 'quiz-next') { st.quiz.i++; st.quiz.picked = null; return renderDetails(); }
    if (t.dataset.act === 'quiz-exit') { st.quiz = null; return renderDetails(); }
    if (t.dataset.act === 'reset-progress') { t.dataset.act = 'reset-confirm'; t.textContent = 'Click again to reset all progress'; return; }
    if (t.dataset.act === 'reset-confirm') { progress = {}; saveProgress(); return route(); }
    if (t.dataset.act === 'start') { st.shown = 0; return play(); }
    if (t.dataset.act === 'overview') { stop(); st.quiz = null; st.step = -1; return refresh(); }
    if (t.matches('tr.row.has-raw')) toggleRaw(t);
  });
  $('#rows').addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('tr.has-raw')) { e.preventDefault(); toggleRaw(e.target); }
  });
  document.addEventListener('input', (e) => {
    if (e.target.id !== 'glossFilter') return;
    const q = e.target.value.trim().toLowerCase();
    let shown = 0;
    $$('.gloss-item').forEach((el) => { const hit = !q || el.dataset.text.includes(q); el.hidden = !hit; shown += hit; });
    $$('.gloss-letter').forEach((h) => { h.hidden = !!q; });
    $('.gloss-empty').hidden = shown > 0;
  });
  $('#drawerBtn').onclick = openDrawer;
  $('#closeDrawer').onclick = closeDrawer;
  $('#scrim').onclick = closeDrawer;
  $('#playBtn').onclick = togglePlay;
  $('#stepBtn').onclick = stepFwd;
  $('#prevBtn').onclick = stepBack;
  $('#resetBtn').onclick = reset;
  $('#speed').onchange = (e) => { st.speed = parseFloat(e.target.value) || 1; };
  $('#searchBtn').onclick = openPalette;
  $('#navToggle').onclick = () => {
    const open = $('#siteHeader').classList.toggle('nav-open');
    $('#navToggle').setAttribute('aria-expanded', String(open));
  };
  $('#themeBtn').onclick = () => {
    const root = document.documentElement;
    const cur = root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'light' ? 'dark' : 'light';
    root.dataset.theme = next;
    try { localStorage.setItem('se-theme', next); } catch (_) { /* storage unavailable */ }
  };
  $('#palette').addEventListener('click', (e) => { if (e.target.id === 'palette') closePalette(); });
  $('#palInput').addEventListener('input', renderPalette);
  $('#palInput').addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); movePalette(1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); movePalette(-1); }
    else if (e.key === 'Enter') { const m = palItems[palIdx]; if (m) { closePalette(); navigate(`/m/${m.id}`); } }
    else if (e.key === 'Escape') closePalette();
  });

  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); $('#palette').hidden ? openPalette() : closePalette(); return; }
    if (e.key === 'Escape') { closePalette(); closeDrawer(); closeNav(); return; }
    if (e.target.matches('input, select, textarea') || !$('#palette').hidden) return;
    if (e.key === '/') { e.preventDefault(); openPalette(); return; }
    if ($('#explorer').hidden) return;
    if (e.key === ' ') { if (e.target.closest('a, button, tr, select')) return; e.preventDefault(); togglePlay(); }
    else if (e.key === 'ArrowRight') stepFwd();
    else if (e.key === 'ArrowLeft') stepBack();
  });

  if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
  initChrome();
  updatePlay();
  // Cookieless page counts (GoatCounter). Steps share their module's path.
  let lastCounted = '';
  function track() {
    const path = '/' + location.pathname.split('/').filter(Boolean).join('/').replace(/^(m\/[^/]+)\/\d+$/, '$1');
    const canonical = document.querySelector('link[rel="canonical"]');
    if (canonical) canonical.href = location.origin + path + (path === '/' ? '' : '/');
    if (path === lastCounted) return;
    const send = () => {
      if (!window.goatcounter || !window.goatcounter.count) return;
      lastCounted = path;
      window.goatcounter.count({ path, title: document.title });
    };
    if (window.goatcounter && window.goatcounter.count) send();
    else window.addEventListener('load', send, { once: true });
  }

  // Client-side navigation with real paths (/m/sqli). Old #/ links are upgraded.
  function navigate(url) {
    if (url !== location.pathname) history.pushState(null, '', url);
    route(); track();
  }
  if (location.hash.startsWith('#/')) history.replaceState(null, '', '/' + location.hash.slice(2).replace(/^\/+/, ''));
  window.addEventListener('popstate', () => {
    if (location.pathname === lastPath && !location.hash.startsWith('#/')) return; // in-page #anchor jump
    route(); track();
  });
  route();
  track();
})();
