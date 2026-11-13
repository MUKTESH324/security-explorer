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
    if (!a) { showPage(homeHTML(), '', 'home'); return startShowcase(); }
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
    if (a === 'contact') return showPage(contactHTML(), 'Contact', 'contact');
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

  const pageHero = (crumb, title, lead, extra = '', art = '') => `
      <header class="page-hero bleed"><div class="wrap page-hero-in">
        <div class="page-hero-text">
          <p class="crumbs-inline">${crumb}</p>
          <h1>${title}</h1>
          ${lead ? `<p class="lead">${lead}</p>` : ''}${extra}
        </div>
        ${art && art.scene ? `<div class="hero-scene" style="--tc:${toneOf(art.scene)}">${topicArt(art.scene)}</div>` : art ? `<div class="hero-art" aria-hidden="true"><span class="ring r1"></span><span class="ring r2"></span><span class="tile"><svg viewBox="0 0 48 48">${icon(art)}</svg></span></div>` : ''}
      </div></header>`;

  const siteStats = () => ({
    modules: MODS.length,
    topics: LIVE.length,
    steps: MODS.reduce((a, m) => a + m.steps.length, 0),
    questions: Object.values(SE.quizzes || {}).reduce((a, q) => a + q.length, 0),
    terms: (SE.glossary || []).length,
  });

  const FAQ = [
    ['Is Security Explorer really free?', 'Yes. Every module, quiz and learning path is free to use, with no account, no ads and no paywall.'],
    ['Who is it for?', 'Students, developers, IT and SOC analysts, and anyone moving into security. Modules are tagged Beginner, Intermediate or Advanced so you can pick your level.'],
    ['Do I need to install anything?', 'No. Everything runs in your browser, on desktop or phone. There is nothing to download and no lab to set up.'],
    ['Is it safe to learn about attacks here?', 'Modules explain how attacks work conceptually and always finish with the defense. Use what you learn only on systems you own or have written permission to test.'],
    ['How accurate is the content?', 'Modules follow public standards such as the OWASP Top 10, MITRE ATT&CK and the relevant RFCs, with references on every module. If you spot a mistake, the report link on each module sends it straight to us.'],
    ['Can I suggest a topic?', 'Yes, please do. Use the contact page or the link at the end of any module.'],
  ];

  function homeHTML() {
    const start = byId.sqli || MODS[0];
    const feat = byId.ssrf || start;
    const si = Math.min(2, feat.steps.length - 1);
    const s = siteStats();
    const firstPath = SE.paths.find((p) => pathMods(p).length) || SE.paths[0];
    return `
      <section class="hero-band bleed">
        <div class="wrap hero">
          <div class="hero-copy">
            <p class="pill">Free · ${s.modules} interactive modules · No sign-up</p>
            <h1>Security concepts, one packet at a time.</h1>
            <p class="lead">Step-by-step walkthroughs of real attacks, protocols and defenses. See who sends what to whom, understand why it works, and learn how to stop it.</p>
            <div class="hero-actions">
              <a class="btn primary lg" href="/modules">Browse modules</a>
              <a class="btn lg" href="/m/${start.id}">Try ${esc(start.name)}</a>
            </div>
          </div>
          <a class="preview" href="/m/${feat.id}/${si + 1}">
            <div class="preview-top"><span class="dots"><i></i><i></i><i></i></span><span>${esc(feat.name)}</span></div>
            ${previewSVG(feat, si)}
            <div class="preview-cap"><span>Step ${si + 1} of ${feat.steps.length}</span><b>${esc(feat.steps[si].title)}</b></div>
          </a>
        </div>
      </section>

      <section class="standards" aria-label="Frameworks the content follows">
        <span class="standards-label">Content aligned with</span>
        <ul>
          <li>OWASP Top 10</li><li>OWASP API Security</li><li>OWASP Top 10 for LLMs</li>
          <li>MITRE ATT&amp;CK</li><li>MITRE ATLAS</li><li>MITRE CWE</li><li>NIST</li><li>IETF RFCs</li>
        </ul>
      </section>

      <section class="stats-band">
        <div class="stat"><b>${s.modules}</b><span>Interactive modules</span></div>
        <div class="stat"><b>${s.topics}</b><span>Security topics</span></div>
        <div class="stat"><b>${s.questions}</b><span>Quiz questions</span></div>
        <div class="stat"><b>${s.terms}</b><span>Glossary terms</span></div>
      </section>

      <section class="band bleed"><div class="wrap">
      <section class="section features">
        <div class="section-intro">
          <p class="eyebrow">How you learn</p>
          <h2>See it happen, then understand why</h2>
          <p class="lead">Every module combines a live diagram, plain-language explanations and a quick check, so concepts actually stick.</p>
        </div>
        <div class="feature-grid">
          <article class="feature">
            <div class="mock mock-table" aria-hidden="true">
              <div class="mt-row k-req"><span class="no">1</span><span class="proto">HTTP</span><span>GET /products?id=7</span></div>
              <div class="mt-row k-atk"><span class="no">2</span><span class="proto">HTTP</span><span>GET /products?id=7'</span></div>
              <div class="mt-row k-data"><span class="no">3</span><span class="proto">MySQL</span><span>ERROR 1064: syntax error…</span></div>
              <div class="mt-row k-def"><span class="no">4</span><span class="proto">MySQL</span><span>PREPARE … WHERE id = ?</span></div>
            </div>
            <h3>Watch every packet</h3>
            <p>Follow each message across a network or sequence diagram, then open the packet table to see the real request or payload.</p>
          </article>
          <article class="feature">
            <div class="mock mock-step" aria-hidden="true">
              <span class="eyebrow">Step 2 of 4</span>
              <b>Probing with a quote</b>
              <i class="ln"></i><i class="ln short"></i>
              <div class="mock-box">Defender's note: never show database errors to users.</div>
            </div>
            <h3>Plain-language steps</h3>
            <p>Each step explains what is happening and why it matters, with the key fields and a defender's note where it counts.</p>
          </article>
          <article class="feature">
            <div class="mock mock-quiz" aria-hidden="true">
              <b>What actually fixes SQL injection?</b>
              <span class="opt">A WAF</span>
              <span class="opt right">Parameterized queries ✓</span>
              <span class="opt">Hiding error messages</span>
            </div>
            <h3>Check your understanding</h3>
            <p>A short quiz closes every module, with an explanation for each answer and your best score remembered.</p>
          </article>
          <article class="feature">
            <div class="mock mock-progress" aria-hidden="true">
              <span class="eyebrow">${esc(firstPath ? firstPath.title : 'Learning path')}</span>
              <div class="progress"><span style="width:56%"></span></div>
              <span class="mp-row done">✓ Ethernet &amp; Switching</span>
              <span class="mp-row done">✓ DHCP</span>
              <span class="mp-row">IP Routing &amp; Traceroute</span>
            </div>
            <h3>Learning paths and progress</h3>
            <p>Follow curated paths from networking basics to AI security. Your progress is saved privately in your own browser.</p>
          </article>
        </div>
      </section>

      </div></section>

      ${showcaseHTML()}

      <section class="section">
        <div class="section-head"><h2>Learning paths</h2><a href="/paths">See all paths</a></div>
        <div class="grid-3">${SE.paths.slice(0, 3).map(pathCard).join('')}</div>
      </section>

      <section class="band bleed"><div class="wrap">
      <section class="section">
        <div class="section-head"><h2>Browse by topic</h2><a href="/modules">All modules</a></div>
        <div class="topic-cards">${LIVE.map(topicRow).join('')}</div>
      </section>
      </div></section>

      <section class="section faq-section">
        <div class="section-intro"><p class="eyebrow">FAQ</p><h2>Common questions</h2></div>
        <div class="faq">${FAQ.map(([q, a]) => `<details><summary>${esc(q)}</summary><p>${esc(a)}</p></details>`).join('')}</div>
      </section>

      <section class="cta-band bleed">
        <div class="wrap cta-in">
          <div><h2>Start with the fundamentals</h2><p>Begin with how networks really work, then move on to attacks and defenses.</p></div>
          <div class="hero-actions">
            <a class="btn primary lg" href="/paths/${firstPath ? firstPath.id : ''}">Start a learning path</a>
            <a class="btn lg ghost" href="/modules">Browse modules</a>
          </div>
        </div>
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


  /* ---------- topic illustrations ---------- */
  // Each topic gets a small scene: a central icon linked to three related icons,
  // with packets travelling along the links. Colours come from --tc on the parent.
  const TOPIC_SCENES = {
    protocols: ['dns', 'client', 'router', 'server'],
    web: ['browser', 'attacker', 'db', 'shield'],
    api: ['api', 'phone', 'gateway', 'server'],
    appsec: ['repo', 'doc', 'cert', 'shield'],
    pentest: ['shell', 'browser', 'phone', 'doc'],
    network: ['router', 'switch', 'wifi', 'attacker'],
    identity: ['idp', 'user', 'phone', 'lock'],
    crypto: ['lock', 'client', 'cert', 'server'],
    cloud: ['cloud', 'bucket', 'container', 'lock'],
    threats: ['attacker', 'mail', 'c2', 'workstation'],
    defense: ['shield', 'firewall', 'ids', 'siem'],
    soc: ['siem', 'user', 'workstation', 'c2'],
    ai: ['ai', 'user', 'doc', 'gateway'],
  };
  const TOPIC_TONES = { protocols: '#3b82f6', web: '#e5484d', api: '#8b5cf6', appsec: '#10b981', pentest: '#f59e0b', network: '#06b6d4',
    identity: '#6366f1', crypto: '#14b8a6', cloud: '#0ea5e9', threats: '#ef4444', defense: '#22c55e', soc: '#2563eb', ai: '#d946ef' };
  const toneOf = (id) => TOPIC_TONES[id] || '#3b82f6';
  function topicArt(id) {
    const [c, a, b, d] = TOPIC_SCENES[id] || ['shield', 'client', 'server', 'lock'];
    const pts = [[62, 46, a], [62, 118, b], [262, 82, d]];
    const tile = (x, y, ic, big) => {
      const s = big ? 60 : 42, r = big ? 16 : 11, k = big ? 34 : 24;
      return `<g class="ta-node${big ? ' main' : ''}"><rect x="${x - s / 2}" y="${y - s / 2}" width="${s}" height="${s}" rx="${r}"/>
        <svg x="${x - k / 2}" y="${y - k / 2}" width="${k}" height="${k}" viewBox="0 0 48 48">${icon(ic)}</svg></g>`;
    };
    let h = '<svg class="topic-art" viewBox="0 0 320 164" aria-hidden="true">';
    h += '<circle class="ta-ring" cx="160" cy="82" r="58"/><circle class="ta-ring dash" cx="160" cy="82" r="78"/>';
    pts.forEach(([x, y], i) => {
      h += `<line class="ta-link" x1="${x}" y1="${y}" x2="160" y2="82"/>`;
      h += `<circle class="ta-pkt" r="3.5"><animateMotion dur="${2.6 + i * 0.7}s" begin="${i * 0.6}s" repeatCount="indefinite" path="M${x} ${y} L160 82"/></circle>`;
    });
    pts.forEach(([x, y, ic]) => { h += tile(x, y, ic, false); });
    h += tile(160, 82, c, true);
    return h + '</svg>';
  }

  /* ---------- featured walkthroughs (home) ---------- */
  const FEATURED = ['sqli', 'oauth-pkce', 'mcp-tool-poisoning', 'threat-hunting', 'tls13', 'burp-workflow'].filter((id) => byId[id]);
  let featTimer = 0, featIdx = 0;
  function showcasePanel(m) {
    const si = Math.min(Math.floor(m.steps.length / 2), m.steps.length - 1);
    const d = domainOf(m.domain);
    return `<a class="preview showcase-preview" href="/m/${m.id}/${si + 1}">
        <div class="preview-top"><span class="dots"><i></i><i></i><i></i></span><span>${esc(m.name)}</span></div>
        ${previewSVG(m, si)}
        <div class="preview-cap"><span>Step ${si + 1} of ${m.steps.length}</span><b>${esc(m.steps[si].title)}</b></div>
      </a>
      <div class="showcase-info">
        <div class="mcard-meta">${kindTag(m)}<span>${esc(d.name)}</span></div>
        <h3>${esc(m.name)}</h3>
        <p class="showcase-full">${esc(m.full)}</p>
        <p class="muted">${fmt(m.summary)}</p>
        <ol class="showcase-steps">${m.steps.map((x) => `<li>${esc(x.title)}</li>`).join('')}</ol>
        <div class="hero-actions"><a class="btn primary" href="/m/${m.id}">Start this module</a><span class="muted small">${esc(m.level)} · ${m.steps.length} steps · ${minutes(m)} min</span></div>
      </div>`;
  }
  function showcaseHTML() {
    if (!FEATURED.length) return '';
    return `<section class="section showcase">
        <div class="section-intro"><p class="eyebrow">Featured walkthroughs</p><h2>Pick a scenario and press play</h2>
          <p class="lead">A taste of what's inside, from classic web attacks to securing AI agents.</p></div>
        <div class="showcase-tabs" role="tablist" aria-label="Featured modules">${FEATURED.map((id, i) => `<button type="button" role="tab" class="chip${i === 0 ? ' on' : ''}" data-feature="${id}" aria-selected="${i === 0}">${esc(byId[id].name)}</button>`).join('')}</div>
        <div id="showcase" class="showcase-panel" role="tabpanel">${showcasePanel(byId[FEATURED[0]])}</div>
      </section>`;
  }
  function selectFeature(id) {
    const box = $('#showcase'); if (!box || !byId[id]) return;
    featIdx = FEATURED.indexOf(id);
    $$('.showcase-tabs [data-feature]').forEach((b) => { const on = b.dataset.feature === id; b.classList.toggle('on', on); b.setAttribute('aria-selected', on); });
    box.innerHTML = showcasePanel(byId[id]);
  }
  function startShowcase() {
    clearInterval(featTimer); featIdx = 0;
    if (!$('#showcase') || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    featTimer = setInterval(() => {
      const box = $('#showcase');
      if (!box) return clearInterval(featTimer);
      if (box.closest('.showcase').matches(':hover')) return;
      selectFeature(FEATURED[(featIdx + 1) % FEATURED.length]);
    }, 9000);
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
    return `<a class="topic-card" href="/modules/${d.id}" style="--tc:${toneOf(d.id)}">
      <span class="topic-card-art">${topicArt(d.id)}</span>
      <span class="topic-card-body"><b>${esc(d.name)}</b><small>${esc(d.blurb)}</small>
        <span class="topic-card-foot">${n} module${n === 1 ? '' : 's'} <span aria-hidden="true">→</span></span></span>
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
      ${pageHero(`<a href="/">Home</a> / ${d ? '<a href="/modules">Modules</a> / ' : ''}<span>${d ? esc(d.name) : 'Modules'}</span>`, d ? esc(d.name) : 'All modules', d ? esc(d.blurb) : `${MODS.length} interactive walkthroughs across ${LIVE.length} topics. Pick one, press play.`, '', d ? { scene: d.id } : 'shield')}
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
      ${pageHero('<a href="/">Home</a> / <span>Learning paths</span>', 'Learning paths', "Short, ordered sets of modules. Each one builds on the last, so it's worth going top to bottom.", '', 'cert')}
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
      ${pageHero('<a href="/">Home</a> / <span>Glossary</span>', 'Glossary', 'Plain-language definitions of the terms used across the site, with links to the modules that show them in action.', '', 'doc')}
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
    const k = (x) => `<kbd>${x}</kbd>`;
    const s = siteStats();
    const card = (ico, title, text) => `<article class="info-card"><span class="info-ico"><svg viewBox="0 0 48 48" aria-hidden="true">${icon(ico)}</svg></span><h3>${title}</h3><p>${text}</p></article>`;
    return `
      ${pageHero('<a href="/">Home</a> / <span>About</span>', 'About Security Explorer', 'A free, open learning site that shows how attacks, protocols and defenses really work, one message at a time.', '', 'shield')}

      <section class="section about-split">
        <div>
          <p class="eyebrow">Why it exists</p>
          <h2>Between reading about it and hacking a lab</h2>
          <p>Most security material either describes an attack in a paragraph or drops you straight into a lab. Security Explorer sits in between: each module plays out one scenario message by message, so you can see what each machine sends, read why it matters, and inspect the actual request or payload.</p>
          <p>Every attack module ends with the fix, because understanding the defense is the point.</p>
        </div>
        <aside class="glance">
          <h3>At a glance</h3>
          <dl>
            <div><dt>${s.modules}</dt><dd>interactive modules</dd></div>
            <div><dt>${s.steps}</dt><dd>animated steps</dd></div>
            <div><dt>${s.questions}</dt><dd>quiz questions</dd></div>
            <div><dt>${s.terms}</dt><dd>glossary terms</dd></div>
          </dl>
        </aside>
      </section>

      <section class="section">
        <div class="section-intro"><p class="eyebrow">Who it's for</p><h2>Built for anyone learning security</h2></div>
        <div class="card-grid-4">
          ${card('user', 'Students', 'Build an intuition for networking and security concepts before exams and labs.')}
          ${card('browser', 'Developers', 'See exactly how injection, XSS, CSRF and API flaws happen, and how to write the fix.')}
          ${card('siem', 'Analysts and SOC teams', 'Understand what attacks look like on the wire, and what to watch for in logs.')}
          ${card('cert', 'Career changers', 'Start from the fundamentals with guided learning paths and short quizzes.')}
        </div>
      </section>

      <section class="section">
        <div class="section-intro"><p class="eyebrow">How it works</p><h2>Four steps in every module</h2></div>
        <ol class="steps-row">
          <li><span>1</span><h3>Watch</h3><p>Press play and follow each packet on a network or sequence diagram.</p></li>
          <li><span>2</span><h3>Read</h3><p>Each step explains what happens and why, in plain language.</p></li>
          <li><span>3</span><h3>Inspect</h3><p>Open the packet table to see the real request, response or payload.</p></li>
          <li><span>4</span><h3>Fix and check</h3><p>Finish on the defense, then test yourself with a short quiz.</p></li>
        </ol>
      </section>

      <section class="section">
        <div class="section-intro"><p class="eyebrow">Our principles</p><h2>What you can expect</h2></div>
        <div class="card-grid-4">
          ${card('cert', 'Accurate', 'Content follows public standards and links to the CWE, OWASP, MITRE or RFC entry behind it.')}
          ${card('shield', 'Defense first', 'Attacks are explained to be understood and stopped. Every attack module ends on the fix.')}
          ${card('lock', 'Private by design', 'No accounts, ads or cookies. Visits are counted anonymously, without personal data.')}
          ${card('cloud', 'Free and open', 'Everything is free to use, on any device, with nothing to install.')}
        </div>
      </section>

      <section class="section about-split">
        <div>
          <p class="eyebrow">Sources</p>
          <h2>Built on trusted references</h2>
          <p>Modules reference public standards and knowledge bases, and the codes in each module link straight to the matching entry. Example IP addresses and domains come from ranges reserved for documentation, so they never point at real systems.</p>
        </div>
        <ul class="source-list">
          <li><a href="https://owasp.org/www-project-top-ten/" ${ext}>OWASP Top 10</a><small>Web application risks</small></li>
          <li><a href="https://owasp.org/API-Security/" ${ext}>OWASP API Security Top 10</a><small>API risks</small></li>
          <li><a href="https://genai.owasp.org/" ${ext}>OWASP Top 10 for LLM Applications</a><small>AI and LLM risks</small></li>
          <li><a href="https://attack.mitre.org/" ${ext}>MITRE ATT&amp;CK</a> · <a href="https://atlas.mitre.org/" ${ext}>ATLAS</a> · <a href="https://cwe.mitre.org/" ${ext}>CWE</a><small>Adversary techniques and weaknesses</small></li>
          <li><a href="https://www.rfc-editor.org/" ${ext}>IETF RFCs</a><small>Protocol specifications</small></li>
        </ul>
      </section>

      <section class="section about-split">
        <div>
          <p class="eyebrow">Using the site</p>
          <h2>Keyboard shortcuts</h2>
          <table class="kv about-keys">
            <tr><th>${k('Space')}</th><td>Play / pause</td></tr>
            <tr><th>${k('→')} ${k('←')}</th><td>Next / previous step</td></tr>
            <tr><th>${k('/')} or ${k(isMac() ? '⌘' : 'Ctrl')} ${k('K')}</th><td>Search modules</td></tr>
            <tr><th>${k('Esc')}</th><td>Close search or the module list</td></tr>
          </table>
          <p class="muted small">Every step has its own link, for example <code>securityexplorer.org/m/sqli/3</code>, so you can share exactly what you're looking at.</p>
        </div>
        <div>
          <p class="eyebrow">Diagram colours</p>
          <h2>Reading the packets</h2>
          <ul class="legend-list">${Object.entries(SE.kinds).map(([kk, v]) => `<li class="k-${kk}"><span class="swatch"></span>${esc(v.label)}</li>`).join('')}</ul>
        </div>
      </section>

      <section class="section">
        <div class="privacy-card">
          <span class="info-ico"><svg viewBox="0 0 48 48" aria-hidden="true">${icon('lock')}</svg></span>
          <div>
            <h2>Privacy</h2>
            <p>No accounts, ads or cookies. Visits are counted anonymously with <a href="https://www.goatcounter.com/" ${ext}>GoatCounter</a>, which doesn't use cookies or collect personal data. Your theme choice, completed modules and quiz scores are saved only in your own browser and never sent anywhere.</p>
            <p class="muted small">Use what you learn responsibly: only test systems you own or have written permission to test.</p>
          </div>
        </div>
      </section>

      <section class="cta-band bleed">
        <div class="wrap cta-in">
          <div><h2>Questions, ideas or corrections?</h2><p>Suggestions for new topics and corrections are always welcome.</p></div>
          <div class="hero-actions"><a class="btn primary lg" href="/contact">Get in touch</a></div>
        </div>
      </section>`;
  }

  const CONTACT_TOPICS = ['Question', 'Suggest a topic', 'Report a mistake', 'Other'];
  let contactStarted = 0;
  function contactHTML() {
    const q = new URLSearchParams(location.search);
    const topic = CONTACT_TOPICS.includes(q.get('topic')) ? q.get('topic') : 'Question';
    const page = (q.get('page') || '').slice(0, 200);
    contactStarted = Date.now();
    return `
      ${pageHero('<a href="/">Home</a> / <span>Contact</span>', 'Contact', 'Questions, ideas for new modules, or a mistake you spotted: send a note and it goes straight to the person who runs the site.', '', 'mail')}
      <div class="contact-layout">
      <article class="prose contact">
        <form id="contactForm" class="contact-form" novalidate>
          <fieldset class="topic-pick">
            <legend>What's it about?</legend>
            ${CONTACT_TOPICS.map((t) => `<label class="chip-radio"><input type="radio" name="topic" value="${esc(t)}"${t === topic ? ' checked' : ''}><span>${esc(t)}</span></label>`).join('')}
          </fieldset>
          ${page ? `<p class="about-page">About: <b>${esc(page)}</b><input type="hidden" name="page" value="${esc(page)}"></p>` : ''}
          <label class="field"><span>Message</span>
            <textarea name="message" rows="7" maxlength="5000" required placeholder="${topic === 'Report a mistake' ? 'Which step, and what looks wrong?' : 'Write your message'}"></textarea></label>
          <div class="field-row">
            <label class="field"><span>Name <small>(optional)</small></span><input name="name" maxlength="100" autocomplete="name"></label>
            <label class="field"><span>Email <small>(optional, only if you'd like a reply)</small></span><input name="email" type="email" maxlength="200" autocomplete="email"></label>
          </div>
          <label class="hp" aria-hidden="true">Website<input name="website" tabindex="-1" autocomplete="off"></label>
          <div class="form-foot">
            <button class="btn primary" type="submit">Send message</button>
            <p class="form-status" role="status" aria-live="polite"></p>
          </div>
          <p class="muted small">Messages are delivered by email and aren't published or shared. Your email address is only used to reply to you.</p>
        </form>
      </article>
      <aside class="contact-side">
        <div class="side-card"><h3>Suggest a topic</h3><p>Missing an attack, protocol or defense you'd like to see played out? Tell us which one.</p></div>
        <div class="side-card"><h3>Report a mistake</h3><p>Each module has a report link at the end, so we know exactly which step you mean.</p></div>
        <div class="side-card"><h3>Response time</h3><p>Messages are usually answered within a few days.</p></div>
      </aside>
      </div>`;
  }
  async function submitContact(form) {
    const status = form.querySelector('.form-status'), btn = form.querySelector('button[type="submit"]');
    const fd = new FormData(form);
    const data = Object.fromEntries(fd.entries());
    data.t = contactStarted;
    if ((data.message || '').trim().length < 10) { status.textContent = 'Please write at least a few words.'; status.className = 'form-status err'; form.message.focus(); return; }
    if (data.email && !form.email.checkValidity()) { status.textContent = "That email address doesn't look right."; status.className = 'form-status err'; form.email.focus(); return; }
    btn.disabled = true; status.textContent = 'Sending…'; status.className = 'form-status';
    try {
      const res = await fetch('/api/contact', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
      const out = await res.json().catch(() => ({}));
      if (res.ok && out.ok) {
        form.innerHTML = '<div class="box"><h2>Message sent</h2><p>Thanks for writing. If you left an email address, you\'ll get a reply there.</p></div>';
        return;
      }
      status.textContent = out.error || "Your message couldn't be sent. Please try again later."; status.className = 'form-status err';
    } catch (_) {
      status.textContent = "Your message couldn't be sent. Check your connection and try again."; status.className = 'form-status err';
    }
    btn.disabled = false;
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
        ${m.defenses?.length ? `<div class="box"><h2>${DEF_TITLE[m.kind] || 'Defenses'}</h2><ul>${m.defenses.map((x) => `<li>${fmt(x)}</li>`).join('')}</ul></div>` : ''}
        ${feedbackLink(m)}`;
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
        <div class="d-actions"><button class="btn" data-act="overview" type="button">Review the defenses</button>${next ? `<a class="btn${quiz ? '' : ' primary'}" href="/m/${next.id}">Next: ${esc(next.name)}</a>` : ''}</div>${feedbackLink(m)}` : ''}`;
  }
  const feedbackLink = (m) => `<p class="feedback-link"><a href="/contact?topic=${encodeURIComponent('Report a mistake')}&amp;page=${encodeURIComponent(m.name)}">Spotted a mistake or have an idea for this module?</a></p>`;

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
    if (t.dataset.feature) { clearInterval(featTimer); return selectFeature(t.dataset.feature); }
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
  document.addEventListener('submit', (e) => {
    if (e.target.id !== 'contactForm') return;
    e.preventDefault();
    submitContact(e.target);
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
