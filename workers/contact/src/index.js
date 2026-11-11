/*
 * Security Explorer contact form endpoint.
 * POST https://securityexplorer.org/api/contact  (JSON, same-origin only)
 * Delivers each message by email through Cloudflare Email Routing.
 * The destination address is a Worker secret (DESTINATION), never in the repo.
 */
import { EmailMessage } from 'cloudflare:email';

const SITE_ORIGIN = 'https://securityexplorer.org';
const FROM_ADDRESS = 'contact-form@securityexplorer.org';
const TOPICS = ['Question', 'Suggest a topic', 'Report a mistake', 'Other'];
const MAX_BODY = 12000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== '/api/contact') return reply(404, { ok: false, error: 'Not found' });
    if (request.method !== 'POST') return reply(405, { ok: false, error: 'Method not allowed' }, { Allow: 'POST' });
    if (request.headers.get('Origin') !== SITE_ORIGIN) return reply(403, { ok: false, error: 'Forbidden' });
    if (!(request.headers.get('Content-Type') || '').toLowerCase().startsWith('application/json')) {
      return reply(415, { ok: false, error: 'Unsupported content type' });
    }

    const raw = await request.text();
    if (raw.length > MAX_BODY) return reply(413, { ok: false, error: 'Message is too long.' });

    let data;
    try { data = JSON.parse(raw); } catch { return reply(400, { ok: false, error: 'Invalid request.' }); }
    if (!data || typeof data !== 'object') return reply(400, { ok: false, error: 'Invalid request.' });

    // Bot traps: a hidden field humans never fill, and a minimum time on the page.
    // Bots get a normal-looking success so they don't learn what tripped them.
    const elapsed = Date.now() - Number(data.t);
    if (data.website || !Number.isFinite(elapsed) || elapsed < 3000 || elapsed > 24 * 3600 * 1000) {
      return reply(200, { ok: true });
    }

    const name = oneLine(data.name, 100);
    const email = oneLine(data.email, 200);
    const page = oneLine(data.page, 200);
    const topic = TOPICS.includes(data.topic) ? data.topic : 'Other';
    const message = String(data.message ?? '').replace(/\r\n?/g, '\n').trim().slice(0, 5000);

    if (message.length < 10) return reply(400, { ok: false, error: 'Please write at least a few words.' });
    if (email && !/^[^\s@<>()",;]+@[^\s@<>()",;]+\.[A-Za-z]{2,}$/.test(email)) {
      return reply(400, { ok: false, error: "That email address doesn't look right." });
    }
    if (!env.DESTINATION) return reply(500, { ok: false, error: 'The contact form is not configured yet.' });

    const country = request.cf?.country || 'unknown';
    const text = [
      `Topic:   ${topic}`,
      `From:    ${name || '(no name given)'}`,
      `Reply to: ${email || '(no email given)'}`,
      page ? `Page:    ${page}` : null,
      `Country: ${country}`,
      '',
      message,
      '',
      '-- ',
      'Sent from the contact form on securityexplorer.org',
    ].filter((l) => l !== null).join('\n');

    const subject = `[Security Explorer] ${topic}${page ? ` · ${page}` : ''}`;
    const mime = buildMime({ from: FROM_ADDRESS, to: env.DESTINATION, replyTo: email, subject, text });

    try {
      await env.CONTACT.send(new EmailMessage(FROM_ADDRESS, env.DESTINATION, mime));
    } catch (err) {
      console.error('send failed', err && err.message);
      return reply(502, { ok: false, error: "Your message couldn't be sent right now. Please try again later." });
    }
    return reply(200, { ok: true });
  },
};

function reply(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}

// Single-line, length-limited text: strips control characters so nothing can inject email headers.
function oneLine(value, max) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, max);
}

function b64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

function buildMime({ from, to, replyTo, subject, text }) {
  const lines = [
    `From: Security Explorer <${from}>`,
    `To: <${to}>`,
    replyTo ? `Reply-To: <${replyTo}>` : null,
    `Subject: =?UTF-8?B?${b64(subject)}?=`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomUUID()}@securityexplorer.org>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64(text).replace(/.{1,76}/g, '$&\r\n').trimEnd(),
  ].filter((l) => l !== null);
  return lines.join('\r\n');
}
