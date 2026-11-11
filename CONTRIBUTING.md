# Adding a module

1. Open the domain file in `js/modules/` (create `js/modules/<domain>.js` for a new domain, then add a `<script>` tag for it in `index.html` before `js/app.js`).
2. Call `SE.register({...})` using the schema below.
3. Reload the page and open the browser console. The registry warns about unknown node ids or packet kinds.

Domains are defined in `js/registry.js` (`web`, `api`, `network`, `identity`, `crypto`, `cloud`, `threats`, `defense`, `ai`). A topic stays hidden on the site until it has at least one module.

Add 3 quiz questions for each new module in `js/quizzes.js` (`[question, [options], correctIndex, explanation]`), and any new terms to `js/glossary.js`.

To add a module to a learning path, put its `id` in the `modules` list of that path in `js/registry.js`.

## Schema

```js
SE.register({
  id: 'tls13',                 // unique, used in the URL (/m/tls13)
  domain: 'crypto',            // one of the domain ids
  kind: 'protocol',            // 'attack' | 'protocol' | 'defense'
  level: 'Beginner',           // Beginner | Intermediate | Advanced
  severity: 'Protocol',        // free text badge
  name: 'TLS 1.3 Handshake',
  full: 'How HTTPS sets up an encrypted channel',
  tags: ['tls', 'https'],      // extra search words
  summary: 'One paragraph. Use `backticks` for code.',
  facts: [['Defined in', 'RFC 8446'], ['Port', '443']],   // CWE-…, T1234(.001), AML.T0051(.000), RFC N are auto-linked
  defenses: ['Bullet', 'Bullet'],                          // "How to defend" / "Security notes" / "Best practices"
  nodes: [
    // viewBox is 900 × 500. Keep x in 100–800 and y in 90–400 so labels fit.
    { id: 'c', type: 'client', label: 'Client', sub: '192.168.1.10', x: 130, y: 245 },
    { id: 's', type: 'server', label: 'Server', sub: 'example.com', x: 770, y: 245 },
    // add evil: true or good: true to tint a node red or green
  ],
  steps: [
    {
      title: 'ClientHello', sub: 'Short subtitle',
      text: 'What happens and why.',
      fields: [['Key', 'Value']],          // optional
      defend: 'Defender note',             // optional
      packets: [
        // [from, to, protocol, info, sizeBytes, kind, rawPayload?]
        ['c', 's', 'TLS', 'ClientHello (key_share X25519)', 517, 'ctl'],
        ['s', 's', 'Local', 'from === to shows a pulse on the node', 0, 'ctl'],
      ],
    },
  ],
});
```

**Packet kinds:** `req` request · `res` response · `ctl` handshake/control · `atk` malicious · `data` sensitive data · `def` defense/blocked

**Node types:** client, workstation, browser, phone, user, attacker, server, db, router, switch, firewall, cloud, dns, idp, dc, mail, shield, ids, siem, bucket, api, container, registry, wifi, c2, cert, lock, files, shell, repo, ai, doc, gateway (see `js/icons.js`).

## Content guidelines

- Explain concepts. Don't publish working exploit chains or weaponized payloads.
- End every attack module with the fix or defense step.
- Use documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `.example` domains.
