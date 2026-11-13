/* Domain: Secure Development (threat modelling, OWASP ASVS, OWASP MASVS) */

SE.register({
  id: 'threat-modeling', domain: 'appsec', kind: 'defense', level: 'Beginner', severity: 'Process',
  name: 'Threat Modelling (STRIDE)', full: 'Finding design flaws before writing code',
  tags: ['threat modeling', 'threat modelling', 'stride', 'data flow diagram', 'dfd', 'trust boundary', 'secure design', 'appsec', 'sdlc'],
  summary: 'Threat modelling is a structured way to ask "what could go wrong?" while a feature is still being designed, when fixes are cheapest. You draw how data flows, mark where trust changes, walk each flow through the STRIDE categories, and turn the answers into concrete requirements and tests.',
  facts: [['Four questions', 'What are we building? What can go wrong? What will we do? Did we do a good job?'], ['Model', 'Data flow diagram + trust boundaries'], ['Threat categories', 'STRIDE'], ['Other methods', 'PASTA, LINDDUN (privacy), attack trees'], ['Free tools', 'OWASP Threat Dragon, Microsoft TM Tool'], ['Relates to', 'OWASP A04 Insecure Design']],
  defenses: [
    'Model each new feature or big change during design, not after release',
    'Keep the diagram simple: processes, data stores, external entities, flows and trust boundaries',
    'Focus on flows that cross a trust boundary; that\'s where most threats live',
    'Turn every accepted threat into a requirement, a ticket and a test',
    'Revisit the model when the design changes, and check that the mitigations shipped',
  ],
  nodes: [
    { id: 'cust', type: 'phone', label: 'Customer App', sub: 'internet (untrusted)', x: 120, y: 245 },
    { id: 'gw', type: 'gateway', label: 'API Gateway', sub: 'trust boundary', x: 380, y: 245 },
    { id: 'ord', type: 'server', label: 'Orders Service', sub: 'internal', x: 620, y: 245 },
    { id: 'db', type: 'db', label: 'Orders DB', sub: 'data store', x: 620, y: 420 },
    { id: 'pay', type: 'cloud', label: 'Payment Provider', sub: 'third party', x: 800, y: 100 },
    { id: 'adm', type: 'user', label: 'Support Staff', sub: 'admin portal', x: 380, y: 420 },
  ],
  steps: [
    {
      title: 'What are we building?', sub: 'Draw the data flows',
      text: 'The team is designing checkout for a food-delivery app. In a short session they draw who talks to whom: the customer\'s phone calls the API gateway, which calls the orders service, which stores orders and talks to an external payment provider. They mark trust boundaries wherever data crosses from one level of trust to another.',
      fields: [['Elements', 'External entity, process, data store'], ['Trust boundaries', 'Internet → gateway, internal → payment provider']],
      packets: [
        ['cust', 'gw', 'Flow', 'Place order (items, address, payment token)', 900, 'ctl'],
        ['gw', 'ord', 'Flow', 'Create order (authenticated user id)', 700, 'ctl'],
        ['ord', 'db', 'Flow', 'Store order', 500, 'ctl'],
        ['ord', 'pay', 'Flow', 'Charge payment token', 400, 'ctl'],
        ['adm', 'ord', 'Flow', 'View orders, issue refunds', 300, 'ctl'],
      ],
    },
    {
      title: 'Spoofing and Tampering', sub: 'S and T of STRIDE',
      text: 'Walking the customer → gateway flow: could someone pretend to be another customer (Spoofing)? Could they change data in transit or in the request, such as the price (Tampering)? Both are realistic, because the phone is fully under the user\'s control.',
      fields: [['Spoofing', 'Calling the API as another user'], ['Tampering', 'Sending price = 0.01 in the order'], ['Mitigation', 'Strong auth tokens; price computed on the server']],
      packets: [
        ['cust', 'gw', 'Threat', 'S: request with another user\'s id', 600, 'atk'],
        ['cust', 'gw', 'Threat', 'T: {"item":"pizza","price":0.01}', 600, 'atk'],
        ['ord', 'ord', 'Mitigation', 'Ignore client prices; look up price server-side', 0, 'def'],
      ],
    },
    {
      title: 'Repudiation and Information disclosure', sub: 'R and I of STRIDE',
      text: 'Could a customer or staff member deny doing something, with no way to prove it (Repudiation)? Could data leak to someone who shouldn\'t see it (Information disclosure)? The team realises refunds aren\'t logged and that card numbers would sit in the orders database.',
      fields: [['Repudiation', '"I never issued that refund"'], ['Disclosure', 'Card data stored in Orders DB'], ['Mitigation', 'Audit log of refunds; store only payment tokens']],
      packets: [
        ['adm', 'ord', 'Threat', 'R: refund issued, no audit trail', 300, 'atk'],
        ['db', 'db', 'Threat', 'I: database backup contains card numbers', 0, 'atk'],
        ['ord', 'pay', 'Mitigation', 'Use provider tokens; never store card numbers', 400, 'def'],
      ],
    },
    {
      title: 'Denial of service and Elevation of privilege', sub: 'D and E of STRIDE',
      text: 'Could someone make the service unavailable (Denial of service), for example by flooding it with fake orders? Could a normal customer reach a function meant for staff (Elevation of privilege), like the refund endpoint?',
      fields: [['DoS', 'Thousands of unpaid orders per minute'], ['EoP', 'Customer calls POST /admin/refund'], ['Mitigation', 'Rate limits; role checks on every admin route']],
      packets: [
        ['cust', 'gw', 'Threat', 'D: 5,000 orders/min from scripts', 4500000, 'atk'],
        ['cust', 'gw', 'Threat', 'E: POST /admin/refund with customer token', 600, 'atk'],
        ['gw', 'cust', 'Mitigation', '429 rate limit · 403 role check', 300, 'def'],
      ],
    },
    {
      title: 'What will we do? Did we do a good job?', sub: 'From threats to tickets and tests',
      text: 'Each threat gets a decision: mitigate, accept, transfer or avoid. Mitigations become requirements in the backlog, many of them taken straight from OWASP ASVS, and each gets a test. Before release the team checks the mitigations actually shipped and updates the model.',
      fields: [['Threats found', '7'], ['Mitigated / accepted', '6 / 1 (documented)'], ['Requirements from', 'OWASP ASVS']],
      defend: 'A one-hour threat model at design time often prevents the bugs that later show up as critical pen-test findings.',
      packets: [
        ['ord', 'ord', 'Backlog', 'SEC-101 server-side pricing · SEC-102 refund audit log · SEC-103 rate limit', 0, 'def',
          `| # | Flow              | STRIDE | Threat                         | Decision | Ticket  |
|---|-------------------|--------|--------------------------------|----------|---------|
| 1 | App → Gateway     | S      | Act as another customer        | Mitigate | SEC-104 |
| 2 | App → Gateway     | T      | Client-supplied price          | Mitigate | SEC-101 |
| 3 | Staff → Orders    | R      | Refund with no audit trail     | Mitigate | SEC-102 |
| 4 | Orders → DB       | I      | Card numbers stored            | Avoid    | SEC-105 |
| 5 | App → Gateway     | D      | Order flooding                 | Mitigate | SEC-103 |
| 6 | App → Admin API   | E      | Customer reaches refund route  | Mitigate | SEC-106 |
| 7 | Orders → Payments | D      | Provider outage                | Accept   | (doc)   |`],
      ],
    },
  ],
});

SE.register({
  id: 'asvs', domain: 'appsec', kind: 'defense', level: 'Intermediate', severity: 'Standard',
  name: 'OWASP ASVS', full: 'Verifying a web app against the Application Security Verification Standard',
  tags: ['asvs', 'owasp asvs', 'application security verification standard', 'security requirements', 'verification', 'appsec', 'pentest', 'code review'],
  summary: 'The OWASP Application Security Verification Standard (ASVS) is a detailed list of security requirements for web apps and APIs. Teams use it to write requirements, to test against, and to agree what "secure enough" means. This module follows a reviewer checking one app\'s account features at Level 2.',
  facts: [['Publisher', 'OWASP'], ['Current version', 'ASVS 5.0 (2025)'], ['Levels', 'L1 baseline · L2 most apps · L3 high assurance'], ['Covers', 'Auth, sessions, access control, validation, crypto, logging…'], ['Used for', 'Requirements, testing, procurement'], ['Mobile counterpart', 'OWASP MASVS']],
  defenses: [
    'Pick a target level per app: L1 at minimum, L2 for apps handling sensitive data, L3 for the most critical',
    'Turn the relevant requirements into user stories and acceptance criteria',
    'Automate checks where possible (headers, cookies, dependency scans) in CI',
    'Verify the rest with code review and manual testing',
    'Track results per requirement so progress is visible release to release',
  ],
  nodes: [
    { id: 'rev', type: 'user', label: 'Security Reviewer', sub: 'ASVS L2 test', x: 120, y: 245, good: true },
    { id: 'app', type: 'browser', label: 'Web App', sub: 'app.example', x: 450, y: 245 },
    { id: 'api', type: 'server', label: 'Account API', sub: 'backend', x: 780, y: 245 },
    { id: 'rep', type: 'doc', label: 'Verification Report', sub: 'per requirement', x: 450, y: 420 },
  ],
  steps: [
    {
      title: 'Choose level and scope', sub: 'How much assurance do we need?',
      text: 'The app stores customers\' personal and payment details, so the team targets Level 2, which suits most business apps. They scope the review to the account features: sign-in, sessions, profile and password reset, and pick the matching ASVS chapters.',
      fields: [['Target', 'Level 2'], ['Chapters', 'Authentication, Session Management, Authorization, Validation'], ['Method', 'Testing + code review']],
      packets: [
        ['rev', 'rep', 'Plan', 'Scope: account features · ASVS 5.0 · Level 2', 600, 'ctl'],
      ],
    },
    {
      title: 'Authentication', sub: 'Passwords, brute force, MFA',
      text: 'The reviewer checks the authentication requirements: long passwords and passphrases are allowed, breached passwords are rejected, repeated failed logins are throttled, and multi-factor authentication is available. Everything passes except the breached-password check.',
      fields: [['Long passphrases', 'Pass'], ['Breached passwords blocked', 'Fail'], ['Brute-force throttling', 'Pass'], ['MFA available', 'Pass']],
      packets: [
        ['rev', 'api', 'HTTPS', 'POST /signup password="Password123!" (known breached)', 500, 'req'],
        ['api', 'rev', 'HTTPS', '201 Created (accepted, should be rejected)', 300, 'atk'],
        ['rev', 'api', 'HTTPS', 'POST /login × 20 wrong passwords', 9000, 'req'],
        ['api', 'rev', 'HTTPS', '429 Too Many Requests after 5 attempts', 200, 'def'],
      ],
    },
    {
      title: 'Session management', sub: 'Cookies and logout',
      text: 'Next, sessions: the session cookie must be `Secure`, `HttpOnly` and `SameSite`, the token must be random and long, a new one must be issued at login, and logout must kill the session on the server, not just in the browser.',
      fields: [['Cookie attributes', 'Pass'], ['New session at login', 'Pass'], ['Server-side logout', 'Pass']],
      packets: [
        ['api', 'app', 'HTTPS', 'Set-Cookie: sid=…; Secure; HttpOnly; SameSite=Lax', 400, 'def',
          `HTTP/1.1 200 OK
Set-Cookie: __Host-sid=Vq3k…(128-bit random); Path=/; Secure; HttpOnly; SameSite=Lax
Cache-Control: no-store`],
        ['rev', 'api', 'HTTPS', 'Reuse old sid after logout', 400, 'req'],
        ['api', 'rev', 'HTTPS', '401 session ended', 200, 'def'],
      ],
    },
    {
      title: 'Authorization and validation', sub: 'Access control on every request',
      text: 'The reviewer swaps their account ID for another user\'s on the profile endpoint, and sends unexpected input to every field. Access control holds and input is validated, but the password-reset link doesn\'t expire, which fails a requirement.',
      fields: [['Object-level access control', 'Pass'], ['Input validation', 'Pass'], ['Reset link expiry', 'Fail']],
      packets: [
        ['rev', 'api', 'HTTPS', 'GET /api/users/1002/profile (own id is 1001)', 500, 'req'],
        ['api', 'rev', 'HTTPS', '403 Forbidden', 200, 'def'],
        ['rev', 'api', 'HTTPS', 'Use 3-day-old password reset link', 500, 'req'],
        ['api', 'rev', 'HTTPS', '200 Reset page (link should have expired)', 4000, 'atk'],
      ],
    },
    {
      title: 'Report and track', sub: 'Pass/fail per requirement',
      text: 'The result is a report listing each in-scope requirement with pass, fail or not applicable, plus evidence. The two failures become tickets, and the team adds automated tests for them so they stay fixed. ASVS turns "is it secure?" into a checklist you can measure.',
      fields: [['Requirements checked', '64'], ['Pass / fail / N/A', '58 / 2 / 4'], ['Next', 'Fix, retest, add to CI']],
      defend: 'Use ASVS from the start: requirements written during design are far cheaper than findings after a pen test.',
      packets: [
        ['rev', 'rep', 'Report', 'ASVS L2 account features: 58 pass, 2 fail, 4 N/A', 12000, 'def',
          `ASVS 5.0 · Level 2 · Scope: account features
Chapter                 Pass  Fail  N/A
Authentication           17     1     1
Session Management       12     0     1
Authorization             9     0     0
Validation & Logic       20     1     2
--------------------------------------
Findings
  F-1  Breached passwords accepted at signup      → SEC-211
  F-2  Password reset link does not expire        → SEC-212`],
      ],
    },
  ],
});

SE.register({
  id: 'masvs', domain: 'appsec', kind: 'defense', level: 'Intermediate', severity: 'Standard',
  name: 'OWASP MASVS', full: 'Verifying a mobile app against the Mobile Application Security Verification Standard',
  tags: ['masvs', 'mastg', 'owasp mas', 'mobile security', 'android', 'ios', 'keystore', 'keychain', 'certificate pinning', 'appsec'],
  summary: 'The OWASP Mobile Application Security Verification Standard (MASVS) sets out what a secure Android or iOS app looks like, grouped into control areas like storage, network and authentication. Its companion, the MASTG testing guide, explains how to test each one. Here a reviewer checks a banking app.',
  facts: [['Publisher', 'OWASP MAS project'], ['Current version', 'MASVS v2'], ['Control groups', 'STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY'], ['Testing guide', 'OWASP MASTG'], ['Testing profiles', 'L1, L2, R (resilience)'], ['Web counterpart', 'OWASP ASVS']],
  defenses: [
    'Store tokens and keys in the Android Keystore or iOS Keychain, never in plain files or preferences',
    'Use TLS everywhere, validate certificates properly, and consider pinning for high-risk apps',
    'Do authentication and authorization on the server; the app is under the user\'s control',
    'Check exported components, deep links and WebViews for unintended access',
    'Add resilience controls (root/jailbreak and tamper detection) only on top of the basics',
  ],
  nodes: [
    { id: 'app', type: 'phone', label: 'Banking App', sub: 'Android / iOS', x: 120, y: 245 },
    { id: 'px', type: 'attacker', label: 'Test Proxy', sub: 'reviewer\'s intercept', x: 450, y: 400 },
    { id: 'api', type: 'server', label: 'Bank API', sub: 'api.bank.example', x: 780, y: 245 },
    { id: 'ks', type: 'lock', label: 'Keystore / Keychain', sub: 'hardware-backed', x: 450, y: 90, good: true },
    { id: 'rev', type: 'user', label: 'Mobile Reviewer', sub: 'MASTG tests', x: 780, y: 420, good: true },
  ],
  steps: [
    {
      title: 'MASVS-STORAGE', sub: 'Where does sensitive data live?',
      text: 'The reviewer inspects what the app writes to the device. The refresh token is stored in the platform Keystore/Keychain, which is protected by hardware, but a debug log file still contains full API responses with account numbers. That\'s a finding.',
      fields: [['Refresh token', 'Keystore/Keychain: Pass'], ['Logs', 'Account numbers in logs: Fail']],
      packets: [
        ['app', 'ks', 'Local', 'Store refresh token (hardware-backed key)', 300, 'def'],
        ['app', 'app', 'Local', 'debug.log contains account numbers', 0, 'atk'],
      ],
    },
    {
      title: 'MASVS-NETWORK', sub: 'Can traffic be intercepted?',
      text: 'The reviewer routes the phone through a test proxy with its own certificate authority. The app refuses to connect because it trusts only the system certificates and pins the bank\'s public key, so the session can\'t be read or changed in transit.',
      fields: [['TLS', 'Required, 1.2+'], ['User-installed CA', 'Not trusted: Pass'], ['Pinning', 'Public key pinned: Pass']],
      packets: [
        ['app', 'px', 'TLS', 'ClientHello api.bank.example', 517, 'ctl'],
        ['px', 'app', 'TLS', 'Certificate signed by the proxy\'s CA', 2400, 'atk'],
        ['app', 'px', 'TLS', 'Alert: bad certificate (pin mismatch) → connection closed', 30, 'def'],
        ['app', 'api', 'TLS', 'Direct connection, valid pinned certificate', 3100, 'ctl'],
      ],
    },
    {
      title: 'MASVS-AUTH', sub: 'Who decides you\'re logged in?',
      text: 'Fingerprint login unlocks a key in the Keystore that signs a challenge from the server, so the server makes the decision. The reviewer also checks that a transfer still needs a fresh server-verified step, rather than a simple "is unlocked" flag inside the app that could be flipped.',
      fields: [['Biometric', 'Unlocks key, server verifies signature: Pass'], ['Transfers', 'Step-up auth on server: Pass']],
      packets: [
        ['api', 'app', 'HTTPS', 'Challenge nonce for transfer approval', 300, 'ctl'],
        ['app', 'ks', 'Local', 'Fingerprint → sign nonce with private key', 200, 'ctl'],
        ['app', 'api', 'HTTPS', 'Signed challenge', 500, 'req'],
        ['api', 'app', 'HTTPS', 'Signature valid → transfer approved', 300, 'def'],
      ],
    },
    {
      title: 'MASVS-PLATFORM and CODE', sub: 'How the app talks to the OS',
      text: 'The reviewer checks deep links, exported components and WebViews. A deep link `bank://transfer?to=…` opens the transfer screen with fields pre-filled from the link, which another app or a web page could trigger. It still needs confirmation, but should be restricted. Third-party libraries are up to date.',
      fields: [['Deep link input', 'Pre-fills transfer: Fail (restrict)'], ['WebView', 'No JavaScript bridge to sensitive APIs: Pass'], ['Dependencies', 'No known vulnerable versions: Pass']],
      packets: [
        ['rev', 'app', 'Intent', 'Open bank://transfer?to=DE89…&amount=900', 300, 'atk'],
        ['app', 'app', 'Local', 'Transfer screen pre-filled (should validate the source)', 0, 'atk'],
      ],
    },
    {
      title: 'RESILIENCE, PRIVACY and the report', sub: 'Extra layers, then results',
      text: 'For a banking app the team also tests the resilience profile: the app detects a rooted device and a modified app and limits what can be done. Privacy controls check that only necessary data is collected. The report maps every result to a MASVS control and a MASTG test.',
      fields: [['Root/tamper detection', 'Pass (R profile)'], ['Privacy', 'Minimal data, consent shown: Pass'], ['Findings', '2 (logs, deep link)']],
      defend: 'Resilience controls slow attackers down but never replace the basics: secure storage, TLS and server-side checks.',
      packets: [
        ['app', 'api', 'HTTPS', 'Device integrity signal: rooted → limited mode', 600, 'def'],
        ['rev', 'rev', 'Report', 'MASVS v2: STORAGE fail (logs), PLATFORM fail (deep link), others pass', 0, 'def',
          `MASVS v2 review · Banking app 6.3 · Profiles L2 + R
MASVS-STORAGE     FAIL  sensitive data written to debug.log   → MOB-31
MASVS-CRYPTO      PASS
MASVS-AUTH        PASS
MASVS-NETWORK     PASS  TLS 1.2+, user CAs not trusted, pinning
MASVS-PLATFORM    FAIL  deep link pre-fills transfer          → MOB-32
MASVS-CODE        PASS
MASVS-RESILIENCE  PASS  root + tamper detection
MASVS-PRIVACY     PASS`],
      ],
    },
  ],
});
