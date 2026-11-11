/* Domain: Identity & Access (IAM) */

SE.register({
  id: 'oauth-pkce', domain: 'identity', kind: 'protocol', level: 'Intermediate', severity: 'Protocol',
  name: 'OAuth 2.0 + PKCE', full: 'Delegated login with the authorization code flow',
  tags: ['oauth', 'oidc', 'openid connect', 'pkce', 'authorization code', 'access token', 'sso', 'iam'],
  summary: 'OAuth 2.0 lets an app act on your behalf without ever seeing your password. The authorization code flow with PKCE is the recommended way to do it for web, mobile and single-page apps, and OpenID Connect adds a signed ID token on top for login.',
  facts: [['Defined in', 'RFC 6749'], ['PKCE', 'RFC 7636'], ['Current best practice', 'RFC 9700'], ['Login layer', 'OpenID Connect (ID token)'], ['Deprecated', 'Implicit and password grants'], ['Common flaw', 'CWE-601 (open redirect)']],
  defenses: [
    'Use the authorization code flow with PKCE (S256) for every client type',
    'Register exact redirect URIs; never allow wildcards or open redirects',
    'Send and check a random `state` value to stop login CSRF',
    'Keep access tokens short-lived and scoped to the least privilege needed',
    'Validate tokens on the API: signature, issuer, audience, expiry and scope',
    'Store refresh tokens server-side or rotate them on every use',
  ],
  nodes: [
    { id: 'b', type: 'browser', label: 'Browser', sub: 'alice', x: 120, y: 245 },
    { id: 'app', type: 'server', label: 'Photo Print App', sub: 'OAuth client', x: 450, y: 100 },
    { id: 'as', type: 'idp', label: 'Authorization Server', sub: 'login.example', x: 780, y: 100, good: true },
    { id: 'api', type: 'api', label: 'Photos API', sub: 'resource server', x: 780, y: 390 },
    { id: 'atk', type: 'attacker', label: 'Malicious App', sub: 'on the same phone', x: 450, y: 400 },
  ],
  steps: [
    {
      title: 'Start the flow', sub: 'Redirect to the authorization server',
      text: 'Alice wants the print app to read her photos. The app creates a random secret called the `code_verifier`, keeps it, and sends only its SHA-256 hash (the `code_challenge`) along with a random `state` value when it redirects her browser to the authorization server.',
      fields: [['response_type', 'code'], ['code_challenge_method', 'S256'], ['scope', 'photos.read']],
      packets: [
        ['b', 'app', 'HTTPS', 'GET /connect-photos', 480, 'req'],
        ['app', 'app', 'Local', 'code_verifier = random(43–128 chars), state = random', 0, 'ctl'],
        ['app', 'b', 'HTTPS', '302 → login.example/authorize?…&code_challenge=…', 720, 'res',
          `HTTP/1.1 302 Found
Location: https://login.example/authorize
  ?response_type=code
  &client_id=print-app
  &redirect_uri=https://print.example/callback
  &scope=photos.read
  &state=xT9q2…
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256`],
      ],
    },
    {
      title: 'Sign in and consent', sub: 'Only the authorization server sees the password',
      text: 'Alice signs in on the authorization server\'s own page, with MFA, and approves the request: "Photo Print App wants to read your photos". The print app never sees her password.',
      fields: [['Authentication', 'Password + MFA'], ['Consent', 'photos.read only']],
      packets: [
        ['b', 'as', 'HTTPS', 'GET /authorize?… (sign-in page)', 900, 'req'],
        ['b', 'as', 'HTTPS', 'POST /login (credentials + MFA)', 1200, 'data'],
        ['b', 'as', 'HTTPS', 'POST /consent (allow photos.read)', 600, 'ctl'],
      ],
    },
    {
      title: 'Authorization code', sub: 'Short-lived and single-use',
      text: 'The authorization server redirects back to the registered redirect URI with a one-time code and the same `state`. The app checks that `state` matches what it sent, which stops an attacker from slipping their own login into Alice\'s session.',
      fields: [['code', 'Valid ~60 s, one use'], ['state', 'Must match']],
      packets: [
        ['as', 'b', 'HTTPS', '302 → print.example/callback?code=SplxlOB…&state=xT9q2…', 520, 'res'],
        ['b', 'app', 'HTTPS', 'GET /callback?code=SplxlOB…&state=xT9q2…', 540, 'req'],
      ],
    },
    {
      title: 'Exchange code for tokens', sub: 'PKCE proves it\'s the same app',
      text: 'The app sends the code and the original `code_verifier` to the token endpoint over a back channel. The authorization server hashes the verifier and checks it matches the challenge from step 1, then issues a short-lived access token (and an ID token if OpenID Connect is used).',
      fields: [['Check', 'SHA256(code_verifier) == code_challenge'], ['access_token', 'expires_in 600 s, scope photos.read']],
      packets: [
        ['app', 'as', 'HTTPS', 'POST /token grant_type=authorization_code, code, code_verifier', 640, 'req'],
        ['as', 'as', 'Local', 'PKCE check passed', 0, 'def'],
        ['as', 'app', 'HTTPS', '200 {access_token, refresh_token, id_token, expires_in: 600}', 2100, 'data'],
      ],
    },
    {
      title: 'A stolen code is useless', sub: 'Why PKCE exists',
      text: 'On a phone, a malicious app could register the same custom URL scheme and capture the redirect with the code. Without the `code_verifier`, which never left the real app, its token request fails.',
      fields: [['Attacker has', 'code'], ['Attacker lacks', 'code_verifier'], ['Result', 'invalid_grant']],
      packets: [
        ['atk', 'as', 'HTTPS', 'POST /token code=SplxlOB… (no valid code_verifier)', 600, 'atk'],
        ['as', 'atk', 'HTTPS', '400 {"error":"invalid_grant"}', 220, 'def'],
      ],
    },
    {
      title: 'Call the API', sub: 'Bearer token, checked every time',
      text: 'The app calls the Photos API with the access token. The API checks the token\'s signature, issuer, audience, expiry and scope before returning anything. A token for `photos.read` can\'t delete photos.',
      fields: [['Header', 'Authorization: Bearer eyJ…'], ['Checks', 'sig, iss, aud, exp, scope']],
      defend: 'Treat access tokens like passwords: never put them in URLs or logs, and keep their lifetime and scope small.',
      packets: [
        ['app', 'api', 'HTTPS', 'GET /v1/photos (Authorization: Bearer …)', 1500, 'req'],
        ['api', 'api', 'Local', 'Token valid: aud=photos-api, scope=photos.read', 0, 'def'],
        ['api', 'app', 'HTTPS', '200 OK [24 photos]', 48000, 'res'],
      ],
    },
  ],
});

SE.register({
  id: 'saml-sso', domain: 'identity', kind: 'protocol', level: 'Intermediate', severity: 'Protocol',
  name: 'SAML Single Sign-On', full: 'Enterprise SSO with signed XML assertions',
  tags: ['saml', 'sso', 'single sign-on', 'idp', 'service provider', 'assertion', 'federation', 'iam'],
  summary: 'SAML 2.0 lets employees sign in once at the company identity provider and reach many business apps. The identity provider sends the app a digitally signed XML assertion saying who the user is, and the app must validate it carefully.',
  facts: [['Standard', 'OASIS SAML 2.0'], ['Format', 'Signed XML assertions'], ['Bindings', 'HTTP-Redirect, HTTP-POST'], ['Roles', 'IdP, Service Provider (SP)'], ['Common flaw', 'CWE-347 (bad signature checks)'], ['Newer alternative', 'OpenID Connect']],
  defenses: [
    'Use a well-maintained SAML library; don\'t parse or verify XML signatures by hand',
    'Require signed assertions and pin the IdP signing certificate',
    'Check Audience, Recipient, Destination, InResponseTo and time limits',
    'Reject replayed assertions by remembering assertion IDs until they expire',
    'Enforce MFA at the IdP so every federated app benefits',
  ],
  nodes: [
    { id: 'b', type: 'browser', label: 'Browser', sub: 'alice@corp.example', x: 120, y: 245 },
    { id: 'sp', type: 'server', label: 'Expenses App', sub: 'service provider', x: 780, y: 120 },
    { id: 'idp', type: 'idp', label: 'Corporate IdP', sub: 'sso.corp.example', x: 780, y: 380, good: true },
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: '203.0.113.66', x: 450, y: 420 },
  ],
  steps: [
    {
      title: 'Visit the app', sub: 'SP-initiated login',
      text: 'Alice opens the expenses app. She has no session, so the app builds a SAML `AuthnRequest` and redirects her browser to the company identity provider.',
      fields: [['Binding', 'HTTP-Redirect'], ['Request ID', '_a91f…']],
      packets: [
        ['b', 'sp', 'HTTPS', 'GET /reports', 460, 'req'],
        ['sp', 'b', 'HTTPS', '302 → sso.corp.example/saml?SAMLRequest=…&RelayState=…', 900, 'res'],
      ],
    },
    {
      title: 'Authenticate once', sub: 'At the identity provider',
      text: 'The IdP checks Alice\'s password and MFA, or reuses her existing SSO session if she signed in earlier today. That one sign-in now covers every connected app.',
      fields: [['Method', 'Password + MFA'], ['SSO session', '8 h']],
      packets: [
        ['b', 'idp', 'HTTPS', 'GET /saml?SAMLRequest=…', 1100, 'req'],
        ['b', 'idp', 'HTTPS', 'POST /login (credentials + MFA)', 1300, 'data'],
      ],
    },
    {
      title: 'Signed assertion', sub: 'Delivered by the browser',
      text: 'The IdP creates an assertion stating who Alice is, for which app and for how long, signs it with its private key, and returns a small form that the browser auto-submits to the app\'s Assertion Consumer Service (ACS) URL.',
      fields: [['Binding', 'HTTP-POST to ACS'], ['Signed', 'RSA-SHA256']],
      packets: [
        ['idp', 'b', 'HTTPS', '200 auto-submit form (SAMLResponse)', 9800, 'res'],
        ['b', 'sp', 'HTTPS', 'POST /saml/acs SAMLResponse=PHNhbWxwOl…', 9800, 'data',
          `<saml:Assertion ID="_7c2e…" IssueInstant="2026-11-10T09:00:02Z">
  <saml:Issuer>https://sso.corp.example</saml:Issuer>
  <ds:Signature>…RSA-SHA256 over the assertion…</ds:Signature>
  <saml:Subject>
    <saml:NameID>alice@corp.example</saml:NameID>
    <saml:SubjectConfirmationData InResponseTo="_a91f…"
        Recipient="https://expenses.example/saml/acs"
        NotOnOrAfter="2026-11-10T09:05:02Z"/>
  </saml:Subject>
  <saml:Conditions>
    <saml:AudienceRestriction>
      <saml:Audience>https://expenses.example</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
</saml:Assertion>`],
      ],
    },
    {
      title: 'Validate everything', sub: 'Where SAML bugs live',
      text: 'Before trusting the assertion, the app verifies the signature with the IdP\'s pinned certificate, then checks that it was meant for this app (Audience), this endpoint (Recipient), this login (InResponseTo), and that it hasn\'t expired or been used before.',
      fields: [['Signature', 'Valid, pinned IdP cert'], ['Audience / Recipient', '✓ / ✓'], ['Time / replay', '✓ / first use']],
      packets: [
        ['sp', 'sp', 'Local', 'Signature + conditions verified', 0, 'def'],
        ['sp', 'b', 'HTTPS', '302 → /reports (Set-Cookie: session)', 600, 'res'],
      ],
    },
    {
      title: 'Tampered assertion', sub: 'Rejected by the signature check',
      text: 'An attacker captures an assertion and edits the NameID to an administrator\'s email. Any change to signed content breaks the signature, so a correctly implemented app rejects it. Real-world SAML breaches come from apps that skip or mis-implement this check.',
      fields: [['Change', 'NameID alice → admin'], ['Result', 'Signature invalid → reject']],
      defend: 'Test your SAML integration with tampered, unsigned, expired and replayed assertions before going live.',
      packets: [
        ['atk', 'sp', 'HTTPS', 'POST /saml/acs (assertion with edited NameID)', 9800, 'atk'],
        ['sp', 'atk', 'HTTPS', '403: invalid signature', 240, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'kerberos', domain: 'identity', kind: 'protocol', level: 'Intermediate', severity: 'Protocol',
  name: 'Kerberos Authentication', full: 'How Active Directory logons use tickets',
  tags: ['kerberos', 'active directory', 'ad', 'kdc', 'tgt', 'ticket', 'domain controller', 'windows', 'iam'],
  summary: 'Kerberos is the ticket-based protocol behind Windows domain logons. Users prove who they are once to the domain controller and get a ticket-granting ticket, which they then trade for service tickets, so passwords never cross the network.',
  facts: [['Defined in', 'RFC 4120'], ['Port', '88 TCP/UDP'], ['Used by', 'Active Directory, many Unix realms'], ['Tickets', 'TGT + service tickets'], ['Clock skew limit', '5 min (default)'], ['Abuse technique', 'T1558']],
  defenses: [
    'Allow only AES encryption types; disable RC4 where possible',
    'Use group managed service accounts (gMSA) or long random service passwords',
    'Put admin accounts in Protected Users and keep them off ordinary workstations',
    'Rotate the krbtgt account password on a regular schedule',
    'Log and alert on unusual ticket requests (events 4768, 4769) in the SIEM',
  ],
  nodes: [
    { id: 'ws', type: 'workstation', label: 'Workstation', sub: 'alice', x: 120, y: 245 },
    { id: 'kdc', type: 'dc', label: 'Domain Controller', sub: 'KDC (AS + TGS)', x: 450, y: 100, good: true },
    { id: 'fs', type: 'files', label: 'File Server', sub: 'cifs/files.corp.example', x: 780, y: 245 },
    { id: 'siem', type: 'siem', label: 'SIEM', sub: 'security logs', x: 450, y: 400 },
  ],
  steps: [
    {
      title: 'AS exchange', sub: 'Getting a ticket-granting ticket',
      text: 'When Alice logs on, her workstation sends an `AS-REQ` with a timestamp encrypted using a key derived from her password (pre-authentication). The KDC decrypts it, so it knows she has the password, and returns a ticket-granting ticket (TGT) plus a session key.',
      fields: [['Pre-auth', 'Encrypted timestamp'], ['TGT encrypted with', 'krbtgt account key'], ['Lifetime', '10 h (default)']],
      packets: [
        ['ws', 'kdc', 'Kerberos', 'AS-REQ alice (PA-ENC-TIMESTAMP)', 280, 'ctl'],
        ['kdc', 'ws', 'Kerberos', 'AS-REP TGT + session key (encrypted for alice)', 1450, 'data'],
        ['kdc', 'siem', 'WEF', 'Event 4768: TGT issued for alice', 900, 'def'],
      ],
    },
    {
      title: 'TGS exchange', sub: 'Asking for a service ticket',
      text: 'To open a file share, the workstation presents the TGT and asks for a ticket for the service name `cifs/files.corp.example`. The KDC issues a service ticket encrypted with the file server\'s own key.',
      fields: [['SPN', 'cifs/files.corp.example'], ['Ticket encrypted with', 'Service account key (AES)']],
      packets: [
        ['ws', 'kdc', 'Kerberos', 'TGS-REQ (TGT + authenticator) for cifs/files', 1600, 'ctl'],
        ['kdc', 'ws', 'Kerberos', 'TGS-REP service ticket + service session key', 1500, 'data'],
        ['kdc', 'siem', 'WEF', 'Event 4769: service ticket cifs/files (AES256)', 900, 'def'],
      ],
    },
    {
      title: 'AP exchange', sub: 'Presenting the ticket',
      text: 'The workstation sends the service ticket to the file server. The server decrypts it with its own key, reads who Alice is and her group memberships, and lets her in. It doesn\'t need to contact the domain controller at all.',
      fields: [['Mutual auth', 'Optional AP-REP'], ['Contains', 'User, groups (PAC), expiry']],
      packets: [
        ['ws', 'fs', 'SMB', 'AP-REQ (service ticket + authenticator)', 1700, 'ctl'],
        ['fs', 'ws', 'SMB', 'AP-REP (mutual authentication) + session established', 300, 'res'],
        ['ws', 'fs', 'SMB', 'Open \\\\files\\finance\\Q4.xlsx', 420, 'req'],
      ],
    },
    {
      title: 'Why the keys matter', sub: 'Ticket abuse and how to spot it',
      text: 'Kerberos is only as strong as the keys behind it. Attackers who get a foothold try to request service tickets for accounts with weak passwords and crack them offline, or forge tickets if they steal the krbtgt key. Strong service passwords, AES-only tickets and monitoring for unusual requests shut most of this down.',
      fields: [['Watch for', 'Many 4769s with RC4 from one host'], ['Technique', 'T1558']],
      defend: 'An unusual burst of service-ticket requests from one workstation is a strong signal. Alert on it and investigate the host.',
      packets: [
        ['ws', 'kdc', 'Kerberos', 'TGS-REQ × 120 SPNs, RC4 requested (unusual)', 190000, 'atk'],
        ['kdc', 'ws', 'Kerberos', 'KDC_ERR_ETYPE_NOSUPP (RC4 disabled)', 180, 'def'],
        ['kdc', 'siem', 'WEF', 'Events 4769 × 120 from one host → alert', 108000, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'mfa-fatigue', domain: 'identity', kind: 'attack', level: 'Beginner', severity: 'High',
  name: 'MFA Fatigue', full: 'Push-notification bombing and how to stop it',
  tags: ['mfa', 'push bombing', 'mfa fatigue', 'number matching', 'passkeys', 'fido2', 'social engineering', 'iam'],
  summary: 'When attackers already have a password, simple "Approve / Deny" push MFA can be worn down: they send prompt after prompt, often with a call pretending to be IT, until the user taps Approve. Number matching and phishing-resistant MFA stop it.',
  facts: [['Technique', 'T1621'], ['Prerequisite', 'A valid password'], ['Weak factor', 'Simple approve/deny push'], ['Better', 'Number matching + context'], ['Best', 'FIDO2 / passkeys'], ['Reference', 'CISA phishing-resistant MFA guidance']],
  defenses: [
    'Turn on number matching and show app name and location in push prompts',
    'Limit how many push prompts a user can receive in a short window',
    'Alert the SOC on repeated MFA denials for the same user',
    'Move admins and high-risk users to passkeys or security keys',
    'Teach staff: an unexpected MFA prompt means your password is known; report it',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: 'has the password', x: 120, y: 120 },
    { id: 'idp', type: 'idp', label: 'Identity Provider', sub: 'sso.corp.example', x: 450, y: 245 },
    { id: 'ph', type: 'phone', label: 'Employee Phone', sub: 'authenticator app', x: 780, y: 120 },
    { id: 'siem', type: 'siem', label: 'SIEM', sub: 'sign-in logs', x: 780, y: 390 },
  ],
  steps: [
    {
      title: 'Password already known', sub: 'Only MFA stands in the way',
      text: 'The attacker has the employee\'s password, perhaps from a reused password in an old breach. Signing in triggers a push notification to the employee\'s phone.',
      fields: [['Factor 1', 'Password ✓'], ['Factor 2', 'Push approval pending']],
      packets: [
        ['atk', 'idp', 'HTTPS', 'POST /login j.smith + correct password', 900, 'atk'],
        ['idp', 'ph', 'Push', '"Approve sign-in?" [Approve] [Deny]', 400, 'ctl'],
        ['ph', 'idp', 'Push', 'Denied', 200, 'def'],
      ],
    },
    {
      title: 'Prompt bombing', sub: 'Again and again',
      text: 'The attacker repeats the login dozens of times, late at night. The phone keeps buzzing. Each denial is logged, but if nobody is watching, the prompts just continue.',
      fields: [['Prompts', '40 in 20 minutes'], ['Time', '01:30 local']],
      packets: [
        ['atk', 'idp', 'HTTPS', 'POST /login × 40', 36000, 'atk'],
        ['idp', 'ph', 'Push', '"Approve sign-in?" × 40', 16000, 'atk'],
        ['idp', 'siem', 'Log', 'mfa.denied user=j.smith × 39', 9000, 'def'],
      ],
    },
    {
      title: 'Social engineering', sub: '"Hi, this is IT support…"',
      text: 'The attacker messages the employee pretending to be the help desk: "We\'re fixing an issue with your account, please approve the next prompt to stop the alerts." Tired and wanting the buzzing to end, the employee taps Approve.',
      fields: [['Pretext', 'Fake help desk'], ['Result', 'Session issued to attacker']],
      packets: [
        ['ph', 'idp', 'Push', 'Approved', 200, 'atk'],
        ['idp', 'atk', 'HTTPS', '302 → apps (session cookie)', 1400, 'data'],
      ],
    },
    {
      title: 'Number matching', sub: 'Approval needs what\'s on the screen',
      text: 'With number matching, the sign-in page shows a two-digit number and the phone asks the user to type it. Someone who didn\'t start the login can\'t see the number, so they can\'t approve it by accident. The prompt also shows the app and location.',
      fields: [['Prompt', 'Enter the number shown: __'], ['Context', 'App: VPN · Location: unknown country']],
      packets: [
        ['atk', 'idp', 'HTTPS', 'POST /login j.smith + password', 900, 'atk'],
        ['idp', 'ph', 'Push', 'Enter the number shown on your sign-in screen', 420, 'def'],
        ['ph', 'idp', 'Push', 'Denied: "I didn\'t try to sign in" (reported)', 220, 'def'],
        ['idp', 'siem', 'Log', 'mfa.fraud_reported user=j.smith → alert', 600, 'def'],
      ],
    },
    {
      title: 'Phishing-resistant MFA', sub: 'Nothing to approve',
      text: 'With a passkey or FIDO2 security key, the login is bound to the real website and needs the user\'s own device in hand. There\'s no prompt an attacker can trigger remotely, so push bombing simply stops working. The SOC resets the leaked password.',
      fields: [['Factor', 'Passkey (FIDO2/WebAuthn)'], ['Follow-up', 'Reset password, check reuse']],
      defend: 'A burst of MFA denials means the password is compromised. Reset it, even if no prompt was approved.',
      packets: [
        ['atk', 'idp', 'HTTPS', 'POST /login j.smith + password', 900, 'atk'],
        ['idp', 'atk', 'HTTPS', 'Passkey required on a registered device → fail', 300, 'def'],
        ['siem', 'idp', 'Action', 'Force password reset for j.smith, revoke sessions', 260, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'pam-jit', domain: 'identity', kind: 'defense', level: 'Intermediate', severity: 'Control',
  name: 'Privileged Access (JIT)', full: 'Just-in-time admin rights with a PAM broker',
  tags: ['pam', 'privileged access', 'just in time', 'jit', 'least privilege', 'vault', 'session recording', 'iam'],
  summary: 'Standing admin accounts are what attackers hunt for. Privileged access management (PAM) removes them: admins request elevated access for a specific task and time, get it after approval through a broker that holds the credentials, and lose it automatically when time is up.',
  facts: [['Principle', 'Least privilege, zero standing access'], ['Components', 'Broker, vault, approval, recording'], ['Credentials', 'Checked out, then rotated'], ['Reference', 'NIST SP 800-53 AC-6'], ['Counters', 'T1078 (valid accounts)'], ['Pairs with', 'MFA, SIEM']],
  defenses: [
    'Remove permanent admin group memberships; grant time-boxed access instead',
    'Require a reason, ticket number and MFA for every elevation',
    'Keep privileged passwords in a vault and rotate them after each use',
    'Record privileged sessions and send events to the SIEM',
    'Alert on any admin login that bypasses the PAM broker',
  ],
  nodes: [
    { id: 'adm', type: 'workstation', label: 'Admin Workstation', sub: 'bob (DBA)', x: 120, y: 245 },
    { id: 'pam', type: 'shield', label: 'PAM Broker', sub: 'JIT + recording', x: 450, y: 245, good: true },
    { id: 'apr', type: 'user', label: 'Approver', sub: 'team lead', x: 450, y: 90, good: true },
    { id: 'vault', type: 'lock', label: 'Credential Vault', sub: 'rotating secrets', x: 450, y: 405 },
    { id: 'db', type: 'db', label: 'Production DB', sub: 'db01.corp.example', x: 780, y: 160 },
    { id: 'siem', type: 'siem', label: 'SIEM', sub: 'audit', x: 780, y: 380 },
  ],
  steps: [
    {
      title: 'No standing access', sub: 'Request with a reason',
      text: 'Bob is a database administrator, but his everyday account has no admin rights. To fix a production issue he requests the `db-admin` role for two hours, quoting the incident ticket, and confirms with MFA.',
      fields: [['Role', 'db-admin on db01'], ['Duration', '2 h'], ['Reason', 'INC-4821']],
      packets: [
        ['adm', 'pam', 'HTTPS', 'Request db-admin on db01, 2 h, ticket INC-4821 (MFA)', 900, 'req'],
      ],
    },
    {
      title: 'Approval', sub: 'A second person agrees',
      text: 'Policy says production admin access needs one approval. The team lead checks the ticket and approves. Low-risk roles could be auto-approved by policy instead.',
      fields: [['Policy', 'Prod → 1 approver'], ['Decision', 'Approved, 2 h']],
      packets: [
        ['pam', 'apr', 'HTTPS', 'Approval needed: bob → db-admin (INC-4821)', 700, 'ctl'],
        ['apr', 'pam', 'HTTPS', 'Approved', 300, 'def'],
      ],
    },
    {
      title: 'Brokered session', sub: 'The password never reaches Bob',
      text: 'The broker checks out the privileged credential from the vault and opens the session to the database on Bob\'s behalf. Bob works through the broker; he never sees or copies the password, and every command is recorded.',
      fields: [['Credential', 'Injected by broker'], ['Recording', 'On (keystrokes + queries)']],
      packets: [
        ['pam', 'vault', 'API', 'Check out db01 admin credential', 300, 'req'],
        ['vault', 'pam', 'API', 'Credential (lease 2 h)', 400, 'data'],
        ['adm', 'pam', 'SSH', 'Session via broker', 2200, 'req'],
        ['pam', 'db', 'SSH', 'Admin session (credential injected, recorded)', 2400, 'req'],
      ],
    },
    {
      title: 'Automatic expiry', sub: 'Access ends on its own',
      text: 'After two hours the broker ends the session, removes the role and tells the vault to rotate the password. Even if something on Bob\'s laptop captured traffic, there\'s nothing reusable left.',
      fields: [['Session', 'Closed'], ['Password', 'Rotated']],
      packets: [
        ['pam', 'db', 'SSH', 'Session terminated (lease expired)', 200, 'def'],
        ['pam', 'vault', 'API', 'Rotate db01 admin credential', 260, 'def'],
        ['vault', 'db', 'API', 'Set new random password', 300, 'def'],
      ],
    },
    {
      title: 'Audit and alerting', sub: 'Every privileged action is visible',
      text: 'The request, approval, session recording and rotation all go to the SIEM. A rule alerts if anyone logs into the database as admin without going through the broker, which is a strong sign of a stolen credential.',
      fields: [['Logged', 'Request, approval, session, rotation'], ['Alert', 'Admin login not via PAM']],
      defend: 'Review who requested what each month. Roles nobody uses should be removed.',
      packets: [
        ['pam', 'siem', 'Syslog', 'pam.session bob db-admin db01 2h INC-4821', 900, 'def'],
        ['db', 'siem', 'Syslog', 'admin login source=pam-broker ✓', 500, 'def'],
      ],
    },
  ],
});
