/* Domain: API Security (OWASP API Security Top 10, 2023) */

SE.register({
  id: 'api-gateway', domain: 'api', kind: 'protocol', level: 'Beginner', severity: 'Protocol',
  name: 'Secure API Request', full: 'What a well-protected API call goes through',
  tags: ['api gateway', 'bearer token', 'jwt', 'rate limit', 'schema validation', 'rest'],
  summary: 'Before looking at how APIs break, see what a well-protected call looks like. A request passes through a gateway that checks the token, rate limits and schema, and then the service itself checks what this caller may do with this object.',
  facts: [['Standard', 'OWASP API Security Top 10 (2023)'], ['Auth', 'OAuth 2.0 bearer tokens'], ['Gateway duties', 'AuthN, rate limit, schema, logging'], ['Service duties', 'Authorization per object/function'], ['Transport', 'HTTPS (TLS 1.2+)'], ['See also', 'OAuth 2.0 + PKCE, IDOR']],
  defenses: [
    'Keep an inventory of every API, version and environment (API9)',
    'Validate tokens centrally at the gateway, and authorize inside each service',
    'Validate requests and responses against an OpenAPI schema',
    'Rate-limit per client and per user; cap page sizes',
    'Log every call with a correlation ID',
  ],
  nodes: [
    { id: 'cli', type: 'phone', label: 'Mobile App', sub: 'user: alice', x: 120, y: 245 },
    { id: 'gw', type: 'gateway', label: 'API Gateway', sub: 'api.example', x: 380, y: 245 },
    { id: 'idp', type: 'idp', label: 'Auth Server', sub: 'JWKS keys', x: 380, y: 90 },
    { id: 'svc', type: 'server', label: 'Orders Service', sub: 'internal', x: 640, y: 245 },
    { id: 'db', type: 'db', label: 'Orders DB', sub: '', x: 820, y: 400 },
  ],
  steps: [
    {
      title: 'Call with a token', sub: 'Bearer token over HTTPS',
      text: 'The app calls the API with an access token it got from the auth server via OAuth. The token is short-lived and scoped to `orders:read`.',
      fields: [['Endpoint', 'GET /v1/orders/5521'], ['Scope', 'orders:read']],
      packets: [
        ['cli', 'gw', 'HTTPS', 'GET /v1/orders/5521 (Authorization: Bearer eyJ…)', 980, 'req'],
      ],
    },
    {
      title: 'Gateway checks', sub: 'Who are you? Not too fast? Well-formed?',
      text: 'The gateway verifies the token\'s signature with the auth server\'s published keys (cached), checks expiry, audience and scope, applies the rate limit for this client, and validates the request against the OpenAPI schema.',
      fields: [['Signature / exp / aud', '✓ / ✓ / ✓'], ['Rate limit', '42 of 100 per minute'], ['Schema', 'orderId is an integer ✓']],
      packets: [
        ['gw', 'idp', 'HTTPS', 'GET /.well-known/jwks.json (cached 1 h)', 300, 'ctl'],
        ['idp', 'gw', 'HTTPS', '200 {keys:[…]}', 1800, 'res'],
        ['gw', 'gw', 'Policy', 'JWT valid, scope ok, rate ok, schema ok', 0, 'def'],
      ],
    },
    {
      title: 'Service authorizes', sub: 'May alice see order 5521?',
      text: 'The gateway forwards the request with the verified identity. The service still makes the authorization decision itself, because only it knows that order 5521 belongs to alice. Skipping this check is the #1 API flaw, BOLA (see the IDOR module).',
      fields: [['Identity', 'sub=alice (from gateway)'], ['Query', 'WHERE id = 5521 AND customer_id = alice']],
      packets: [
        ['gw', 'svc', 'HTTP', 'GET /orders/5521 (X-User: alice, X-Request-Id: 9f1c…)', 640, 'req'],
        ['svc', 'db', 'SQL', 'SELECT … WHERE id = 5521 AND customer_id = ?', 120, 'def'],
        ['db', 'svc', 'SQL', '1 row', 400, 'res'],
      ],
    },
    {
      title: 'Minimal response', sub: 'Only the fields the client needs',
      text: 'The service returns a response built from an explicit output model, not the raw database row. Internal fields such as cost price or fraud score never leave, and the gateway logs the call for monitoring.',
      fields: [['Returned', 'id, status, items, total'], ['Not returned', 'internal_notes, fraud_score']],
      defend: 'Define response models explicitly. "Return the whole object and let the client filter it" leaks data (API3).',
      packets: [
        ['svc', 'gw', 'HTTP', '200 {"id":5521,"status":"shipped","total":42.50}', 520, 'res'],
        ['gw', 'cli', 'HTTPS', '200 OK', 560, 'res'],
      ],
    },
  ],
});

SE.register({
  id: 'mass-assignment', domain: 'api', kind: 'attack', level: 'Beginner', severity: 'High',
  name: 'Mass Assignment', full: 'Broken Object Property Level Authorization',
  tags: ['mass assignment', 'bopla', 'excessive data exposure', 'api3', 'over-posting'],
  summary: 'Many frameworks can bind a JSON body straight onto a database object. If the API doesn\'t limit which properties a caller may set (or see), a user can send extra fields like `"role":"admin"` and the server saves them.',
  facts: [['OWASP API', 'API3:2023 BOPLA'], ['CWE', 'CWE-915'], ['Also called', 'Over-posting, autobinding'], ['Read side', 'Excessive data exposure'], ['Root cause', 'Binding whole objects'], ['Impact', 'Privilege escalation, data tampering']],
  defenses: [
    'Use explicit input DTOs / allow-lists of writable fields per endpoint',
    'Never bind request bodies directly to database models',
    'Mark sensitive properties read-only in the schema and reject unknown fields',
    'Use explicit output models so you never return more than intended',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Regular User', sub: 'mallory', x: 130, y: 245 },
    { id: 'api', type: 'api', label: 'Users API', sub: 'PATCH /v1/users/me', x: 460, y: 245 },
    { id: 'db', type: 'db', label: 'Users DB', sub: 'role, plan, credits…', x: 780, y: 245 },
  ],
  steps: [
    {
      title: 'Normal profile update', sub: 'Changing a display name',
      text: 'The app sends a PATCH with the field the user edited. Server code does something like `user.update(request.json)`, copying every key in the body onto the user record.',
      fields: [['Body', '{"displayName":"Mal"}'], ['Code', 'user.update(**body)']],
      packets: [
        ['atk', 'api', 'HTTPS', 'PATCH /v1/users/me {"displayName":"Mal"}', 420, 'req'],
        ['api', 'db', 'SQL', 'UPDATE users SET display_name = ? WHERE id = 77', 110, 'req'],
        ['api', 'atk', 'HTTPS', '200 {"id":77,"displayName":"Mal","role":"user","plan":"free"}', 380, 'res'],
      ],
    },
    {
      title: 'The response gives hints', sub: 'Excessive data exposure',
      text: 'The response echoes the whole user object, including `role` and `plan`. The user now knows the property names the server stores.',
      fields: [['Leaked names', 'role, plan, credits'], ['Problem', 'Full model returned']],
      packets: [
        ['atk', 'api', 'HTTPS', 'GET /v1/users/me', 380, 'req'],
        ['api', 'atk', 'HTTPS', '200 {…, "role":"user", "plan":"free", "credits":0}', 420, 'data'],
      ],
    },
    {
      title: 'Adding extra properties', sub: 'The server saves them',
      text: 'The user adds `"role":"admin"` and `"plan":"enterprise"` to the same PATCH. The binder copies every key, so the account is now an admin on the top plan.',
      fields: [['Body', '{"displayName":"Mal","role":"admin","plan":"enterprise"}'], ['Result', 'Privilege escalation']],
      packets: [
        ['atk', 'api', 'HTTPS', 'PATCH /v1/users/me {"displayName":"Mal","role":"admin","plan":"enterprise"}', 470, 'atk'],
        ['api', 'db', 'SQL', 'UPDATE users SET display_name=?, role=?, plan=? WHERE id = 77', 140, 'atk'],
        ['api', 'atk', 'HTTPS', '200 {"role":"admin","plan":"enterprise"}', 380, 'data'],
      ],
    },
    {
      title: 'Fix: allow-listed fields', sub: 'Explicit input and output models',
      text: 'The endpoint now accepts a `ProfileUpdate` model containing only `displayName` and `avatarUrl`, and rejects unknown fields. Role and plan can only be changed through separate admin and billing flows.',
      fields: [['Writable', 'displayName, avatarUrl'], ['Unknown fields', '422 rejected']],
      defend: 'Make the safe pattern the default in your framework, e.g. strict schemas with additionalProperties: false.',
      packets: [
        ['atk', 'api', 'HTTPS', 'PATCH /v1/users/me {"displayName":"Mal","role":"admin"}', 440, 'atk'],
        ['api', 'atk', 'HTTPS', '422 Unprocessable Entity — unknown field "role"', 200, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'bfla', domain: 'api', kind: 'attack', level: 'Beginner', severity: 'High',
  name: 'Broken Function Authorization', full: 'Calling admin endpoints as a normal user',
  tags: ['bfla', 'api5', 'admin endpoint', 'authorization', 'rbac'],
  summary: 'Broken Function Level Authorization (BFLA) means the API checks that you\'re logged in, but not whether your role may use that function. Admin endpoints hidden from the UI are still reachable by anyone who guesses or finds the URL.',
  facts: [['OWASP API', 'API5:2023 BFLA'], ['CWE', 'CWE-285'], ['Typical find', 'Docs, JS bundles, predictable paths'], ['Differs from BOLA', 'Function, not object'], ['Impact', 'Admin actions by regular users'], ['Fix', 'Deny by default, role checks']],
  defenses: [
    'Deny by default; every route must declare its required role or permission',
    'Enforce authorization on the server; hiding buttons in the UI is not security',
    'Keep admin APIs on a separate host or path with extra controls',
    'Write automated tests calling every admin route as a normal user',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Regular User', sub: 'role=user', x: 130, y: 245 },
    { id: 'api', type: 'api', label: 'API', sub: 'api.example', x: 460, y: 245 },
    { id: 'db', type: 'db', label: 'Database', sub: '', x: 780, y: 245 },
  ],
  steps: [
    {
      title: 'Normal call', sub: 'Allowed function',
      text: 'A regular user lists their own projects. The API checks the token is valid and returns the data.',
      fields: [['Route', 'GET /v1/projects'], ['Check', 'Token valid ✓']],
      packets: [
        ['atk', 'api', 'HTTPS', 'GET /v1/projects (Bearer user token)', 420, 'req'],
        ['api', 'atk', 'HTTPS', '200 [3 projects]', 1400, 'res'],
      ],
    },
    {
      title: 'Discovering admin routes', sub: 'Hidden is not protected',
      text: 'The single-page app\'s JavaScript bundle contains every route, including admin ones that are only hidden in the UI. Predictable naming (`/v1/admin/...`) gives them away too.',
      fields: [['Found', 'DELETE /v1/admin/users/{id}'], ['Source', 'app.js bundle']],
      packets: [
        ['atk', 'api', 'HTTPS', 'GET /static/app.3f9a.js', 380, 'req'],
        ['api', 'atk', 'HTTPS', '200 (bundle with route table incl. /v1/admin/*)', 412000, 'data'],
      ],
    },
    {
      title: 'Calling an admin function', sub: 'Only authentication was checked',
      text: 'The admin route checks only that the token is valid, not that the caller is an admin. The regular user can list or delete any account.',
      fields: [['Route', 'GET /v1/admin/users'], ['Missing check', "role == 'admin'"]],
      packets: [
        ['atk', 'api', 'HTTPS', 'GET /v1/admin/users (Bearer user token)', 430, 'atk'],
        ['api', 'db', 'SQL', 'SELECT id, email, role FROM users', 80, 'atk'],
        ['db', 'api', 'SQL', '12,400 rows', 900000, 'data'],
        ['api', 'atk', 'HTTPS', '200 [all users]', 900000, 'data'],
      ],
    },
    {
      title: 'Fix: role checks, deny by default', sub: 'Every route declares a permission',
      text: 'Routes now declare required permissions, such as `@requires("users:admin")`, enforced by middleware. Any route without a declaration is refused, so new endpoints can\'t be left open by accident.',
      fields: [['Policy', 'users:admin required'], ['Response', '403 Forbidden']],
      defend: 'Alert when a non-admin token hits an admin path; that\'s almost never accidental.',
      packets: [
        ['atk', 'api', 'HTTPS', 'GET /v1/admin/users (Bearer user token)', 430, 'atk'],
        ['api', 'atk', 'HTTPS', '403 Forbidden — missing permission users:admin', 200, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'api-rate-limit', domain: 'api', kind: 'attack', level: 'Beginner', severity: 'Medium',
  name: 'Unrestricted Resource Use', full: 'APIs without limits',
  tags: ['rate limiting', 'api4', 'pagination', 'cost', 'dos', 'abuse'],
  summary: 'An API that puts no limits on how often, how much, or how expensively it can be called can be scraped, run up huge bills (SMS, email, compute), or knocked over by one client. Limits are a security control.',
  facts: [['OWASP API', 'API4:2023 Unrestricted Resource Consumption'], ['CWE', 'CWE-770'], ['Related', 'API6 Sensitive Business Flows'], ['Costs', 'Compute, SMS, email, storage'], ['Fix', 'Quotas, pagination caps, timeouts'], ['HTTP status', '429 Too Many Requests']],
  defenses: [
    'Rate-limit per API key, user and IP, with stricter limits on expensive endpoints',
    'Cap page sizes, upload sizes, query complexity and execution time',
    'Set spending limits and alerts on paid integrations (SMS, email, AI calls)',
    'Return 429 with Retry-After, and monitor for scraping patterns',
  ],
  nodes: [
    { id: 'bot', type: 'attacker', label: 'Script', sub: 'abusive client', x: 130, y: 245 },
    { id: 'api', type: 'api', label: 'API', sub: 'api.example', x: 460, y: 245 },
    { id: 'db', type: 'db', label: 'Database', sub: '', x: 780, y: 120 },
    { id: 'sms', type: 'phone', label: 'SMS Provider', sub: '$0.05 per message', x: 780, y: 390 },
  ],
  steps: [
    {
      title: 'Huge page sizes', sub: 'limit=1000000',
      text: 'The list endpoint accepts any `limit`. One request asks for a million rows, tying up the database and returning hundreds of megabytes.',
      fields: [['Param', 'limit=1000000'], ['Effect', 'Slow query, huge response']],
      packets: [
        ['bot', 'api', 'HTTPS', 'GET /v1/products?limit=1000000', 420, 'atk'],
        ['api', 'db', 'SQL', 'SELECT … LIMIT 1000000', 80, 'atk'],
        ['db', 'api', 'SQL', '1,000,000 rows (14 s)', 380000000, 'res'],
        ['api', 'bot', 'HTTPS', '200 OK (380 MB)', 380000000, 'data'],
      ],
    },
    {
      title: 'Costly side effects', sub: 'SMS on every request',
      text: 'The "send verification code" endpoint has no throttle. Every call sends a paid SMS, so a script calling it thousands of times runs up a large bill.',
      fields: [['Endpoint', 'POST /v1/otp/send'], ['Cost', '10,000 × $0.05 = $500 per run']],
      packets: [
        ['bot', 'api', 'HTTPS', 'POST /v1/otp/send × 10,000', 5200000, 'atk'],
        ['api', 'sms', 'HTTPS', 'Send SMS × 10,000', 4100000, 'atk'],
      ],
    },
    {
      title: 'Fix: limits everywhere', sub: 'Quotas, caps and budgets',
      text: 'Page size is capped at 100, the OTP endpoint allows 3 sends per phone number per hour, each client has a quota, and the SMS account has a daily spending cap with an alert.',
      fields: [['Max limit', '100'], ['OTP', '3 / number / hour'], ['Budget', 'Daily cap + alert']],
      defend: 'Watch cost dashboards as security signals; a sudden bill spike is often abuse.',
      packets: [
        ['bot', 'api', 'HTTPS', 'GET /v1/products?limit=1000000', 420, 'atk'],
        ['api', 'bot', 'HTTPS', '400 — limit must be ≤ 100', 160, 'def'],
        ['bot', 'api', 'HTTPS', 'POST /v1/otp/send (4th in an hour)', 520, 'atk'],
        ['api', 'bot', 'HTTPS', '429 Too Many Requests (Retry-After: 3600)', 180, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'webhook-hmac', domain: 'api', kind: 'defense', level: 'Intermediate', severity: 'Best practice',
  name: 'Signed Webhooks', full: 'Verifying webhook senders with HMAC',
  tags: ['webhook', 'hmac', 'signature', 'replay', 'timestamp', 'api10'],
  summary: 'Webhooks are API calls made *to* you. Anyone who finds your webhook URL can send fake events, such as "payment succeeded". Providers sign each delivery with a shared secret so you can check it really came from them and wasn\'t replayed.',
  facts: [['OWASP API', 'API10:2023 Unsafe Consumption of APIs'], ['Mechanism', 'HMAC-SHA256 over timestamp + body'], ['Replay defense', 'Timestamp tolerance + event IDs'], ['Compare', 'Constant-time'], ['CWE', 'CWE-345'], ['Common in', 'Payments, Git hosting, chat apps']],
  defenses: [
    'Verify the HMAC signature on the raw request body before parsing',
    'Reject old timestamps (e.g. older than 5 minutes) and duplicate event IDs',
    'Use constant-time comparison',
    'Store the webhook secret in a secrets manager and rotate it',
    'Treat webhook data as untrusted: re-fetch critical state from the provider\'s API',
  ],
  nodes: [
    { id: 'prov', type: 'server', label: 'Payment Provider', sub: 'sends webhooks', x: 130, y: 110 },
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: 'knows the URL', x: 130, y: 390 },
    { id: 'hook', type: 'api', label: 'Webhook Endpoint', sub: 'shop.example/hooks/pay', x: 520, y: 245 },
    { id: 'db', type: 'db', label: 'Orders DB', sub: '', x: 800, y: 245 },
  ],
  steps: [
    {
      title: 'A genuine event', sub: 'Signed by the provider',
      text: 'When a payment succeeds, the provider POSTs an event. It computes `HMAC-SHA256(secret, timestamp + "." + body)` and sends it in a header. Only the provider and the shop know the secret.',
      fields: [['Header', 'X-Signature: t=1794358000,v1=5f8a…'], ['Event', 'payment.succeeded order 9001']],
      packets: [
        ['prov', 'hook', 'HTTPS', 'POST /hooks/pay {"type":"payment.succeeded","order":9001} + X-Signature', 860, 'req',
          `POST /hooks/pay HTTP/1.1
Content-Type: application/json
X-Signature: t=1794358000,v1=5f8a2c…e91

{"id":"evt_81f2","type":"payment.succeeded","order":9001,"amount":4999}`],
      ],
    },
    {
      title: 'Verify, then act', sub: 'Recompute the HMAC',
      text: 'The endpoint recomputes the HMAC over the raw body with its copy of the secret, compares it in constant time, checks the timestamp is fresh and the event ID is new, and only then marks the order paid.',
      fields: [['Signature', 'match ✓'], ['Timestamp', '12 s old ✓'], ['Event ID', 'first time ✓']],
      packets: [
        ['hook', 'hook', 'HMAC', 'HMAC-SHA256(secret, t + "." + raw body) == v1 ✓', 0, 'def'],
        ['hook', 'db', 'SQL', 'UPDATE orders SET status = \'paid\' WHERE id = 9001', 110, 'req'],
        ['hook', 'prov', 'HTTPS', '200 OK', 60, 'res'],
      ],
    },
    {
      title: 'Forged event rejected', sub: 'No secret, no valid signature',
      text: 'An attacker who finds the URL posts a fake "payment succeeded" event. Without the secret they can\'t produce a valid signature, so the endpoint rejects it. Without this check, they would get goods for free.',
      fields: [['Signature', 'missing or invalid'], ['Result', '401, order unchanged']],
      packets: [
        ['atk', 'hook', 'HTTPS', 'POST /hooks/pay {"type":"payment.succeeded","order":9002} (no valid signature)', 700, 'atk'],
        ['hook', 'atk', 'HTTPS', '401 Unauthorized — bad signature', 120, 'def'],
      ],
    },
    {
      title: 'Replay rejected', sub: 'Old, valid messages',
      text: 'Even a real, correctly signed message could be captured and resent later. The timestamp tolerance and stored event IDs make each delivery usable once.',
      fields: [['Timestamp', '3 days old ✗'], ['Event ID', 'evt_81f2 already processed']],
      defend: 'For high-value events, confirm by calling the provider\'s API (GET payment) before shipping anything.',
      packets: [
        ['atk', 'hook', 'HTTPS', 'POST /hooks/pay (replayed evt_81f2 with original signature)', 860, 'atk'],
        ['hook', 'atk', 'HTTPS', '400 — timestamp outside tolerance / duplicate event', 140, 'def'],
      ],
    },
  ],
});
