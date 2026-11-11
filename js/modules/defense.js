/* Domain: Defense & Blue Team */

SE.register({
  id: 'waf', domain: 'defense', kind: 'defense', level: 'Beginner', severity: 'Control',
  name: 'Web Application Firewall', full: 'Inspecting HTTP before it reaches the app',
  tags: ['waf', 'modsecurity', 'crs', 'rate limit', 'reverse proxy'],
  summary: 'A WAF sits in front of a web app as a reverse proxy and inspects every HTTP request. It blocks known attack patterns, rate-limits abuse and logs everything. It\'s a valuable layer, but not a substitute for fixing the code.',
  facts: [['Placement', 'Reverse proxy / CDN edge'], ['Common ruleset', 'OWASP Core Rule Set (CRS)'], ['Detection', 'Signatures + anomaly scoring'], ['Modes', 'Detect-only → Block'], ['Weakness', 'Bypasses, false positives'], ['Pairs with', 'Secure code, SIEM']],
  defenses: [
    'Start in detection-only mode, tune false positives, then switch to blocking',
    'Rate-limit login, signup and password-reset endpoints',
    'Send WAF events to your SIEM and alert on spikes',
    'Fix the underlying bugs; treat the WAF as defense in depth',
    'Keep rules updated and add virtual patches for new CVEs while you fix them',
  ],
  nodes: [
    { id: 'usr', type: 'browser', label: 'Customer', sub: '192.0.2.44', x: 120, y: 110 },
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: '203.0.113.66', x: 120, y: 385 },
    { id: 'waf', type: 'shield', label: 'WAF', sub: 'reverse proxy', x: 450, y: 245 },
    { id: 'app', type: 'server', label: 'Web App', sub: 'shop.example', x: 780, y: 245 },
    { id: 'siem', type: 'siem', label: 'SIEM', sub: 'security logs', x: 780, y: 420 },
  ],
  steps: [
    {
      title: 'Normal traffic', sub: 'Inspected and passed',
      text: 'Every request terminates at the WAF first. A normal product request scores 0 against the rules and is forwarded to the app unchanged.',
      fields: [['Anomaly score', '0'], ['Action', 'Pass']],
      packets: [
        ['usr', 'waf', 'HTTPS', 'GET /products?id=7', 412, 'req'],
        ['waf', 'app', 'HTTP', 'GET /products?id=7 (X-Forwarded-For: 192.0.2.44)', 450, 'req'],
        ['app', 'waf', 'HTTP', '200 OK', 5310, 'res'],
        ['waf', 'usr', 'HTTPS', '200 OK', 5310, 'res'],
      ],
    },
    {
      title: 'Attack pattern blocked', sub: 'Rules + anomaly score',
      text: 'An injection attempt matches several SQL-injection rules. Their scores add up past the blocking threshold, so the WAF answers 403 itself. The request never reaches the app, and an event goes to the SIEM.',
      fields: [['Matched', 'SQLi rules (942xxx family)'], ['Score', '10 ≥ threshold 5 → block']],
      packets: [
        ['atk', 'waf', 'HTTPS', "GET /products?id=1' UNION SELECT …", 498, 'atk'],
        ['waf', 'waf', 'CRS', 'SQL injection rules matched, anomaly score 10', 0, 'def'],
        ['waf', 'atk', 'HTTPS', '403 Forbidden', 210, 'def'],
        ['waf', 'siem', 'Syslog', 'waf.block rule=942100 src=203.0.113.66 uri=/products', 640, 'def'],
      ],
    },
    {
      title: 'Rate limiting', sub: 'Slowing brute force',
      text: 'The attacker scripts hundreds of login attempts per second. A rate-limit rule on `/login` allows a few per minute per IP and account, then returns 429.',
      fields: [['Limit', '10 req/min per IP on /login'], ['Response', '429 Too Many Requests']],
      packets: [
        ['atk', 'waf', 'HTTPS', 'POST /login × 300/s', 190000, 'atk'],
        ['waf', 'atk', 'HTTPS', '429 Too Many Requests (Retry-After: 60)', 180, 'def'],
        ['waf', 'siem', 'Syslog', 'waf.ratelimit /login src=203.0.113.66', 520, 'def'],
      ],
    },
    {
      title: 'Defense in depth', sub: 'When a request slips through',
      text: 'No ruleset catches everything: unusual encodings or new techniques can get past. That\'s why the app behind it still uses parameterized queries. The WAF buys time and visibility; secure code closes the hole.',
      fields: [['WAF', 'Missed (false negative)'], ['App', 'Prepared statement → harmless']],
      defend: 'Measure both: false positives annoy customers, false negatives are why you still fix the code.',
      packets: [
        ['atk', 'waf', 'HTTPS', 'GET /products?id=… (obfuscated payload)', 520, 'atk'],
        ['waf', 'app', 'HTTP', 'Forwarded (no rule matched)', 560, 'atk'],
        ['app', 'waf', 'HTTP', '404 Not Found (parameterized query, no injection)', 600, 'def'],
        ['waf', 'atk', 'HTTPS', '404 Not Found', 600, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'ids', domain: 'defense', kind: 'defense', level: 'Intermediate', severity: 'Control',
  name: 'Network IDS / IPS', full: 'Detecting attacks on the wire',
  tags: ['ids', 'ips', 'suricata', 'snort', 'zeek', 'span', 'tap', 'signatures'],
  summary: 'A network intrusion detection system watches copies of traffic and raises alerts on known-bad patterns and suspicious behaviour. In inline (IPS) mode it can drop malicious packets itself.',
  facts: [['Open-source tools', 'Suricata, Snort, Zeek'], ['Feed', 'SPAN port or network TAP'], ['Detection', 'Signatures + anomalies'], ['IDS', 'Passive, alerts only'], ['IPS', 'Inline, can block'], ['Blind spot', 'Encrypted payloads']],
  defenses: [
    'Place sensors at chokepoints: internet edge, between segments, data-center core',
    'Use maintained rule feeds and tune them for your environment',
    'Combine with flow/metadata logging (e.g. Zeek) for encrypted traffic',
    'Forward alerts to a SIEM with asset context',
    'Run IPS mode only where a false positive won\'t break critical traffic',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'External Host', sub: '203.0.113.66', x: 120, y: 200 },
    { id: 'sw', type: 'switch', label: 'Core Switch', sub: 'SPAN port', x: 450, y: 200 },
    { id: 'srv', type: 'server', label: 'Web Server', sub: '10.0.0.20', x: 780, y: 200 },
    { id: 'ids', type: 'ids', label: 'IDS Sensor', sub: 'Suricata', x: 450, y: 410 },
    { id: 'siem', type: 'siem', label: 'SIEM', sub: 'alerts', x: 780, y: 410 },
  ],
  steps: [
    {
      title: 'Mirroring traffic', sub: 'A copy, not the original',
      text: 'The switch copies every frame on the monitored link to a SPAN port connected to the sensor. The IDS sees everything but sits out of the path, so it can\'t slow down or break traffic.',
      fields: [['Feed', 'SPAN (mirror) port'], ['Mode', 'Passive IDS']],
      packets: [
        ['atk', 'sw', 'HTTP', 'GET /index.html', 420, 'req'],
        ['sw', 'srv', 'HTTP', 'GET /index.html', 420, 'req'],
        ['sw', 'ids', 'SPAN', 'Mirrored copy', 420, 'ctl'],
      ],
    },
    {
      title: 'Signature match', sub: 'Known-bad pattern',
      text: 'A request contains a pattern matching a rule for command-injection attempts against CGI scripts. The sensor raises an alert with the rule ID, source, destination and the matching bytes.',
      fields: [['Rule', 'Command injection attempt (sid 1000001)'], ['Severity', 'High']],
      packets: [
        ['atk', 'sw', 'HTTP', 'GET /cgi-bin/status?host=…;… (suspicious)', 510, 'atk'],
        ['sw', 'srv', 'HTTP', 'Forwarded (IDS is passive)', 510, 'atk'],
        ['sw', 'ids', 'SPAN', 'Mirrored copy', 510, 'ctl'],
        ['ids', 'ids', 'Rule', 'alert http … msg:"Command injection attempt" sid:1000001', 0, 'def'],
        ['ids', 'siem', 'EVE JSON', 'alert sid=1000001 src=203.0.113.66 dst=10.0.0.20', 900, 'def',
          `{
  "event_type": "alert",
  "src_ip": "203.0.113.66", "dest_ip": "10.0.0.20", "dest_port": 80,
  "alert": { "signature_id": 1000001,
             "signature": "Command injection attempt",
             "severity": 1, "category": "Web Application Attack" },
  "http": { "url": "/cgi-bin/status?host=…" }
}`],
      ],
    },
    {
      title: 'Behaviour anomaly', sub: 'No single bad packet',
      text: 'Some activity is only suspicious in aggregate. One host touching 1,000 ports in a few seconds matches a threshold rule for port scanning, even though each packet is just an ordinary SYN.',
      fields: [['Pattern', '1,000 ports / 3 s from one source'], ['Alert', 'Possible port scan']],
      packets: [
        ['atk', 'sw', 'TCP', '[SYN] to 1,000 ports in 3 s', 66000, 'atk'],
        ['sw', 'ids', 'SPAN', 'Mirrored copies', 66000, 'ctl'],
        ['ids', 'siem', 'EVE JSON', 'alert "Possible port scan" src=203.0.113.66', 700, 'def'],
      ],
    },
    {
      title: 'IPS mode', sub: 'Inline and blocking',
      text: 'Placed inline instead of on a SPAN port, the same engine becomes an IPS: matching packets are dropped and the connection reset before they reach the server. That\'s more protection, but a bad rule can now block real users.',
      fields: [['Placement', 'Inline (bridge)'], ['Action', 'drop + reset']],
      defend: 'Encrypted traffic hides payloads from network sensors. Pair them with endpoint telemetry and TLS-terminating proxies where appropriate.',
      packets: [
        ['atk', 'ids', 'HTTP', 'GET /cgi-bin/status?host=…;… (suspicious)', 510, 'atk'],
        ['ids', 'atk', 'TCP', '[RST] connection reset (drop rule)', 54, 'def'],
        ['ids', 'siem', 'EVE JSON', 'drop sid=1000001 src=203.0.113.66', 880, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'siem', domain: 'defense', kind: 'defense', level: 'Intermediate', severity: 'Process',
  name: 'SIEM Detection & Triage', full: 'From raw logs to a handled incident',
  tags: ['siem', 'soc', 'logs', 'correlation', 'triage', 'incident response', 'brute force'],
  summary: 'A SIEM collects logs from across the organisation, normalises them, and runs detection rules that link events no single system would notice. Analysts then triage the alerts and respond. Here\'s one brute-force alert followed end to end.',
  facts: [['Examples', 'Splunk, Elastic, Sentinel, Wazuh'], ['Detects', 'T1110 (Brute Force)'], ['Key Windows events', '4625 failed, 4624 success'], ['Normalisation', 'ECS / CIM field names'], ['Output', 'Alerts → cases'], ['Response model', 'NIST SP 800-61']],
  defenses: [
    'Collect the high-value sources first: identity, endpoints, firewall/VPN, cloud audit logs',
    'Normalise fields so one rule works across sources',
    'Write detections around attacker behaviour, and test them',
    'Give alerts context (asset owner, user role, geo) to speed triage',
    'Document response playbooks and practise them',
  ],
  nodes: [
    { id: 'dc', type: 'dc', label: 'Domain Controller', sub: 'Security log', x: 120, y: 100 },
    { id: 'vpn', type: 'firewall', label: 'VPN / Firewall', sub: 'syslog', x: 120, y: 260 },
    { id: 'ep', type: 'workstation', label: 'Endpoints', sub: 'EDR telemetry', x: 120, y: 410 },
    { id: 'col', type: 'server', label: 'Log Collector', sub: 'parse + normalise', x: 430, y: 260 },
    { id: 'siem', type: 'siem', label: 'SIEM', sub: 'rules + search', x: 760, y: 150 },
    { id: 'soc', type: 'user', label: 'SOC Analyst', sub: 'on shift', x: 760, y: 390, good: true },
  ],
  steps: [
    {
      title: 'Collect', sub: 'Logs from everywhere',
      text: 'Sources send events to a collector: failed logons from the domain controller, VPN connections from the firewall, process activity from endpoints. One event alone means little.',
      fields: [['DC', 'Event 4625 (failed logon)'], ['VPN', 'Login attempts by IP']],
      packets: [
        ['dc', 'col', 'WEF', 'Event 4625 failed logon, user=j.smith × 48', 46000, 'ctl'],
        ['vpn', 'col', 'Syslog', 'vpn auth failure user=j.smith src=203.0.113.66 × 48', 21000, 'ctl'],
        ['ep', 'col', 'EDR', 'Process + network telemetry', 8800, 'ctl'],
      ],
    },
    {
      title: 'Normalise', sub: 'One language for all logs',
      text: 'The collector parses each format and maps it to common fields like `user.name`, `source.ip` and `event.outcome`, so a single rule can reason across Windows, VPN and EDR data.',
      fields: [['user.name', 'j.smith'], ['source.ip', '203.0.113.66'], ['event.outcome', 'failure']],
      packets: [
        ['col', 'siem', 'HTTPS', 'Bulk index: 97 normalised events', 64000, 'ctl'],
      ],
    },
    {
      title: 'Correlate', sub: 'A rule fires',
      text: 'A detection rule looks for many failures followed by a success for the same user from the same IP within a short window. The VPN finally shows a successful login, so the rule fires a high-severity alert.',
      fields: [['Rule', '≥ 20 failures then success, 10 min'], ['Severity', 'High']],
      packets: [
        ['vpn', 'col', 'Syslog', 'vpn auth success user=j.smith src=203.0.113.66', 480, 'atk'],
        ['col', 'siem', 'HTTPS', 'Index event', 600, 'ctl'],
        ['siem', 'siem', 'Rule', 'Brute force followed by success → ALERT (high)', 0, 'def'],
      ],
    },
    {
      title: 'Triage', sub: 'Is it real?',
      text: 'The analyst checks context: the user normally logs in from the office, never from this country; the IP is on a threat-intel list; and there\'s new activity on the user\'s session. Verdict: true positive.',
      fields: [['Geo', 'Unusual country'], ['Threat intel', 'IP flagged'], ['Verdict', 'True positive']],
      packets: [
        ['siem', 'soc', 'Alert', 'HIGH: possible account compromise j.smith', 1200, 'def'],
        ['soc', 'siem', 'Query', 'All activity for user j.smith OR source.ip 203.0.113.66, last 24 h', 300, 'req'],
        ['siem', 'soc', 'Results', '1 VPN session, 3 file-share accesses', 5400, 'res'],
      ],
    },
    {
      title: 'Respond', sub: 'Contain, then recover',
      text: 'Following the playbook, the analyst disables the account and revokes its sessions, blocks the IP, and opens an incident to check what was accessed. Afterwards, the lesson (no MFA on the VPN) becomes a fix.',
      fields: [['Contain', 'Disable account, block IP'], ['Follow-up', 'Enforce MFA on VPN']],
      defend: 'Measure time to detect and time to respond, and review every incident for detections you could add.',
      packets: [
        ['soc', 'dc', 'Action', 'Disable j.smith, reset password, revoke sessions', 300, 'def'],
        ['soc', 'vpn', 'Action', 'Block 203.0.113.66, terminate active session', 260, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'zero-trust', domain: 'defense', kind: 'defense', level: 'Intermediate', severity: 'Architecture',
  name: 'Zero Trust Access', full: 'Never trust the network, verify every request',
  tags: ['zero trust', 'ztna', 'beyondcorp', 'device posture', 'conditional access', 'sso'],
  summary: 'Zero Trust drops the idea that being "inside the network" means being trusted. Every request to every app is checked against who the user is, the health of their device, and policy, and checked again continuously.',
  facts: [['Reference', 'NIST SP 800-207'], ['Replaces', 'Flat VPN access'], ['PEP', 'Policy Enforcement Point (proxy)'], ['PDP', 'Policy Decision Point (engine)'], ['Signals', 'Identity, device, risk, context'], ['Principle', 'Least privilege, per app']],
  defenses: [
    'Put every internal app behind an identity-aware proxy',
    'Require phishing-resistant MFA (FIDO2/passkeys)',
    'Check device health (managed, encrypted, patched, EDR running)',
    'Grant access per app and per role, not to whole networks',
    'Re-evaluate sessions continuously and revoke on risk changes',
  ],
  nodes: [
    { id: 'u', type: 'client', label: 'Employee Laptop', sub: 'alice (finance)', x: 120, y: 245 },
    { id: 'pep', type: 'shield', label: 'Access Proxy', sub: 'PEP', x: 450, y: 245 },
    { id: 'pdp', type: 'idp', label: 'Policy Engine', sub: 'PDP + IdP', x: 450, y: 90, good: true },
    { id: 'mdm', type: 'lock', label: 'Device Posture', sub: 'MDM / EDR', x: 450, y: 405, good: true },
    { id: 'app', type: 'server', label: 'Payroll App', sub: 'internal', x: 780, y: 245 },
  ],
  steps: [
    {
      title: 'Request from anywhere', sub: 'No VPN, no implicit trust',
      text: 'Alice opens the payroll app from a café. There\'s no VPN: the app is only reachable through the access proxy, which treats this request like any other, whatever network it came from.',
      fields: [['Network', 'Untrusted (café Wi-Fi)'], ['App exposure', 'Only via proxy']],
      packets: [
        ['u', 'pep', 'HTTPS', 'GET https://payroll.corp.example/', 520, 'req'],
      ],
    },
    {
      title: 'Verify identity', sub: 'SSO + strong MFA',
      text: 'With no valid session, the proxy sends Alice to the identity provider. She signs in with a passkey, which is phishing-resistant because it\'s bound to the real domain.',
      fields: [['Method', 'OIDC SSO'], ['MFA', 'Passkey (FIDO2)']],
      packets: [
        ['pep', 'u', 'HTTPS', '302 → identity provider', 400, 'res'],
        ['u', 'pdp', 'HTTPS', 'Sign-in with passkey', 1600, 'ctl'],
        ['pdp', 'u', 'HTTPS', '302 → proxy with signed ID token', 1400, 'res'],
        ['u', 'pep', 'HTTPS', 'GET / (ID token)', 1500, 'req'],
      ],
    },
    {
      title: 'Verify device', sub: 'Is this laptop healthy?',
      text: 'The proxy asks the device-posture service about this laptop: company-managed, disk encrypted, OS patched, EDR running. All checks pass.',
      fields: [['Managed', 'Yes'], ['Encrypted / patched / EDR', '✓ / ✓ / ✓']],
      packets: [
        ['pep', 'mdm', 'API', 'Posture for device id 7f2c…?', 300, 'req'],
        ['mdm', 'pep', 'API', 'compliant: managed, encrypted, patched, EDR healthy', 420, 'def'],
      ],
    },
    {
      title: 'Policy decision', sub: 'Least privilege, per app',
      text: 'The proxy sends all the signals to the policy engine. The rule for payroll says: finance group, compliant device, low sign-in risk. It allows access to this one app only, for a limited session.',
      fields: [['Policy', 'group=finance AND device=compliant AND risk=low'], ['Decision', 'ALLOW payroll only, 8 h']],
      packets: [
        ['pep', 'pdp', 'Policy', 'user=alice group=finance device=compliant risk=low app=payroll', 380, 'req'],
        ['pdp', 'pep', 'Policy', 'ALLOW (scope: payroll, session 8 h, continuous evaluation)', 260, 'def'],
        ['pep', 'app', 'mTLS', 'GET / (identity headers, mutual TLS)', 900, 'req'],
        ['app', 'pep', 'mTLS', '200 OK', 18000, 'res'],
        ['pep', 'u', 'HTTPS', '200 OK (payroll dashboard)', 18000, 'res'],
      ],
    },
    {
      title: 'Continuous evaluation', sub: 'Trust can be withdrawn',
      text: 'An hour later the EDR agent on the laptop stops reporting, perhaps disabled by malware. The posture service flags the change and the proxy revokes the session straight away instead of waiting for it to expire.',
      fields: [['Trigger', 'EDR stopped reporting'], ['Action', 'Session revoked, re-verify required']],
      defend: 'This is the core difference from a VPN: access is a decision made repeatedly, not once at the front door.',
      packets: [
        ['mdm', 'pep', 'Signal', 'Device 7f2c… non-compliant: EDR not reporting', 300, 'atk'],
        ['pep', 'u', 'HTTPS', '401: session revoked, device must be remediated', 600, 'def'],
      ],
    },
  ],
});
