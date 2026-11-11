/* Domain: Security Operations (SOC) */

SE.register({
  id: 'phishing-triage', domain: 'soc', kind: 'defense', level: 'Beginner', severity: 'Process',
  name: 'Phishing Investigation', full: 'From a reported email to a cleaned-up mailbox',
  tags: ['phishing', 'soc', 'email', 'spf', 'dkim', 'dmarc', 'sandbox', 'triage', 'report button'],
  summary: 'Phishing is the most common alert a SOC handles. This walks through one reported email: reading the headers, checking the link safely in a sandbox, finding everyone who received or clicked it, and cleaning up.',
  facts: [['Technique', 'T1566.002'], ['Email checks', 'SPF, DKIM, DMARC'], ['Safe analysis', 'Sandbox / URL detonation'], ['Scope with', 'Mail and proxy logs'], ['Typical goal', 'Credential theft'], ['Response model', 'NIST SP 800-61']],
  defenses: [
    'Give users a one-click "Report phishing" button and thank them for using it',
    'Enforce DMARC on your own domains so others can\'t spoof them',
    'Flag external senders and newly registered lookalike domains',
    'Search and purge every copy of a confirmed phish, not just the reported one',
    'Reset passwords and revoke sessions for anyone who entered credentials',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Sender', sub: 'micros0ft-billing.example', x: 120, y: 100 },
    { id: 'mx', type: 'mail', label: 'Mail Gateway', sub: 'corp.example', x: 450, y: 100 },
    { id: 'u', type: 'user', label: 'Employee', sub: 'reports the email', x: 780, y: 100 },
    { id: 'soc', type: 'user', label: 'SOC Analyst', sub: 'triage queue', x: 780, y: 390, good: true },
    { id: 'sbx', type: 'container', label: 'Sandbox', sub: 'URL detonation', x: 450, y: 390 },
  ],
  steps: [
    {
      title: 'Reported by a user', sub: 'The best sensor you have',
      text: 'An invoice email from a lookalike domain passes the gateway, because the sender\'s own SPF record is valid. An employee finds it suspicious and clicks "Report phishing", which sends a copy to the SOC queue.',
      fields: [['Subject', '"Overdue invoice: action required"'], ['Recipients', 'Unknown yet']],
      packets: [
        ['atk', 'mx', 'SMTP', 'MAIL FROM:<billing@micros0ft-billing.example>', 3800, 'atk'],
        ['mx', 'u', 'SMTP', 'Delivered to inbox', 3800, 'atk'],
        ['u', 'soc', 'Report', 'Reported as phishing (original attached)', 4200, 'def'],
      ],
    },
    {
      title: 'Read the headers', sub: 'Who really sent it?',
      text: 'The analyst checks the headers. The display name says Microsoft, but the domain uses a zero instead of an "o" and was registered two days ago. SPF passes only because it\'s the attacker\'s own domain; DMARC alignment with the real brand fails.',
      fields: [['From', 'Microsoft Billing <billing@micros0ft-billing.example>'], ['Domain age', '2 days'], ['Verdict so far', 'Suspicious']],
      packets: [
        ['soc', 'soc', 'Analysis', 'Header review: lookalike domain, new registration', 0, 'def',
          `From: "Microsoft Billing" <billing@micros0ft-billing.example>
Reply-To: <payments@another-domain.example>
Return-Path: <bounce@micros0ft-billing.example>
Received: from mail.micros0ft-billing.example (203.0.113.25)
Authentication-Results: mx.corp.example;
   spf=pass smtp.mailfrom=micros0ft-billing.example;
   dkim=pass header.d=micros0ft-billing.example;
   dmarc=pass header.from=micros0ft-billing.example
Subject: Overdue invoice: action required`],
      ],
    },
    {
      title: 'Detonate the link', sub: 'Safely, never on your laptop',
      text: 'The email links to a "view invoice" page. The analyst submits the URL to a sandbox, which opens it in an isolated browser and records what happens: a fake sign-in page that posts credentials to the attacker\'s server.',
      fields: [['Behaviour', 'Fake sign-in form'], ['Verdict', 'Malicious: credential harvesting']],
      packets: [
        ['soc', 'sbx', 'API', 'Submit URL hxxps://micros0ft-billing[.]example/inv', 400, 'req'],
        ['sbx', 'atk', 'HTTPS', 'GET /inv (isolated browser)', 600, 'ctl'],
        ['atk', 'sbx', 'HTTPS', 'Fake sign-in page', 42000, 'atk'],
        ['sbx', 'soc', 'API', 'Verdict: phishing (credential harvest), screenshot attached', 180000, 'def'],
      ],
    },
    {
      title: 'Scope it', sub: 'Who else got it? Who clicked?',
      text: 'One report rarely means one recipient. Searching mail logs by sender and subject finds 23 recipients. Web proxy logs show two of them opened the link, and one submitted the form.',
      fields: [['Recipients', '23'], ['Clicked', '2'], ['Entered credentials', '1']],
      packets: [
        ['soc', 'mx', 'Search', 'sender=*@micros0ft-billing.example last 48 h', 300, 'req'],
        ['mx', 'soc', 'Search', '23 messages delivered', 6000, 'res'],
      ],
    },
    {
      title: 'Respond', sub: 'Purge, block, reset',
      text: 'The analyst purges all 23 copies from mailboxes, blocks the domain and URL, resets the password and revokes sessions for the user who entered credentials, and checks their recent sign-ins. The reporter gets a thank-you.',
      fields: [['Purged', '23 emails'], ['Blocked', 'Domain + URL'], ['Account', 'Reset + sessions revoked']],
      defend: 'Fast reporting shrinks the damage. Track time from first delivery to purge, and celebrate the people who report.',
      packets: [
        ['soc', 'mx', 'Action', 'Purge 23 messages, block sender domain', 400, 'def'],
        ['soc', 'u', 'Email', 'Thanks for reporting: confirmed phishing, removed', 900, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'edr-detection', domain: 'soc', kind: 'defense', level: 'Intermediate', severity: 'Control',
  name: 'EDR Detection & Isolation', full: 'Catching malicious behaviour on an endpoint',
  tags: ['edr', 'xdr', 'endpoint', 'process tree', 'isolation', 'credential dumping', 'lsass', 'soc'],
  summary: 'Endpoint detection and response (EDR) agents record what happens on each laptop and server: processes, files, network connections. Here an agent spots a suspicious chain of processes, blocks an attempt to steal credentials from memory, and lets the SOC isolate the machine.',
  facts: [['Examples', 'Defender for Endpoint, CrowdStrike, SentinelOne'], ['Sees', 'Processes, files, network, registry'], ['Detects', 'Behaviour, not just signatures'], ['Techniques here', 'T1204.002, T1059.001, T1003.001'], ['Response', 'Kill, quarantine, isolate'], ['Pairs with', 'SIEM, SOAR']],
  defenses: [
    'Deploy EDR on every endpoint and server, and alert when an agent goes silent',
    'Turn on tamper protection so malware can\'t switch the agent off',
    'Enable credential protections such as LSASS protection / Credential Guard',
    'Block Office apps from launching script interpreters',
    'Practise host isolation so the SOC can use it in seconds',
  ],
  nodes: [
    { id: 'ws', type: 'workstation', label: 'Finance Laptop', sub: 'EDR agent', x: 120, y: 245 },
    { id: 'c2', type: 'c2', label: 'Unknown Server', sub: '203.0.113.80', x: 450, y: 400, evil: true },
    { id: 'edr', type: 'cloud', label: 'EDR Console', sub: 'cloud analytics', x: 450, y: 100, good: true },
    { id: 'soc', type: 'user', label: 'SOC Analyst', sub: 'on shift', x: 780, y: 100, good: true },
    { id: 'siem', type: 'siem', label: 'SIEM', sub: 'correlation', x: 780, y: 390 },
  ],
  steps: [
    {
      title: 'Constant telemetry', sub: 'The agent sees everything',
      text: 'The EDR agent streams events to the console: every process start with its parent and command line, file writes, network connections. Most of it is routine and simply stored for searching later.',
      fields: [['Events', 'Process, file, network, registry'], ['Volume', '~20k events/day/laptop']],
      packets: [
        ['ws', 'edr', 'TLS', 'Telemetry batch: process + network events', 64000, 'ctl'],
      ],
    },
    {
      title: 'Suspicious process chain', sub: 'Behaviour, not a known file',
      text: 'A user opens an attached spreadsheet. Excel starts PowerShell with an encoded command, which connects to an unfamiliar server and downloads something. No single file is known-bad, but the chain of behaviour is a classic attack pattern.',
      fields: [['Parent → child', 'excel.exe → powershell.exe -enc …'], ['Techniques', 'T1204.002 → T1059.001']],
      packets: [
        ['ws', 'c2', 'HTTPS', 'GET /update.bin (from powershell.exe)', 600, 'atk'],
        ['c2', 'ws', 'HTTPS', '200 payload', 220000, 'atk'],
        ['ws', 'edr', 'TLS', 'Process tree + network event', 3200, 'ctl',
          `explorer.exe (pid 4120)
 └─ excel.exe  "Invoice_Q4.xlsm"          (pid 7312)
     └─ powershell.exe -nop -w hidden -enc JABjAD0A…   (pid 7720)
         └─ network: 203.0.113.80:443  GET /update.bin
         └─ file write: %APPDATA%\\svc\\upd.exe`],
        ['edr', 'soc', 'Alert', 'HIGH: Office app spawned encoded PowerShell', 1400, 'def'],
      ],
    },
    {
      title: 'Credential theft blocked', sub: 'Automatic prevention',
      text: 'The downloaded program tries to open the memory of `lsass.exe`, the Windows process that holds logon secrets. The agent blocks the access and kills the process automatically, before any credentials are read.',
      fields: [['Attempt', 'Read LSASS memory'], ['Technique', 'T1003.001'], ['Action', 'Blocked + process killed']],
      packets: [
        ['ws', 'ws', 'Local', 'upd.exe → OpenProcess(lsass.exe) denied, process killed', 0, 'def'],
        ['ws', 'edr', 'TLS', 'Prevention event: credential access blocked', 2400, 'def'],
      ],
    },
    {
      title: 'Isolate the host', sub: 'Contain in one click',
      text: 'The analyst isolates the laptop. It can no longer talk to anything except the EDR console, so the attacker\'s connection is cut while the analyst can still investigate remotely, pulling files and the timeline.',
      fields: [['Network', 'Only EDR console allowed'], ['User impact', 'Laptop offline for work']],
      packets: [
        ['soc', 'edr', 'HTTPS', 'Isolate host FIN-LT-042', 300, 'def'],
        ['edr', 'ws', 'TLS', 'Network containment ON', 260, 'def'],
        ['ws', 'c2', 'HTTPS', 'Connection attempt blocked by isolation', 80, 'def'],
      ],
    },
    {
      title: 'Hunt and recover', sub: 'Was it only this laptop?',
      text: 'The analyst searches all endpoints for the file hash and the server address: no other hits. The laptop is reimaged, the user\'s password reset as a precaution, and the SIEM gets a new rule for this behaviour.',
      fields: [['Fleet search', 'Hash + IP: 0 other hosts'], ['Recovery', 'Reimage + password reset']],
      defend: 'Most of the value comes from speed: alert to isolation in minutes, not hours.',
      packets: [
        ['soc', 'edr', 'Query', 'Search fleet: sha256=9f2b… OR dst=203.0.113.80', 300, 'req'],
        ['edr', 'soc', 'Query', '1 host (already isolated)', 800, 'res'],
        ['edr', 'siem', 'API', 'Incident + indicators exported', 4000, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'incident-response', domain: 'soc', kind: 'defense', level: 'Intermediate', severity: 'Process',
  name: 'Incident Response Lifecycle', full: 'Handling a ransomware precursor, phase by phase',
  tags: ['incident response', 'ir', 'nist 800-61', 'containment', 'eradication', 'recovery', 'ransomware', 'soc', 'playbook'],
  summary: 'Incident response turns an alert into a controlled, documented recovery. This module follows the NIST lifecycle through a realistic case: early signs of a ransomware attack spotted on a server, contained before encryption started.',
  facts: [['Framework', 'NIST SP 800-61'], ['Phases', 'Prepare, Detect & analyse, Contain, Eradicate & recover, Lessons'], ['Precursors', 'T1021.001 (RDP), T1490'], ['Key metrics', 'Time to detect, time to contain'], ['Evidence', 'Preserve before wiping'], ['Recovery from', 'Offline, tested backups']],
  defenses: [
    'Prepare before you need it: playbooks, contacts, and an out-of-band chat channel',
    'Keep offline or immutable backups and test restoring them',
    'Preserve evidence (memory, disk, logs) before reimaging',
    'Contain fast: isolate hosts, disable accounts, block indicators',
    'Run a blameless lessons-learned review and turn findings into fixes',
  ],
  nodes: [
    { id: 'srv', type: 'server', label: 'File Server', sub: 'fs02', x: 120, y: 120 },
    { id: 'atk', type: 'attacker', label: 'Intruder', sub: 'via stolen VPN login', x: 120, y: 390 },
    { id: 'siem', type: 'siem', label: 'SIEM', sub: 'detections', x: 450, y: 120 },
    { id: 'ir', type: 'user', label: 'IR Lead', sub: 'SOC on call', x: 450, y: 390, good: true },
    { id: 'dc', type: 'dc', label: 'Domain Controller', sub: 'identity', x: 780, y: 120 },
    { id: 'bk', type: 'bucket', label: 'Backups', sub: 'immutable', x: 780, y: 390, good: true },
  ],
  steps: [
    {
      title: 'Detect and analyse', sub: 'Something isn\'t right',
      text: 'At 02:10 the SIEM fires two related alerts on the file server: a remote desktop logon from a service desk account that never uses RDP, then a command deleting volume shadow copies. Deleting backups is a classic step right before ransomware encryption.',
      fields: [['Alerts', 'Unusual RDP logon + shadow copy deletion'], ['Techniques', 'T1021.001, T1490'], ['Severity', 'Critical']],
      packets: [
        ['atk', 'srv', 'RDP', 'Logon as svc-helpdesk', 4800, 'atk'],
        ['srv', 'siem', 'WEF', '4624 logon type 10 + vssadmin delete shadows', 2200, 'def'],
        ['siem', 'ir', 'Page', 'CRITICAL: possible ransomware precursor on fs02', 600, 'def'],
      ],
    },
    {
      title: 'Contain', sub: 'Stop the spread first',
      text: 'The IR lead follows the ransomware playbook: isolate the server from the network, disable the abused account and revoke its sessions, and block the VPN source address. The goal is to stop the attacker\'s next move, even before the full picture is known.',
      fields: [['Host', 'fs02 isolated'], ['Account', 'svc-helpdesk disabled'], ['Time to contain', '14 minutes']],
      packets: [
        ['ir', 'srv', 'EDR', 'Isolate fs02', 300, 'def'],
        ['ir', 'dc', 'Action', 'Disable svc-helpdesk, revoke tickets and sessions', 300, 'def'],
        ['atk', 'srv', 'RDP', 'Reconnect attempt → no route', 80, 'def'],
      ],
    },
    {
      title: 'Preserve and scope', sub: 'Evidence before cleanup',
      text: 'Before anything is wiped, the team captures memory and disk images and exports the relevant logs. Searching the SIEM for the account and source address shows the attacker came in through the VPN with a stolen password and touched only this server.',
      fields: [['Evidence', 'Memory, disk image, logs (hashed)'], ['Entry point', 'VPN, no MFA on service account'], ['Scope', '1 server, 1 account']],
      packets: [
        ['ir', 'srv', 'EDR', 'Collect memory + triage package', 300, 'req'],
        ['srv', 'ir', 'EDR', 'Evidence package (sha256 recorded)', 4200000, 'data'],
        ['ir', 'siem', 'Query', 'user=svc-helpdesk OR src=203.0.113.0/24, last 30 days', 300, 'req'],
        ['siem', 'ir', 'Results', 'VPN login 01:52, RDP to fs02 only', 9000, 'res'],
      ],
    },
    {
      title: 'Eradicate and recover', sub: 'Clean, restore, watch',
      text: 'The server is rebuilt from a known-good image and its data restored from immutable backups the attacker couldn\'t reach. The service account gets a new password and MFA, and the team watches closely for any return.',
      fields: [['Rebuild', 'Clean image'], ['Data', 'Restored from immutable backup'], ['Hardening', 'MFA on all VPN accounts']],
      packets: [
        ['bk', 'srv', 'Restore', 'Restore fs02 data (snapshot 01:00)', 900000000, 'def'],
        ['ir', 'dc', 'Action', 'New password + MFA for svc-helpdesk', 300, 'def'],
      ],
    },
    {
      title: 'Lessons learned', sub: 'Make it harder next time',
      text: 'A blameless review records the timeline and decisions. Actions: MFA on every VPN account, alerts for service accounts used interactively, and a new detection for shadow-copy deletion that now isolates the host automatically.',
      fields: [['Time to detect', '18 min'], ['Time to contain', '14 min'], ['Follow-ups', '3 fixes, 2 new detections']],
      defend: 'An incident you learn nothing from is likely to happen again. Track follow-up actions until they\'re closed.',
      packets: [
        ['ir', 'siem', 'Rule', 'New: vssadmin delete → auto-isolate host', 400, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'threat-hunting', domain: 'soc', kind: 'defense', level: 'Advanced', severity: 'Process',
  name: 'Threat Hunting', full: 'Finding a hidden C2 beacon with a hypothesis',
  tags: ['threat hunting', 'beaconing', 'c2', 'command and control', 'proxy logs', 'hypothesis', 'soc'],
  summary: 'Threat hunting is going looking for attackers that no alert has caught yet. Hunters start from a hypothesis based on how attackers behave, search the data for it, and turn every confirmed finding into a new automatic detection.',
  facts: [['Approach', 'Hypothesis-driven'], ['Hypothesis here', 'HTTPS C2 beaconing'], ['Technique', 'T1071.001'], ['Data', 'Proxy, DNS, EDR logs'], ['Signals', 'Regular timing, rare domain'], ['Output', 'Incident + new detection']],
  defenses: [
    'Keep enough history (proxy, DNS, EDR) to search weeks back',
    'Base hunts on real attacker techniques from threat intelligence and ATT&CK',
    'Look for rarity and regularity, not just known-bad indicators',
    'Escalate confirmed findings straight into incident response',
    'Turn every successful hunt into a tested detection rule',
  ],
  nodes: [
    { id: 'h', type: 'user', label: 'Threat Hunter', sub: 'SOC', x: 120, y: 245, good: true },
    { id: 'siem', type: 'siem', label: 'SIEM / Data Lake', sub: '90 days of logs', x: 450, y: 100 },
    { id: 'px', type: 'gateway', label: 'Web Proxy', sub: 'egress logs', x: 450, y: 390 },
    { id: 'ws', type: 'workstation', label: 'HR Laptop', sub: 'HR-LT-017', x: 780, y: 390 },
    { id: 'c2', type: 'c2', label: 'cdn-metrics.example', sub: '198.51.100.23', x: 780, y: 100, evil: true },
  ],
  steps: [
    {
      title: 'Form a hypothesis', sub: 'Start from attacker behaviour',
      text: 'Threat intelligence says a group targeting your industry uses implants that "call home" over HTTPS at regular intervals. Hypothesis: if one of our machines is infected, it will contact a rare domain on a steady schedule.',
      fields: [['Hypothesis', 'Regular HTTPS beacons to a rare domain'], ['Technique', 'T1071.001']],
      packets: [
        ['h', 'h', 'Plan', 'Hypothesis + data sources: proxy logs, 30 days', 0, 'ctl'],
      ],
    },
    {
      title: 'Search the data', sub: 'Rare and regular',
      text: 'The hunter groups proxy logs by laptop and destination, keeps destinations seen by very few machines, and measures how evenly spaced the connections are. Human browsing is bursty; an implant on a timer is not.',
      fields: [['Filter', 'Domains seen by ≤ 2 hosts'], ['Measure', 'Interval jitter between requests']],
      packets: [
        ['h', 'siem', 'Query', 'proxy logs → group by host, domain → rarity + interval stats', 600, 'req',
          `proxy
| where time > ago(30d)
| summarize hosts = dcount(src_host) by domain
| where hosts <= 2
| join proxy on domain
| summarize n = count(), avg_gap = avg(gap_s), jitter = stdev(gap_s)
    by src_host, domain
| where n > 500 and jitter < 10
| order by jitter asc`],
        ['siem', 'h', 'Results', '1 match: HR-LT-017 → cdn-metrics.example', 1200, 'res'],
      ],
    },
    {
      title: 'A pattern appears', sub: 'Every 60 seconds, for 3 days',
      text: 'One HR laptop contacts `cdn-metrics.example` every 60 seconds (±4 s), day and night, even when nobody is logged in. The domain was first seen three days ago and no other machine uses it.',
      fields: [['Interval', '60 s ± 4 s'], ['First seen', '3 days ago'], ['Prevalence', '1 host']],
      packets: [
        ['ws', 'px', 'HTTPS', 'CONNECT cdn-metrics.example:443 (every 60 s)', 900, 'atk'],
        ['px', 'c2', 'HTTPS', 'Small request / small response', 1100, 'atk'],
        ['px', 'siem', 'Log', '4,300 entries in 72 h', 2600000, 'ctl'],
      ],
    },
    {
      title: 'Validate on the endpoint', sub: 'Which process is calling out?',
      text: 'Pivoting to endpoint data, the hunter finds the connections come from an unsigned program in the user\'s AppData folder that runs at every logon. That confirms it: this is an implant, and the case is escalated to incident response.',
      fields: [['Process', '%APPDATA%\\updater\\svc.exe (unsigned)'], ['Persistence', 'Run key at logon'], ['Verdict', 'True positive → incident']],
      packets: [
        ['h', 'siem', 'Query', 'EDR network events for HR-LT-017 → cdn-metrics.example', 400, 'req'],
        ['siem', 'h', 'Results', 'svc.exe (unsigned) since 3 days, Run key persistence', 3000, 'res'],
        ['h', 'ws', 'EDR', 'Isolate HR-LT-017, open incident', 300, 'def'],
      ],
    },
    {
      title: 'Hunt becomes detection', sub: 'Never hunt the same thing twice',
      text: 'The domain and file hash are blocked everywhere, and the hunter turns the query into a scheduled SIEM rule that alerts on rare, highly regular outbound connections. Next time, it\'s found automatically.',
      fields: [['Blocked', 'Domain, IP, hash'], ['New rule', 'Rare + regular egress, hourly']],
      defend: 'Document each hunt, even ones that find nothing: they show which blind spots you\'ve already checked.',
      packets: [
        ['h', 'px', 'Action', 'Block cdn-metrics.example', 200, 'def'],
        ['h', 'siem', 'Rule', 'Scheduled detection: beaconing to rare domains', 600, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'soar-playbook', domain: 'soc', kind: 'defense', level: 'Intermediate', severity: 'Control',
  name: 'SOAR Playbook Automation', full: 'Automating triage of a risky sign-in',
  tags: ['soar', 'automation', 'playbook', 'enrichment', 'impossible travel', 'soc', 'case management'],
  summary: 'Security orchestration, automation and response (SOAR) tools run playbooks: the repetitive lookups and first-response actions an analyst would otherwise do by hand. Here a risky sign-in is enriched, scored and contained in seconds, with a human approving the bigger decisions.',
  facts: [['Examples', 'Sentinel playbooks, Splunk SOAR, Cortex XSOAR, Tines'], ['Trigger', 'SIEM alert'], ['Steps', 'Enrich, decide, act, document'], ['Scenario', 'Impossible travel sign-in'], ['Human role', 'Approve high-impact actions'], ['Benefit', 'Faster, consistent response']],
  defenses: [
    'Automate the lookups first; they save the most analyst time',
    'Keep a human approval step for disruptive actions like disabling executives',
    'Log every automated action in the case for audit',
    'Test playbooks regularly so a changed API doesn\'t silently break them',
    'Measure time saved and false-positive rates to tune the logic',
  ],
  nodes: [
    { id: 'siem', type: 'siem', label: 'SIEM', sub: 'alert source', x: 120, y: 245 },
    { id: 'soar', type: 'gateway', label: 'SOAR', sub: 'playbook engine', x: 450, y: 245, good: true },
    { id: 'ti', type: 'cloud', label: 'Threat Intel', sub: 'IP reputation', x: 450, y: 90 },
    { id: 'idp', type: 'idp', label: 'Identity Provider', sub: 'sign-ins', x: 780, y: 120 },
    { id: 'soc', type: 'user', label: 'SOC Analyst', sub: 'approver', x: 780, y: 390, good: true },
  ],
  steps: [
    {
      title: 'Alert triggers playbook', sub: 'Impossible travel',
      text: 'The SIEM raises an alert: user `m.lee` signed in from Toronto, then 20 minutes later from another continent. That\'s physically impossible, but it can also be a VPN. The SOAR playbook starts automatically.',
      fields: [['Alert', 'Impossible travel'], ['User', 'm.lee'], ['Gap', '20 min, 6,000 km']],
      packets: [
        ['siem', 'soar', 'Webhook', 'Alert: impossible travel m.lee (198.51.100.77)', 1200, 'def'],
      ],
    },
    {
      title: 'Enrich', sub: 'The lookups an analyst would do',
      text: 'In parallel, the playbook checks the IP\'s reputation (a known anonymising proxy), asks the identity provider for the session details (no MFA was performed, legacy protocol) and looks at the user\'s usual locations and devices.',
      fields: [['IP reputation', 'Anonymising proxy, high risk'], ['MFA', 'Not performed (legacy auth)'], ['Device', 'Unknown']],
      packets: [
        ['soar', 'ti', 'API', 'Reputation 198.51.100.77?', 200, 'req'],
        ['ti', 'soar', 'API', 'High risk: anonymising proxy', 500, 'res'],
        ['soar', 'idp', 'API', 'Sign-in details for m.lee, last 24 h', 300, 'req'],
        ['idp', 'soar', 'API', 'Legacy auth, no MFA, unknown device', 2400, 'res'],
      ],
    },
    {
      title: 'Decide and act', sub: 'Automatic first response',
      text: 'The combined risk score passes the playbook\'s threshold, so it takes the low-impact actions straight away: revoke the user\'s sessions and require a password reset with MFA at next sign-in.',
      fields: [['Risk score', '92 / 100'], ['Auto actions', 'Revoke sessions, force reset']],
      packets: [
        ['soar', 'idp', 'API', 'Revoke all sessions for m.lee', 260, 'def'],
        ['soar', 'idp', 'API', 'Require password reset + MFA', 260, 'def'],
      ],
    },
    {
      title: 'Human in the loop', sub: 'For the big decisions',
      text: 'Blocking legacy authentication for the whole department would stop the attack path, but could break a business app. The playbook opens a case with all the evidence and asks an analyst to approve. The analyst checks with the app owner, then approves.',
      fields: [['Proposed', 'Block legacy auth for Sales'], ['Approval', 'Analyst + app owner']],
      packets: [
        ['soar', 'soc', 'Case', 'Approve: block legacy auth for Sales group? (evidence attached)', 9000, 'ctl'],
        ['soc', 'soar', 'Case', 'Approved', 200, 'def'],
        ['soar', 'idp', 'API', 'Conditional access: block legacy auth for Sales', 400, 'def'],
      ],
    },
    {
      title: 'Document and measure', sub: 'Every step on the record',
      text: 'Each lookup, decision and action is written to the case automatically. What took an analyst 30 minutes now takes under a minute, and every similar alert is handled the same way.',
      fields: [['Time to contain', '< 1 min (was ~30)'], ['Audit trail', 'Complete']],
      defend: 'Automation amplifies mistakes as well as good decisions. Review playbook outcomes every month.',
      packets: [
        ['soar', 'siem', 'API', 'Close alert: true positive, contained, case #2291', 700, 'def'],
      ],
    },
  ],
});
