/* Domain: Network Security */

SE.register({
  id: 'port-scan', domain: 'network', kind: 'attack', level: 'Beginner', severity: 'Recon',
  name: 'Port Scanning', full: 'TCP SYN "half-open" scan',
  tags: ['nmap', 'recon', 'syn scan', 'reconnaissance', 'ports'],
  summary: 'Before attacking, adversaries map which services are listening. A SYN scan sends the first packet of the TCP handshake and reads the reply. SYN-ACK means open, RST means closed, and silence means filtered. It never completes the handshake.',
  facts: [['Phase', 'Reconnaissance'], ['ATT&CK', 'T1046'], ['Classic tool', 'Nmap (-sS)'], ['Open', 'SYN → SYN/ACK'], ['Closed', 'SYN → RST'], ['Filtered', 'SYN → (nothing)']],
  defenses: [
    'Default-deny firewall: expose only the ports you need',
    'Turn off unused services; inventory what is listening',
    'IDS rules for scan patterns, plus alerting',
    "Hide version banners where possible",
    'Scan yourself regularly so you see what attackers see',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Scanner', sub: '203.0.113.66', x: 140, y: 245 },
    { id: 'tgt', type: 'server', label: 'Target Host', sub: '198.51.100.20', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Host discovery', sub: 'Is anyone home?',
      text: 'First the scanner checks whether the host is up, using an ICMP echo (ping) and a probe to a common port.',
      fields: [['Probe', 'ICMP echo + TCP 443'], ['Result', 'Host is up']],
      packets: [
        ['atk', 'tgt', 'ICMP', 'Echo (ping) request id=0x1f2e', 42, 'ctl'],
        ['tgt', 'atk', 'ICMP', 'Echo (ping) reply id=0x1f2e', 42, 'res'],
      ],
    },
    {
      title: 'Open port', sub: 'SYN → SYN/ACK → RST',
      text: 'The scanner sends a SYN to port 22. The target replies SYN/ACK, so a service is listening. Instead of completing the handshake, the scanner sends RST. The connection never fully opens, which is why this is called a half-open scan.',
      fields: [['Port', '22/tcp'], ['State', 'open']],
      packets: [
        ['atk', 'tgt', 'TCP', '51000 → 22 [SYN] Seq=0', 58, 'ctl'],
        ['tgt', 'atk', 'TCP', '22 → 51000 [SYN, ACK] Seq=0 Ack=1', 58, 'res'],
        ['atk', 'tgt', 'TCP', '51000 → 22 [RST] Seq=1', 54, 'ctl'],
      ],
    },
    {
      title: 'Closed port', sub: 'SYN → RST',
      text: 'On port 23 the host answers RST/ACK: reachable, but nothing listening.',
      fields: [['Port', '23/tcp'], ['State', 'closed']],
      packets: [
        ['atk', 'tgt', 'TCP', '51000 → 23 [SYN] Seq=0', 58, 'ctl'],
        ['tgt', 'atk', 'TCP', '23 → 51000 [RST, ACK]', 54, 'res'],
      ],
    },
    {
      title: 'Filtered port', sub: 'Silence',
      text: 'A firewall silently drops probes to port 3389. The scanner retries, gets nothing, and marks the port as filtered.',
      fields: [['Port', '3389/tcp'], ['State', 'filtered']],
      packets: [
        ['atk', 'tgt', 'TCP', '51000 → 3389 [SYN] Seq=0', 58, 'ctl'],
        ['atk', 'tgt', 'TCP', '51000 → 3389 [SYN] Seq=0 (retransmission)', 58, 'ctl'],
      ],
    },
    {
      title: 'Service detection', sub: 'What exactly is running?',
      text: 'For open ports, the scanner connects fully and reads the banner. A version string lets the attacker look up known vulnerabilities (CVEs) for that exact build.',
      fields: [['Banner', 'SSH-2.0-OpenSSH_8.2p1 Ubuntu'], ['Next', 'Look up CVEs for this version']],
      defend: 'Patch quickly. Your exposed versions are visible to everyone on the internet, all the time.',
      packets: [
        ['atk', 'tgt', 'TCP', '51001 → 22 [SYN] / [SYN,ACK] / [ACK]', 174, 'ctl'],
        ['tgt', 'atk', 'SSH', 'Server banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5', 95, 'data'],
      ],
    },
  ],
});

SE.register({
  id: 'arp-spoof', domain: 'network', kind: 'attack', level: 'Intermediate', severity: 'High',
  name: 'ARP Spoofing', full: 'Man-in-the-middle on the local network',
  tags: ['arp', 'mitm', 'poisoning', 'lan', 'layer 2'],
  summary: 'ARP maps IP addresses to MAC addresses on a local network, and it trusts every reply it gets. An attacker on the same LAN sends fake ARP replies saying they are the gateway, so the victim\'s traffic flows through the attacker.',
  facts: [['OSI layer', 'Layer 2 (Data link)'], ['ATT&CK', 'T1557.002'], ['Requires', 'Same broadcast domain'], ['Impact', 'Sniffing, tampering, session theft'], ['Why it works', 'ARP has no authentication'], ['Switch defense', 'Dynamic ARP Inspection']],
  defenses: [
    'Enable Dynamic ARP Inspection (DAI) + DHCP snooping on switches',
    'Encrypt everything (TLS/HTTPS, HSTS), so intercepted traffic stays unreadable',
    'Segment networks; isolate guests and IoT',
    'Detect ARP anomalies (e.g. arpwatch, IDS rules)',
  ],
  nodes: [
    { id: 'vic', type: 'client', label: 'Victim', sub: '192.168.1.10', x: 130, y: 330 },
    { id: 'sw', type: 'switch', label: 'Switch', sub: 'access layer', x: 450, y: 330 },
    { id: 'gw', type: 'router', label: 'Gateway', sub: '192.168.1.1', x: 780, y: 330 },
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: '192.168.1.66', x: 450, y: 110 },
  ],
  steps: [
    {
      title: 'Normal ARP', sub: 'Who has 192.168.1.1?',
      text: 'To reach the internet, the victim needs the gateway\'s MAC address. It broadcasts an ARP request and the gateway answers. The result goes into the victim\'s ARP cache.',
      fields: [['Gateway MAC', 'aa:aa:aa:00:00:01'], ['Cache', '192.168.1.1 → aa:aa:…:01']],
      packets: [
        ['vic', 'sw', 'ARP', 'Who has 192.168.1.1? Tell 192.168.1.10 (broadcast)', 42, 'ctl'],
        ['gw', 'vic', 'ARP', '192.168.1.1 is at aa:aa:aa:00:00:01', 42, 'res'],
      ],
    },
    {
      title: 'Poisoning', sub: 'Unsolicited lies',
      text: 'The attacker keeps sending unsolicited ARP replies. It tells the victim "the gateway is at my MAC" and tells the gateway "the victim is at my MAC". Both overwrite their caches.',
      fields: [['Victim cache', '192.168.1.1 → ee:ee:…:66 ✗'], ['Gateway cache', '192.168.1.10 → ee:ee:…:66 ✗']],
      packets: [
        ['atk', 'vic', 'ARP', '192.168.1.1 is at ee:ee:ee:66:66:66 (spoofed reply)', 42, 'atk'],
        ['atk', 'gw', 'ARP', '192.168.1.10 is at ee:ee:ee:66:66:66 (spoofed reply)', 42, 'atk'],
      ],
    },
    {
      title: 'Traffic through the attacker', sub: 'Invisible relay',
      text: 'Now the victim\'s frames go to the attacker. The attacker forwards them so nothing seems broken, while reading or changing anything that isn\'t encrypted, such as a plain-HTTP login.',
      fields: [['Captured', 'user=alice&pass=…'], ['Victim notices?', 'No']],
      packets: [
        ['vic', 'atk', 'HTTP', 'POST /login user=alice&pass=Winter2024 (plaintext)', 610, 'data'],
        ['atk', 'gw', 'HTTP', 'POST /login (forwarded)', 610, 'atk'],
        ['gw', 'atk', 'HTTP', '302 Found Set-Cookie: sid=…', 420, 'res'],
        ['atk', 'vic', 'HTTP', '302 Found (forwarded, cookie copied)', 420, 'atk'],
      ],
    },
    {
      title: 'Defense: DAI', sub: 'The switch checks ARP',
      text: 'With Dynamic ARP Inspection the switch compares each ARP reply with its DHCP snooping table. A reply that claims 192.168.1.1 from the wrong port and MAC is dropped. With HTTPS everywhere, intercepted traffic would be unreadable anyway.',
      fields: [['Binding', '192.168.1.1 ↔ aa:aa:…:01 (port 24)'], ['Action', 'Drop + log']],
      defend: 'Always encrypt. Layer-2 defenses are often missing on café, hotel and home networks.',
      packets: [
        ['atk', 'sw', 'ARP', '192.168.1.1 is at ee:ee:ee:66:66:66 (spoofed)', 42, 'atk'],
        ['sw', 'atk', 'DAI', 'Dropped — no DHCP binding match, port err-disabled', 0, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'dns-spoof', domain: 'network', kind: 'attack', level: 'Advanced', severity: 'High',
  name: 'DNS Cache Poisoning', full: 'Forging answers into a resolver cache',
  tags: ['dns', 'kaminsky', 'poisoning', 'dnssec', 'spoofing'],
  summary: 'DNS mostly runs over UDP and a resolver accepts the first matching answer. If an attacker can forge a reply, with the right transaction ID and port, before the real one arrives, the resolver caches a fake address and sends every user to the attacker\'s server.',
  facts: [['Protocol', 'DNS over UDP/53'], ['ATT&CK', 'T1557'], ['Famous variant', 'Kaminsky attack (2008)'], ['Guess space', '16-bit TXID × source port'], ['Impact', 'Mass redirection, phishing'], ['Strong fix', 'DNSSEC validation']],
  defenses: [
    'Source-port randomization plus random transaction IDs',
    'DNSSEC signing and validation',
    'Encrypted DNS to trusted resolvers (DoH/DoT)',
    'HTTPS and HSTS, so a spoofed IP fails certificate checks',
  ],
  nodes: [
    { id: 'vic', type: 'client', label: 'Users', sub: '192.168.1.0/24', x: 120, y: 245 },
    { id: 'res', type: 'dns', label: 'Resolver', sub: '10.0.0.53', x: 450, y: 245 },
    { id: 'auth', type: 'dns', label: 'Authoritative NS', sub: 'ns1.bank.example', x: 780, y: 110 },
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: '203.0.113.66', x: 780, y: 385 },
  ],
  steps: [
    {
      title: 'Normal lookup', sub: 'Resolver asks the authority',
      text: 'A user asks for `bank.example`. The resolver asks the authoritative server, matches the reply by transaction ID and port, caches it, and answers the user.',
      fields: [['TXID', '0x1a2b'], ['Answer', '198.51.100.7 (TTL 300)']],
      packets: [
        ['vic', 'res', 'DNS', 'Standard query A bank.example', 72, 'req'],
        ['res', 'auth', 'DNS', 'Query A bank.example (TXID 0x1a2b, sport 53124)', 72, 'req'],
        ['auth', 'res', 'DNS', 'Response A 198.51.100.7', 88, 'res'],
        ['res', 'vic', 'DNS', 'Response A 198.51.100.7', 88, 'res'],
      ],
    },
    {
      title: 'The race', sub: 'Flood of forged answers',
      text: 'When the cache entry expires, the resolver asks again. At that moment the attacker floods it with forged answers that guess the transaction ID (and port). Only one guess needs to match before the real answer arrives.',
      fields: [['Real TXID', '0x4c11 (secret)'], ['Forged', 'Thousands of guesses']],
      packets: [
        ['vic', 'res', 'DNS', 'Standard query A bank.example', 72, 'req'],
        ['res', 'auth', 'DNS', 'Query A bank.example (TXID 0x4c11)', 72, 'req'],
        ['atk', 'res', 'DNS', 'Forged response A 203.0.113.66 (TXID 0x0000…0xffff)', 88000, 'atk'],
        ['auth', 'res', 'DNS', 'Response A 198.51.100.7 (too late, ignored)', 88, 'res'],
      ],
    },
    {
      title: 'Poisoned cache', sub: 'Every user gets the fake IP',
      text: 'A forged answer matched first. The resolver caches the attacker\'s IP with a long TTL and hands it to every user who asks.',
      fields: [['Cached', 'bank.example → 203.0.113.66'], ['TTL', '86400 s']],
      packets: [
        ['res', 'res', 'Cache', 'bank.example → 203.0.113.66 (TTL 86400)', 0, 'atk'],
        ['res', 'vic', 'DNS', 'Response A 203.0.113.66', 88, 'atk'],
      ],
    },
    {
      title: 'Users redirected', sub: 'Fake bank, real URL bar',
      text: 'Browsers connect to the attacker\'s server while showing `bank.example`. Over plain HTTP the clone looks perfect. Over HTTPS the attacker has no valid certificate, so the browser shows a warning, which is why TLS matters.',
      fields: [['HTTP', 'Silent compromise'], ['HTTPS', 'Certificate error']],
      packets: [
        ['vic', 'atk', 'HTTP', 'GET / Host: bank.example', 420, 'atk'],
        ['atk', 'vic', 'HTTP', '200 OK (cloned login page)', 12400, 'atk'],
      ],
    },
    {
      title: 'Defense: DNSSEC', sub: 'Signed answers',
      text: 'With DNSSEC the authoritative zone signs its records. A validating resolver checks the RRSIG signature and throws away the forged, unsigned answer, however fast it arrived.',
      fields: [['Record', 'A + RRSIG'], ['Forged answer', 'Bogus → discarded']],
      defend: 'Also use randomized source ports. They make blind guessing about 65,000× harder.',
      packets: [
        ['atk', 'res', 'DNS', 'Forged response A 203.0.113.66 (no valid RRSIG)', 88, 'atk'],
        ['auth', 'res', 'DNS', 'Response A 198.51.100.7 + RRSIG', 310, 'res'],
        ['res', 'res', 'DNSSEC', 'Signature verified; forged answer discarded', 0, 'def'],
        ['res', 'vic', 'DNS', 'Response A 198.51.100.7 (AD flag set)', 88, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'syn-flood', domain: 'network', kind: 'attack', level: 'Intermediate', severity: 'High',
  name: 'SYN Flood', full: 'Denial of service via half-open connections',
  tags: ['dos', 'ddos', 'syn cookies', 'availability', 'tcp'],
  summary: 'A SYN flood sends huge numbers of connection requests (SYNs) from spoofed addresses and never finishes the handshake. The server keeps state for each half-open connection until its queue fills, and then real users can\'t connect.',
  facts: [['Target', 'Availability'], ['ATT&CK', 'T1499.001'], ['CWE', 'CWE-400'], ['Layer', 'Transport (TCP)'], ['Classic fix', 'SYN cookies'], ['At scale', 'DDoS scrubbing / CDN']],
  defenses: [
    'Enable SYN cookies (stateless handshake when the queue is full)',
    'Rate-limit SYNs per source at the edge',
    'Put services behind a CDN / DDoS scrubbing provider',
    'Ask your ISP for upstream filtering and anti-spoofing (BCP 38)',
  ],
  nodes: [
    { id: 'bot', type: 'attacker', label: 'Botnet', sub: 'spoofed sources', x: 130, y: 110 },
    { id: 'usr', type: 'client', label: 'Real User', sub: '192.0.2.44', x: 130, y: 385 },
    { id: 'srv', type: 'server', label: 'Web Server', sub: 'backlog = 1024', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Normal handshake', sub: 'SYN, SYN-ACK, ACK',
      text: 'A real user connects with the three-way handshake. Between SYN and ACK the server holds a small record in its backlog queue.',
      fields: [['Backlog', '1 / 1024'], ['State', 'ESTABLISHED']],
      packets: [
        ['usr', 'srv', 'TCP', '50122 → 443 [SYN]', 66, 'ctl'],
        ['srv', 'usr', 'TCP', '443 → 50122 [SYN, ACK]', 66, 'ctl'],
        ['usr', 'srv', 'TCP', '50122 → 443 [ACK]', 54, 'ctl'],
      ],
    },
    {
      title: 'The flood', sub: 'Millions of half-open connections',
      text: 'Bots send SYNs with random fake source IPs. The server replies SYN-ACK to addresses that never answer, and keeps a slot for each until it times out.',
      fields: [['Rate', '~500,000 SYN/s'], ['Backlog', '1024 / 1024 (full)']],
      packets: [
        ['bot', 'srv', 'TCP', '[SYN] src=random spoofed × 500k/s', 33000000, 'atk'],
        ['srv', 'bot', 'TCP', '[SYN, ACK] → spoofed addresses (never answered)', 33000000, 'ctl'],
        ['srv', 'srv', 'Kernel', 'SYN backlog full: 1024 half-open', 0, 'atk'],
      ],
    },
    {
      title: 'Real users denied', sub: 'No room left',
      text: 'The real user\'s SYN finds no free slot and is dropped. Their browser retries, then shows a timeout. The service is down without a single byte of application traffic.',
      fields: [['User sees', 'ERR_CONNECTION_TIMED_OUT'], ['Server CPU', 'Fine, queue exhausted']],
      packets: [
        ['usr', 'srv', 'TCP', '50140 → 443 [SYN] (dropped)', 66, 'req'],
        ['usr', 'srv', 'TCP', '50140 → 443 [SYN] (retransmission, dropped)', 66, 'req'],
      ],
    },
    {
      title: 'Defense: SYN cookies', sub: 'Stateless handshake',
      text: 'With SYN cookies, the server stores nothing for a SYN. It encodes the connection info in the SYN-ACK\'s sequence number. Only a client that answers with a matching ACK gets a real slot. Spoofed sources never answer, so they cost nothing.',
      fields: [['State per SYN', '0 bytes'], ['Real user', 'Connects normally']],
      defend: 'Big volumetric floods can still fill your bandwidth. Absorb those upstream with a CDN or scrubbing service.',
      packets: [
        ['bot', 'srv', 'TCP', '[SYN] spoofed × 500k/s', 33000000, 'atk'],
        ['srv', 'bot', 'TCP', '[SYN, ACK] seq = cookie (no state kept)', 33000000, 'def'],
        ['usr', 'srv', 'TCP', '50141 → 443 [SYN]', 66, 'ctl'],
        ['srv', 'usr', 'TCP', '[SYN, ACK] seq = cookie', 66, 'def'],
        ['usr', 'srv', 'TCP', '[ACK] cookie valid → connection created', 54, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'evil-twin', domain: 'network', kind: 'attack', level: 'Intermediate', severity: 'High',
  name: 'Evil Twin Wi-Fi', full: 'Rogue access point impersonation',
  tags: ['wifi', 'rogue ap', 'deauth', 'wireless', 'captive portal'],
  summary: 'An evil twin is a fake Wi-Fi access point with the same name (SSID) as a real one. The attacker knocks victims off the real network and lures them onto the fake one, then watches their traffic or serves a phishing "login" portal.',
  facts: [['Medium', '802.11 Wi-Fi'], ['ATT&CK', 'T1557'], ['Common places', 'Cafés, airports, hotels'], ['Key trick', 'Deauthentication frames'], ['Mitigation', '802.11w (PMF), WPA3'], ['Detection', 'Wireless IDS']],
  defenses: [
    'WPA3 / 802.11w Protected Management Frames block forged deauth',
    'WPA2/3-Enterprise with strict server-certificate validation',
    'Use a VPN on untrusted networks; HTTPS everywhere',
    'Wireless IDS to spot rogue APs that copy your SSID',
    'Set devices not to auto-join open networks',
  ],
  nodes: [
    { id: 'vic', type: 'phone', label: 'Victim Phone', sub: 'auto-joins "CafeWiFi"', x: 130, y: 245 },
    { id: 'ap', type: 'wifi', label: 'Real AP', sub: 'CafeWiFi ch 6', x: 470, y: 100 },
    { id: 'twin', type: 'wifi', label: 'Evil Twin', sub: 'CafeWiFi ch 11', x: 470, y: 390, evil: true },
    { id: 'inet', type: 'cloud', label: 'Internet', sub: '', x: 790, y: 245 },
  ],
  steps: [
    {
      title: 'Normal connection', sub: 'Joining the café Wi-Fi',
      text: 'The phone associates with the real access point and uses it to reach the internet.',
      fields: [['SSID', 'CafeWiFi'], ['BSSID', '00:11:22:33:44:55']],
      packets: [
        ['vic', 'ap', '802.11', 'Probe Request SSID=CafeWiFi', 90, 'ctl'],
        ['ap', 'vic', '802.11', 'Probe Response SSID=CafeWiFi', 260, 'ctl'],
        ['vic', 'ap', '802.11', 'Association Request', 120, 'ctl'],
        ['ap', 'inet', 'IP', 'User traffic (normal)', 1500, 'req'],
      ],
    },
    {
      title: 'Deauth attack', sub: 'Kicked off the real AP',
      text: 'Without Protected Management Frames, deauthentication frames aren\'t authenticated. The attacker forges them with the real AP\'s address and the phone disconnects.',
      fields: [['Spoofed source', '00:11:22:33:44:55'], ['Reason code', '7 (class 3 frame)']],
      packets: [
        ['twin', 'vic', '802.11', 'Deauthentication (spoofed from real AP) × 64', 1700, 'atk'],
      ],
    },
    {
      title: 'Joining the twin', sub: 'Same name, stronger signal',
      text: 'The phone looks for "CafeWiFi" again. The evil twin has the same SSID and a stronger signal, so the phone joins it automatically.',
      fields: [['SSID', 'CafeWiFi (identical)'], ['Signal', '-38 dBm vs -71 dBm']],
      packets: [
        ['twin', 'vic', '802.11', 'Beacon SSID=CafeWiFi (strong)', 260, 'atk'],
        ['vic', 'twin', '802.11', 'Association Request', 120, 'ctl'],
        ['twin', 'vic', '802.11', 'Association Response — success', 140, 'atk'],
      ],
    },
    {
      title: 'Interception & phishing', sub: 'Attacker sits in the middle',
      text: 'All traffic now passes through the attacker. They forward it to the internet and also show a fake captive portal asking the user to "sign in with your email account".',
      fields: [['Portal', 'Fake "sign in to continue"'], ['Captured', 'Email + password']],
      packets: [
        ['vic', 'twin', 'DNS/HTTP', 'All traffic routed via attacker', 4200, 'data'],
        ['twin', 'vic', 'HTTP', '302 → fake captive portal', 9800, 'atk'],
        ['vic', 'twin', 'HTTP', 'POST /portal email=…&password=…', 520, 'data'],
        ['twin', 'inet', 'IP', 'Forwarded traffic (looks normal to the user)', 4200, 'atk'],
      ],
    },
    {
      title: 'Defense: PMF + WPA3', sub: 'Forged frames ignored',
      text: 'With 802.11w (required by WPA3) management frames are protected, so the phone ignores the forged deauth and stays on the real AP. Enterprise Wi-Fi with certificate validation would also expose the fake network.',
      fields: [['PMF', 'Required'], ['Deauth', 'Ignored (no valid MIC)']],
      defend: 'Treat public Wi-Fi as hostile: use a VPN, and never type credentials into Wi-Fi portals.',
      packets: [
        ['twin', 'vic', '802.11', 'Deauthentication (spoofed)', 26, 'atk'],
        ['vic', 'vic', '802.11w', 'Unprotected deauth ignored; stays connected', 0, 'def'],
        ['vic', 'ap', '802.11', 'Traffic continues on real AP', 1500, 'def'],
      ],
    },
  ],
});
