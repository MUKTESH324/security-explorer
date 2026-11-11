/* Domain: Internet Protocols, application protocols */

SE.register({
  id: 'smtp', domain: 'protocols', kind: 'protocol', level: 'Intermediate', severity: 'Protocol',
  name: 'SMTP', full: 'How an email gets delivered',
  tags: ['smtp', 'email', 'mx', 'spf', 'dkim', 'dmarc', 'starttls', 'mail'],
  summary: 'Sending an email takes two SMTP hops. Your mail app hands the message to your provider\'s server, which looks up the recipient domain\'s MX record and passes it to their server. The receiving side checks SPF, DKIM and DMARC to decide whether to trust it.',
  facts: [['Defined in', 'RFC 5321'], ['Ports', '587 submission · 25 server-to-server'], ['Encryption', 'STARTTLS / implicit TLS (465)'], ['Routing', 'MX records in DNS'], ['Sender checks', 'SPF, DKIM, DMARC'], ['Related', 'RFC 7208, RFC 6376, RFC 7489']],
  defenses: [
    'Publish SPF, sign with DKIM and enforce DMARC (p=quarantine or reject)',
    'Require authentication and TLS on the submission port',
    'Never run an open relay',
    'Use MTA-STS so other servers must use TLS when sending to you',
  ],
  nodes: [
    { id: 'app', type: 'client', label: 'Mail App', sub: 'alice@corp.example', x: 110, y: 245 },
    { id: 'sub', type: 'mail', label: 'Sending Server', sub: 'smtp.corp.example', x: 380, y: 245 },
    { id: 'dns', type: 'dns', label: 'DNS', sub: 'MX / SPF / DKIM', x: 600, y: 90 },
    { id: 'mx', type: 'mail', label: 'Receiving Server', sub: 'mx.partner.example', x: 800, y: 245 },
    { id: 'box', type: 'user', label: "Bob's Mailbox", sub: 'bob@partner.example', x: 640, y: 400 },
  ],
  steps: [
    {
      title: 'Submission', sub: 'Mail app to your provider',
      text: 'The mail app connects to port 587, upgrades to TLS with `STARTTLS`, logs in, and hands over the message.',
      fields: [['Port', '587 + STARTTLS'], ['Auth', 'Required']],
      packets: [
        ['app', 'sub', 'SMTP', 'EHLO laptop · STARTTLS · AUTH · MAIL FROM · RCPT TO · DATA', 4200, 'req',
          `S: 220 smtp.corp.example ESMTP
C: EHLO laptop
S: 250-STARTTLS
C: STARTTLS
   (TLS handshake, everything below is encrypted)
C: AUTH PLAIN ****
S: 235 Authentication successful
C: MAIL FROM:<alice@corp.example>
C: RCPT TO:<bob@partner.example>
C: DATA
   Subject: Q3 report …
C: .
S: 250 OK queued as 7C1F2A`],
        ['sub', 'app', 'SMTP', '250 OK: queued as 7C1F2A', 60, 'res'],
      ],
    },
    {
      title: 'Find the destination', sub: 'MX lookup',
      text: 'The sending server asks DNS for the MX record of `partner.example`, which names the server that accepts its mail. It also signs the message with DKIM.',
      fields: [['MX', '10 mx.partner.example'], ['DKIM', 'Signature added (selector s1)']],
      packets: [
        ['sub', 'dns', 'DNS', 'Query MX partner.example', 76, 'req'],
        ['dns', 'sub', 'DNS', 'Response MX 10 mx.partner.example', 110, 'res'],
      ],
    },
    {
      title: 'Server to server', sub: 'Port 25 relay',
      text: 'The sending server connects to the receiving server on port 25, upgrades to TLS, and transfers the message.',
      fields: [['Port', '25 + STARTTLS'], ['From IP', '192.0.2.25']],
      packets: [
        ['sub', 'mx', 'SMTP', 'EHLO smtp.corp.example · STARTTLS · MAIL FROM · RCPT TO · DATA', 4400, 'req'],
        ['mx', 'sub', 'SMTP', '250 2.0.0 OK accepted', 60, 'res'],
      ],
    },
    {
      title: 'Trust checks', sub: 'SPF, DKIM, DMARC',
      text: 'Before delivering, the receiver checks DNS: is this IP allowed to send for `corp.example` (SPF)? Is the DKIM signature valid? Does the sender\'s DMARC policy pass? All pass, so the message goes to the inbox.',
      fields: [['SPF', 'pass'], ['DKIM', 'pass (d=corp.example)'], ['DMARC', 'pass']],
      defend: 'Without SPF, DKIM and an enforced DMARC policy, anyone can send mail that claims to come from your domain.',
      packets: [
        ['mx', 'dns', 'DNS', 'TXT corp.example (SPF) · s1._domainkey (DKIM) · _dmarc (DMARC)', 220, 'req'],
        ['dns', 'mx', 'DNS', 'v=spf1 ip4:192.0.2.0/24 -all · DKIM key · p=reject', 640, 'res'],
        ['mx', 'mx', 'Policy', 'SPF pass · DKIM pass · DMARC pass', 0, 'def'],
        ['mx', 'box', 'Local', 'Delivered to inbox', 4400, 'res'],
      ],
    },
  ],
});

SE.register({
  id: 'imap', domain: 'protocols', kind: 'protocol', level: 'Beginner', severity: 'Protocol',
  name: 'IMAP', full: 'Reading mail that stays on the server',
  tags: ['imap', 'email', 'mailbox', 'idle', 'pop3'],
  summary: 'IMAP lets mail apps read and organise a mailbox that lives on the server, so your phone and laptop stay in sync. The app logs in, opens a folder, fetches what it needs, and waits for new mail with IDLE.',
  facts: [['Defined in', 'RFC 9051'], ['Port', '993 (implicit TLS)'], ['Model', 'Mail stays on the server'], ['Push', 'IDLE command'], ['Older alternative', 'POP3 (download and delete)'], ['Auth', 'OAuth 2.0 or password']],
  defenses: [
    'Use port 993 with TLS only; disable plain-text 143',
    'Prefer OAuth 2.0 with MFA over stored passwords',
    'Disable legacy protocols (POP3, basic auth) you don\'t need',
    'Alert on logins from new countries or IMAP clients',
  ],
  nodes: [
    { id: 'c', type: 'phone', label: 'Phone Mail App', sub: 'bob@partner.example', x: 140, y: 245 },
    { id: 's', type: 'mail', label: 'IMAP Server', sub: 'imap.partner.example:993', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Connect and log in', sub: 'Over TLS from the start',
      text: 'The app opens a TLS connection on port 993 and authenticates, here with an OAuth token rather than a password.',
      fields: [['Port', '993 (TLS)'], ['Auth', 'XOAUTH2']],
      packets: [
        ['c', 's', 'TLS', 'TCP + TLS handshake', 3600, 'ctl'],
        ['s', 'c', 'IMAP', '* OK IMAP4rev2 server ready', 60, 'res'],
        ['c', 's', 'IMAP', 'a1 AUTHENTICATE XOAUTH2 ****', 900, 'req'],
        ['s', 'c', 'IMAP', 'a1 OK authenticated', 40, 'res'],
      ],
    },
    {
      title: 'Open the inbox', sub: 'What\'s new?',
      text: 'The app selects the inbox and learns how many messages exist and which are unseen.',
      fields: [['Folder', 'INBOX'], ['Unseen', '3']],
      packets: [
        ['c', 's', 'IMAP', 'a2 SELECT INBOX', 30, 'req'],
        ['s', 'c', 'IMAP', '* 214 EXISTS · * OK [UNSEEN 212] · a2 OK', 180, 'res'],
      ],
    },
    {
      title: 'Fetch headers, then a message', sub: 'Only what\'s needed',
      text: 'It fetches headers for the new messages to build the list, then downloads the full body only when you open one.',
      fields: [['List', 'FETCH 212:214 (ENVELOPE FLAGS)'], ['Open', 'FETCH 214 BODY[]']],
      packets: [
        ['c', 's', 'IMAP', 'a3 FETCH 212:214 (FLAGS ENVELOPE)', 50, 'req'],
        ['s', 'c', 'IMAP', '3 envelopes (from, subject, date)', 1400, 'res'],
        ['c', 's', 'IMAP', 'a4 FETCH 214 BODY[]', 30, 'req'],
        ['s', 'c', 'IMAP', 'Message 214 (18 KB)', 18400, 'res'],
      ],
    },
    {
      title: 'Wait for new mail', sub: 'IDLE',
      text: 'Instead of polling, the app sends IDLE and the server pushes a notice the moment new mail arrives.',
      fields: [['Command', 'IDLE'], ['Push', '* 215 EXISTS']],
      defend: 'Mailboxes are high-value targets. Legacy IMAP with basic passwords bypasses MFA, which is why providers are turning it off.',
      packets: [
        ['c', 's', 'IMAP', 'a5 IDLE', 20, 'req'],
        ['s', 'c', 'IMAP', '* 215 EXISTS (new mail)', 30, 'res'],
      ],
    },
  ],
});

SE.register({
  id: 'ssh', domain: 'protocols', kind: 'protocol', level: 'Intermediate', severity: 'Protocol',
  name: 'SSH', full: 'Secure Shell',
  tags: ['ssh', 'remote shell', 'public key', 'host key', 'kex', 'openssh'],
  summary: 'SSH gives you an encrypted remote terminal. Both sides agree on keys, the server proves its identity with a host key, you prove yours (ideally with a key pair, not a password), and then everything you type travels encrypted.',
  facts: [['Defined in', 'RFC 4253'], ['Port', '22'], ['Key exchange', 'curve25519 / sntrup761 hybrid'], ['Server identity', 'Host key (fingerprint)'], ['User auth', 'Public key, password, certificates'], ['Common uses', 'Shell, SFTP, port forwarding, Git']],
  defenses: [
    'Use key-based auth and disable password login',
    'Verify the host key fingerprint the first time you connect',
    'Disable root login; use sudo with individual accounts',
    'Restrict who can reach port 22 (VPN, bastion, allow-list)',
    'Consider SSH certificates for large fleets',
  ],
  nodes: [
    { id: 'c', type: 'client', label: 'Your Laptop', sub: 'ssh client', x: 140, y: 245 },
    { id: 's', type: 'server', label: 'Linux Server', sub: 'sshd :22', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Version and algorithms', sub: 'Agreeing on how to talk',
      text: 'After the TCP handshake, both sides send a version string, then lists of the key-exchange, cipher and MAC algorithms they support. They pick the best ones in common.',
      fields: [['Server', 'SSH-2.0-OpenSSH_9.8'], ['Chosen cipher', 'chacha20-poly1305']],
      packets: [
        ['s', 'c', 'SSH', 'SSH-2.0-OpenSSH_9.8', 41, 'ctl'],
        ['c', 's', 'SSH', 'SSH-2.0-OpenSSH_9.8', 41, 'ctl'],
        ['c', 's', 'SSH', 'KEXINIT (algorithm lists)', 1500, 'ctl'],
        ['s', 'c', 'SSH', 'KEXINIT (algorithm lists)', 1100, 'ctl'],
      ],
    },
    {
      title: 'Key exchange', sub: 'A shared secret + server proof',
      text: 'An elliptic-curve Diffie-Hellman exchange creates session keys. The server signs the exchange with its host key, proving it is the machine you expect.',
      fields: [['KEX', 'curve25519-sha256'], ['Host key', 'ED25519 SHA256:nThbg6kXUpJ…']],
      packets: [
        ['c', 's', 'SSH', 'KEX_ECDH_INIT (client public key)', 80, 'ctl'],
        ['s', 'c', 'SSH', 'KEX_ECDH_REPLY (server public key + host key + signature)', 300, 'ctl'],
        ['c', 'c', 'Local', 'Compare host key with known_hosts', 0, 'def'],
        ['c', 's', 'SSH', 'NEWKEYS (encryption on)', 16, 'ctl'],
      ],
    },
    {
      title: 'User authentication', sub: 'Prove who you are',
      text: 'The client offers your public key and signs a challenge with the private key, which never leaves your laptop. The server checks it against `authorized_keys`.',
      fields: [['Method', 'publickey (ed25519)'], ['Result', 'Accepted']],
      packets: [
        ['c', 's', 'SSH', 'USERAUTH_REQUEST publickey (signed)', 420, 'req'],
        ['s', 'c', 'SSH', 'USERAUTH_SUCCESS', 16, 'res'],
      ],
    },
    {
      title: 'Encrypted session', sub: 'Your shell',
      text: 'A channel opens and you get a shell. Every keystroke and every line of output is encrypted and integrity-protected.',
      fields: [['Channel', 'session + pty'], ['Traffic', 'Encrypted both ways']],
      defend: 'If SSH warns that a host key changed, stop. It can mean a rebuilt server, or someone in the middle.',
      packets: [
        ['c', 's', 'SSH', 'CHANNEL_OPEN session · pty-req · shell', 200, 'req'],
        ['s', 'c', 'SSH', 'Encrypted data (prompt: user@server:~$)', 120, 'res'],
        ['c', 's', 'SSH', 'Encrypted data (keystrokes)', 90, 'req'],
      ],
    },
  ],
});

SE.register({
  id: 'ftp', domain: 'protocols', kind: 'protocol', level: 'Beginner', severity: 'Legacy',
  name: 'FTP', full: 'File Transfer Protocol',
  tags: ['ftp', 'file transfer', 'passive mode', 'sftp', 'ftps', 'legacy'],
  summary: 'FTP is one of the internet\'s oldest protocols. It uses one connection for commands and a separate one for each file. Everything, including the password, travels in plain text, which is why SFTP or FTPS have replaced it.',
  facts: [['Defined in', 'RFC 959'], ['Ports', '21 control + separate data port'], ['Modes', 'Active / Passive (PASV)'], ['Encryption', 'None'], ['Secure replacements', 'SFTP (over SSH), FTPS'], ['Status', 'Legacy']],
  defenses: [
    'Replace FTP with SFTP or HTTPS uploads',
    'If FTP must stay, use FTPS and disable anonymous login',
    'Never reuse FTP passwords elsewhere; assume they\'ve been seen',
    'Restrict FTP to specific source addresses',
  ],
  nodes: [
    { id: 'c', type: 'client', label: 'FTP Client', sub: '192.168.1.42', x: 140, y: 245 },
    { id: 'eve', type: 'ids', label: 'Anyone on the path', sub: 'café Wi-Fi, ISP', x: 450, y: 410, evil: true },
    { id: 's', type: 'files', label: 'FTP Server', sub: 'files.example:21', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Control connection', sub: 'Plain-text login',
      text: 'The client connects to port 21 and logs in with `USER` and `PASS`. Both are sent as readable text.',
      fields: [['Port', '21'], ['Password', 'Sent in clear text']],
      packets: [
        ['s', 'c', 'FTP', '220 Welcome to files.example', 40, 'res'],
        ['c', 's', 'FTP', 'USER alice', 20, 'req'],
        ['s', 'c', 'FTP', '331 Password required', 30, 'res'],
        ['c', 's', 'FTP', 'PASS Summer2026!', 24, 'data'],
        ['s', 'c', 'FTP', '230 Login successful', 30, 'res'],
      ],
    },
    {
      title: 'Passive mode', sub: 'A second connection for data',
      text: 'To download a file, the client asks for passive mode. The server replies with an IP and port, and the client opens a new connection there for the file itself.',
      fields: [['Reply', '227 Entering Passive Mode (198,51,100,30,195,80)'], ['Data port', '195×256+80 = 50000']],
      packets: [
        ['c', 's', 'FTP', 'PASV', 6, 'req'],
        ['s', 'c', 'FTP', '227 Entering Passive Mode (…,195,80)', 50, 'res'],
        ['c', 's', 'TCP', '→ :50000 [SYN] (data connection)', 66, 'ctl'],
      ],
    },
    {
      title: 'Transfer', sub: 'File over the data channel',
      text: 'The client sends `RETR` on the control connection and the file arrives on the data connection, also unencrypted.',
      fields: [['Command', 'RETR payroll.csv'], ['Size', '220 KB']],
      packets: [
        ['c', 's', 'FTP', 'RETR payroll.csv', 18, 'req'],
        ['s', 'c', 'FTP-DATA', 'payroll.csv contents (plain text)', 225000, 'data'],
        ['s', 'c', 'FTP', '226 Transfer complete', 30, 'res'],
      ],
    },
    {
      title: 'Why it\'s retired', sub: 'Everything was visible',
      text: 'Anyone on the network path could read the password and the file. SFTP does the same job inside an encrypted SSH session.',
      fields: [['Seen by observer', 'Username, password, file'], ['Replacement', 'SFTP (port 22)']],
      defend: 'Search your environment for port 21 listeners. Each one is a likely source of leaked credentials.',
      packets: [
        ['c', 'eve', 'Sniff', 'Observer sees: PASS Summer2026!', 24, 'atk'],
        ['s', 'eve', 'Sniff', 'Observer sees: payroll.csv', 225000, 'atk'],
      ],
    },
  ],
});

SE.register({
  id: 'websocket', domain: 'protocols', kind: 'protocol', level: 'Intermediate', severity: 'Protocol',
  name: 'WebSocket', full: 'Two-way, real-time web messaging',
  tags: ['websocket', 'wss', 'upgrade', 'real-time', 'chat', 'cswsh'],
  summary: 'HTTP is request-then-response. WebSocket starts as an HTTP request and then "upgrades" into a long-lived, two-way channel, so the server can push messages instantly. Chat apps, live dashboards and multiplayer games rely on it.',
  facts: [['Defined in', 'RFC 6455'], ['URLs', 'ws:// (80), wss:// (443)'], ['Starts as', 'HTTP GET with Upgrade header'], ['Success', '101 Switching Protocols'], ['Data', 'Frames (text, binary, ping, close)'], ['Known risk', 'Cross-site WebSocket hijacking']],
  defenses: [
    'Always use wss:// (TLS)',
    'Check the Origin header during the handshake',
    'Authenticate with a token in the first message, not just a cookie',
    'Validate and rate-limit every incoming message like any other input',
  ],
  nodes: [
    { id: 'br', type: 'browser', label: 'Browser', sub: 'chat.example', x: 140, y: 245 },
    { id: 's', type: 'server', label: 'Chat Server', sub: 'wss://chat.example', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Upgrade request', sub: 'Starts as HTTP',
      text: 'The browser sends a normal HTTP GET with `Upgrade: websocket` and a random key.',
      fields: [['Header', 'Upgrade: websocket'], ['Origin', 'https://chat.example']],
      packets: [
        ['br', 's', 'HTTP', 'GET /socket (Upgrade: websocket)', 480, 'req',
          `GET /socket HTTP/1.1
Host: chat.example
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://chat.example`],
      ],
    },
    {
      title: '101 Switching Protocols', sub: 'Now it\'s a WebSocket',
      text: 'The server checks the Origin, then agrees. From here on the connection carries WebSocket frames, not HTTP.',
      fields: [['Status', '101'], ['Accept', 'Hash of the client key']],
      packets: [
        ['s', 'br', 'HTTP', '101 Switching Protocols', 160, 'res'],
      ],
    },
    {
      title: 'Messages both ways', sub: 'Server push',
      text: 'Either side can send at any time. The server pushes new chat messages instantly, with no polling.',
      fields: [['Frame type', 'Text'], ['Direction', 'Both']],
      packets: [
        ['br', 's', 'WS', 'Text frame {"type":"msg","text":"hi team"}', 40, 'req'],
        ['s', 'br', 'WS', 'Text frame {"from":"sam","text":"morning!"}', 44, 'res'],
        ['s', 'br', 'WS', 'Text frame {"from":"lee","text":"standup in 5"}', 48, 'res'],
      ],
    },
    {
      title: 'Keep-alive and close', sub: 'Ping, pong, goodbye',
      text: 'Ping and pong frames keep idle connections alive through proxies. A close frame ends the session cleanly.',
      fields: [['Keep-alive', 'Ping / Pong'], ['Close code', '1000 (normal)']],
      defend: 'Browsers send cookies with WebSocket handshakes from any site. Without an Origin check, a malicious page can open a socket as the logged-in user.',
      packets: [
        ['s', 'br', 'WS', 'Ping', 6, 'ctl'],
        ['br', 's', 'WS', 'Pong', 6, 'ctl'],
        ['br', 's', 'WS', 'Close 1000', 8, 'ctl'],
      ],
    },
  ],
});

SE.register({
  id: 'quic', domain: 'protocols', kind: 'protocol', level: 'Intermediate', severity: 'Protocol',
  name: 'QUIC & HTTP/3', full: 'Fast, encrypted transport over UDP',
  tags: ['quic', 'http/3', 'udp', 'streams', 'connection migration', '0-rtt'],
  summary: 'QUIC rebuilds what TCP and TLS do, on top of UDP, with encryption built in. Connections start faster, many streams share one connection without blocking each other, and a connection can survive switching from Wi-Fi to mobile data. HTTP/3 runs on it.',
  facts: [['Defined in', 'RFC 9000'], ['HTTP/3', 'RFC 9114'], ['Transport', 'UDP 443'], ['Encryption', 'TLS 1.3, always on'], ['Setup', '1 RTT (0-RTT on resume)'], ['Key feature', 'Independent streams']],
  defenses: [
    'Keep QUIC visible to your monitoring; some tools only inspect TCP',
    'Treat 0-RTT data as replayable: only allow safe, idempotent requests',
    'Rate-limit UDP 443 like any other public service',
    'Firewalls can force fallback to TCP by blocking UDP 443 if policy requires',
  ],
  nodes: [
    { id: 'c', type: 'phone', label: 'Phone Browser', sub: 'Wi-Fi 192.168.1.42', x: 140, y: 245 },
    { id: 's', type: 'server', label: 'Web Server', sub: 'h3 on UDP 443', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Initial', sub: 'Transport and TLS together',
      text: 'The first UDP packet already carries the TLS 1.3 ClientHello. Transport setup and encryption setup happen in the same round trip.',
      fields: [['Packet type', 'Initial'], ['Contains', 'TLS ClientHello']],
      packets: [
        ['c', 's', 'QUIC', 'Initial (CRYPTO: ClientHello, ALPN h3)', 1250, 'ctl'],
        ['s', 'c', 'QUIC', 'Initial (ServerHello) + Handshake (cert, Finished)', 3800, 'ctl'],
        ['c', 's', 'QUIC', 'Handshake (Finished)', 90, 'ctl'],
      ],
    },
    {
      title: 'Parallel streams', sub: 'No head-of-line blocking',
      text: 'The page, CSS and images travel on separate streams in one connection. If a packet for one image is lost, only that stream waits; the others keep flowing.',
      fields: [['Streams', '0, 4, 8, 12'], ['Lost packet', 'Only delays its own stream']],
      packets: [
        ['c', 's', 'HTTP/3', 'Stream 0: GET /  · Stream 4: GET /app.css · Stream 8: GET /logo.png', 420, 'req'],
        ['s', 'c', 'HTTP/3', 'Stream 0: 200 (HTML)', 12800, 'res'],
        ['s', 'c', 'HTTP/3', 'Stream 4: 200 (CSS)', 4100, 'res'],
        ['s', 'c', 'HTTP/3', 'Stream 8: 200 (PNG)', 22000, 'res'],
      ],
    },
    {
      title: 'Connection migration', sub: 'Wi-Fi to mobile, no reconnect',
      text: 'You walk out of Wi-Fi range and the phone switches to mobile data with a new IP. Because QUIC identifies connections by an ID, not by IP and port, the transfer simply continues.',
      fields: [['New address', 'Mobile 100.70.1.9'], ['Connection ID', 'Unchanged']],
      defend: 'All QUIC headers beyond the basics are encrypted, so middleboxes see far less. That\'s good for privacy, harder for network monitoring.',
      packets: [
        ['c', 's', 'QUIC', '1-RTT from new IP (same connection ID) + PATH_CHALLENGE', 80, 'ctl'],
        ['s', 'c', 'QUIC', 'PATH_RESPONSE', 80, 'ctl'],
        ['s', 'c', 'HTTP/3', 'Stream 12 continues (video chunk)', 48000, 'res'],
      ],
    },
  ],
});

SE.register({
  id: 'ntp', domain: 'protocols', kind: 'protocol', level: 'Beginner', severity: 'Protocol',
  name: 'NTP', full: 'Network Time Protocol',
  tags: ['ntp', 'time', 'clock', 'nts', 'stratum'],
  summary: 'Accurate time quietly underpins security: certificates, Kerberos tickets, MFA codes and log correlation all depend on it. NTP sets your clock by exchanging four timestamps with a time server and working out both the offset and the network delay.',
  facts: [['Defined in', 'RFC 5905'], ['Transport', 'UDP 123'], ['Hierarchy', 'Stratum 0 (atomic/GPS) → 1 → 2 …'], ['Accuracy', 'Milliseconds over the internet'], ['Secure version', 'NTS (RFC 8915)'], ['Why it matters', 'TLS, Kerberos, TOTP, logs']],
  defenses: [
    'Use several trusted time sources, and NTS where supported',
    'Don\'t expose NTP servers to the internet with old monitoring commands enabled (amplification)',
    'Alert on large sudden clock jumps on servers',
    'Keep all logging systems on the same time source',
  ],
  nodes: [
    { id: 'c', type: 'server', label: 'Your Server', sub: 'clock 2.4 s fast', x: 140, y: 245 },
    { id: 's', type: 'server', label: 'Time Server', sub: 'stratum 2', x: 760, y: 245, good: true },
  ],
  steps: [
    {
      title: 'Request with T1', sub: 'When I sent this',
      text: 'The client sends a request stamped with its own send time, T1.',
      fields: [['T1 (client send)', '10:00:02.400']],
      packets: [
        ['c', 's', 'NTP', 'Client request, transmit time T1', 90, 'req'],
      ],
    },
    {
      title: 'Reply with T2 and T3', sub: 'When I got it, when I answered',
      text: 'The server records when the request arrived (T2) and when it sent the reply (T3). The client notes when the reply arrives (T4).',
      fields: [['T2 (server receive)', '10:00:00.020'], ['T3 (server send)', '10:00:00.021'], ['T4 (client receive)', '10:00:02.441']],
      packets: [
        ['s', 'c', 'NTP', 'Server reply: T1, T2, T3, stratum 2', 90, 'res'],
      ],
    },
    {
      title: 'Work out the offset', sub: 'Simple arithmetic',
      text: 'Offset = ((T2 − T1) + (T3 − T4)) / 2 ≈ −2.400 s, so the client is about 2.4 seconds fast. Round-trip delay = (T4 − T1) − (T3 − T2) = 40 ms. The client slews its clock gently into line.',
      fields: [['Offset', '−2.400 s'], ['Delay', '40 ms']],
      defend: 'A few minutes of clock drift can break TLS validation, Kerberos logins and MFA codes, and makes incident timelines unreliable.',
      packets: [
        ['c', 'c', 'Local', 'Adjust clock by −2.400 s', 0, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'bgp', domain: 'protocols', kind: 'protocol', level: 'Advanced', severity: 'Protocol',
  name: 'BGP', full: 'Border Gateway Protocol',
  tags: ['bgp', 'routing', 'autonomous system', 'as', 'rpki', 'hijack', 'internet'],
  summary: 'The internet is tens of thousands of separate networks (autonomous systems). BGP is how they tell each other which address ranges they can reach. Each network announces its prefixes, neighbours pass them on, and every router picks a path.',
  facts: [['Defined in', 'RFC 4271'], ['Transport', 'TCP 179'], ['Speakers', 'Autonomous systems (AS numbers)'], ['Messages', 'OPEN, KEEPALIVE, UPDATE, NOTIFICATION'], ['Main risk', 'Route hijacks and leaks'], ['Protection', 'RPKI (RFC 6480)']],
  defenses: [
    'Sign your prefixes with RPKI (ROAs) and validate others\' routes',
    'Filter what each neighbour may announce (prefix lists, IRR)',
    'Use MANRS practices and monitor announcements for your prefixes',
    'Protect BGP sessions with TCP-AO / MD5 and TTL security',
  ],
  nodes: [
    { id: 'a', type: 'router', label: 'Hosting Network', sub: 'AS 64500 · 198.51.100.0/24', x: 140, y: 245 },
    { id: 'b', type: 'router', label: 'Transit Provider', sub: 'AS 64510', x: 450, y: 110 },
    { id: 'c', type: 'router', label: 'Your ISP', sub: 'AS 64520', x: 760, y: 245 },
    { id: 'x', type: 'router', label: 'Other Network', sub: 'AS 64666', x: 450, y: 400, evil: true },
  ],
  steps: [
    {
      title: 'Open a session', sub: 'Neighbours shake hands',
      text: 'Two neighbouring routers open a TCP connection on port 179 and exchange OPEN messages with their AS numbers. KEEPALIVEs then confirm the link is up.',
      fields: [['Port', 'TCP 179'], ['Peers', 'AS 64500 ↔ AS 64510']],
      packets: [
        ['a', 'b', 'BGP', 'OPEN (AS 64500, hold time 90)', 80, 'ctl'],
        ['b', 'a', 'BGP', 'OPEN (AS 64510, hold time 90)', 80, 'ctl'],
        ['a', 'b', 'BGP', 'KEEPALIVE', 19, 'ctl'],
      ],
    },
    {
      title: 'Announce a prefix', sub: '"I can reach 198.51.100.0/24"',
      text: 'The hosting network announces its address range. The transit provider adds its own AS number to the path and passes the route on to your ISP.',
      fields: [['Prefix', '198.51.100.0/24'], ['AS path at ISP', '64510 64500']],
      packets: [
        ['a', 'b', 'BGP', 'UPDATE 198.51.100.0/24, AS_PATH 64500', 60, 'req'],
        ['b', 'c', 'BGP', 'UPDATE 198.51.100.0/24, AS_PATH 64510 64500', 64, 'req'],
      ],
    },
    {
      title: 'A conflicting announcement', sub: 'Mistake or hijack',
      text: 'Another network announces the same range, by mistake or on purpose. BGP has no built-in way to know who really owns an address range, so some routers may prefer the wrong path.',
      fields: [['Bogus origin', 'AS 64666'], ['Effect', 'Traffic may be misdirected']],
      packets: [
        ['x', 'c', 'BGP', 'UPDATE 198.51.100.0/24, AS_PATH 64666', 60, 'atk'],
      ],
    },
    {
      title: 'RPKI validation', sub: 'Checking who may originate',
      text: 'The hosting network published a signed ROA saying only AS 64500 may originate this prefix. Your ISP validates routes against RPKI, marks the bogus announcement invalid, and drops it.',
      fields: [['ROA', '198.51.100.0/24 → AS 64500'], ['AS 64666 route', 'RPKI invalid → rejected']],
      defend: 'RPKI stops most accidental hijacks. Check whether your prefixes have ROAs and whether your providers validate them.',
      packets: [
        ['c', 'c', 'RPKI', 'Origin AS 64666 not authorized → invalid, dropped', 0, 'def'],
        ['c', 'c', 'RPKI', 'Origin AS 64500 matches ROA → valid, installed', 0, 'def'],
      ],
    },
  ],
});
