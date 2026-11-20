/* End-of-module quizzes: [question, [options], index of correct option, explanation]. */
SE.quizzes = {
  /* ---- Internet Protocols ---- */
  ethernet: [
    ['What does a switch do with a frame for a MAC address it hasn\'t learned yet?', ['Drops it', 'Floods it out of every other port', 'Sends it to the router'], 1, 'Unknown destinations are flooded. Once the device replies, the switch learns its port.'],
    ['How does a switch learn which port a device is on?', ['From the source MAC of frames it receives', 'From DHCP', 'From DNS'], 0, 'Every incoming frame teaches the switch: "this source MAC lives on this port".'],
    ['What limits how far a broadcast travels?', ['The TTL', 'The VLAN (broadcast domain)', 'The MTU'], 1, 'Broadcasts reach every port in the same VLAN, which is why segmenting with VLANs matters.'],
  ],
  dhcp: [
    ['What are the four DHCP messages, in order?', ['Discover, Offer, Request, Acknowledge', 'Request, Offer, Accept, Done', 'Hello, Offer, Confirm, Lease'], 0, 'The DORA exchange: Discover, Offer, Request, Acknowledge.'],
    ['Why does a new device send DHCP Discover to 255.255.255.255?', ['It\'s the router\'s address', 'It has no IP yet and doesn\'t know where the server is', 'To reach the internet'], 1, 'With no address and no server known, broadcasting is the only option.'],
    ['Which switch feature stops a fake DHCP server?', ['Port mirroring', 'DHCP snooping', 'Spanning tree'], 1, 'DHCP snooping only lets trusted ports send DHCP server replies.'],
  ],
  'ip-routing': [
    ['What does each router do to an IP packet\'s TTL?', ['Doubles it', 'Lowers it by one', 'Resets it to 64'], 1, 'Each hop decrements TTL; at zero the packet is dropped and an ICMP message is sent back.'],
    ['How does traceroute discover each hop?', ['It asks DNS', 'It sends probes with TTL 1, 2, 3… and reads the ICMP replies', 'It logs into each router'], 1, 'Each router that drops a probe reveals itself with "Time Exceeded".'],
    ['What tells traceroute it has reached the destination?', ['A Time Exceeded message', 'A Port Unreachable reply from the target', 'A TCP RST from the first router'], 1, 'The target has nothing on that high UDP port, so it answers Port Unreachable.'],
  ],
  icmp: [
    ['Which ICMP messages does ping use?', ['Echo Request and Echo Reply', 'Time Exceeded', 'Redirect'], 0, 'Ping sends type 8 Echo Request and expects type 0 Echo Reply.'],
    ['Why is blocking all ICMP a bad idea?', ['It disables DNS', 'It breaks Path MTU Discovery, causing hung connections', 'It slows down TCP handshakes'], 1, '"Fragmentation needed" messages are how senders learn to shrink packets.'],
    ['What does "Destination Unreachable" help with?', ['Making failures fast and clear instead of timing out', 'Encrypting traffic', 'Assigning IP addresses'], 0, 'The network reports the problem so apps don\'t wait for a timeout.'],
  ],
  tcp: [
    ['What is the TCP three-way handshake?', ['SYN, SYN-ACK, ACK', 'HELLO, OK, START', 'SYN, ACK, FIN'], 0, 'Both sides exchange starting sequence numbers and confirm them.'],
    ['What does an ACK number of 518 mean?', ['518 packets were lost', 'Everything up to byte 517 arrived; send byte 518 next', 'The window is 518 bytes'], 1, 'ACK numbers name the next byte the receiver expects.'],
    ['What triggers a fast retransmit?', ['A FIN packet', 'Three duplicate ACKs', 'A DNS timeout'], 1, 'Repeated ACKs for the same byte signal that a segment went missing.'],
  ],
  udp: [
    ['What does UDP do when a datagram is lost?', ['Resends it automatically', 'Nothing; the application decides', 'Closes the connection'], 1, 'UDP has no retransmission. Real-time apps simply use the next update.'],
    ['Why do games and voice calls like UDP?', ['It\'s encrypted', 'No handshake and no waiting for old data', 'It guarantees order'], 1, 'Low latency matters more than replaying stale data.'],
    ['Why can UDP services be abused for amplification attacks?', ['UDP source addresses are easy to spoof', 'UDP packets are always large', 'UDP needs no ports'], 0, 'Attackers fake the victim\'s address so big replies go to the victim.'],
  ],
  dns: [
    ['Who does the resolver ask first when nothing is cached?', ['The authoritative server', 'A root server', 'The website itself'], 1, 'Root servers refer it to the TLD servers, which refer it to the domain\'s name servers.'],
    ['What does a DNS record\'s TTL control?', ['How long the answer may be cached', 'How many hops the query may take', 'How long the domain is registered'], 0, 'After the TTL expires, the resolver must look the name up again.'],
    ['What does DNSSEC add?', ['Encryption of queries', 'Signatures that prove answers are genuine', 'Faster lookups'], 1, 'DNSSEC authenticates answers; DoH and DoT encrypt them.'],
  ],
  http: [
    ['What does a 304 Not Modified response mean?', ['The page was deleted', 'Your cached copy is still current; no body is sent', 'You need to log in'], 1, 'The browser reuses its cached copy, saving bandwidth.'],
    ['Which header tells browsers to always use HTTPS for a site?', ['Content-Type', 'Strict-Transport-Security (HSTS)', 'Cache-Control'], 1, 'HSTS stops browsers ever falling back to plain HTTP.'],
    ['Where should session tokens never go?', ['In URLs', 'In HttpOnly cookies', 'In request headers'], 0, 'URLs end up in logs, browser history and referrer headers.'],
  ],
  smtp: [
    ['How does a sending server find where to deliver mail for partner.example?', ['It asks for the MX record in DNS', 'It guesses mail.partner.example', 'It asks the recipient\'s browser'], 0, 'The MX record names the receiving mail server.'],
    ['Which check confirms a server is allowed to send for a domain?', ['DKIM', 'SPF', 'IMAP'], 1, 'SPF lists permitted sending IPs; DKIM proves the message was signed by the domain.'],
    ['What does DMARC add on top of SPF and DKIM?', ['Encryption', 'A policy for what receivers should do when checks fail', 'Faster delivery'], 1, 'With p=reject, spoofed mail claiming to be from you is refused.'],
  ],
  imap: [
    ['How does IMAP differ from POP3?', ['IMAP keeps mail on the server and syncs devices', 'IMAP is only for sending', 'IMAP deletes mail after download'], 0, 'That\'s why your phone and laptop show the same inbox.'],
    ['What does the IDLE command do?', ['Logs you out', 'Lets the server push new-mail notices', 'Pauses the download'], 1, 'Instead of polling, the app waits for the server to announce new mail.'],
    ['Why are providers turning off basic password logins for IMAP?', ['They\'re slow', 'They bypass MFA', 'They break IDLE'], 1, 'OAuth with MFA is much harder to abuse than a stored password.'],
  ],
  ssh: [
    ['What should you do if SSH warns the host key has changed?', ['Ignore it', 'Stop and verify; it may be an attacker in the middle', 'Delete your own key'], 1, 'A changed host key can mean a rebuilt server or an interception.'],
    ['During public-key login, what leaves your laptop?', ['Your private key', 'A signature made with your private key', 'Your password'], 1, 'The private key never leaves; the server checks the signature with your public key.'],
    ['Which setting most reduces SSH brute-force risk?', ['Disabling password authentication', 'Changing the banner', 'Using a longer username'], 0, 'Key-only login makes password guessing pointless.'],
  ],
  ftp: [
    ['What can someone on the network path see in a plain FTP session?', ['Nothing', 'Only file names', 'Username, password and file contents'], 2, 'FTP sends everything in clear text.'],
    ['Why does FTP open a second connection?', ['For encryption', 'For the file data itself', 'For DNS'], 1, 'Port 21 carries commands; each transfer uses a separate data connection.'],
    ['What is the usual secure replacement?', ['Telnet', 'SFTP over SSH', 'HTTP on port 80'], 1, 'SFTP gives the same file operations inside an encrypted SSH session.'],
  ],
  websocket: [
    ['How does a WebSocket connection start?', ['As an HTTP request with an Upgrade header', 'As a UDP datagram', 'As a DNS query'], 0, 'The server answers 101 Switching Protocols and the connection becomes a WebSocket.'],
    ['What does WebSocket allow that plain HTTP doesn\'t?', ['Server push at any time', 'Caching', 'Compression'], 0, 'Either side can send messages whenever it likes.'],
    ['Which check prevents cross-site WebSocket hijacking?', ['Checking the Origin header in the handshake', 'Using port 80', 'Disabling ping frames'], 0, 'Browsers send cookies with WebSocket handshakes from any site.'],
  ],
  quic: [
    ['What does QUIC run on?', ['TCP', 'UDP', 'ICMP'], 1, 'QUIC rebuilds reliability and encryption on top of UDP.'],
    ['What is head-of-line blocking, and how does QUIC avoid it?', ['One lost packet stalls everything; QUIC uses independent streams', 'Slow DNS; QUIC caches it', 'Large headers; QUIC compresses them'], 0, 'A loss only delays the stream it belongs to.'],
    ['How does a QUIC connection survive switching from Wi-Fi to mobile data?', ['It identifies connections by an ID, not IP and port', 'It reconnects quickly', 'It uses the same IP'], 0, 'Connection migration keeps transfers going across networks.'],
  ],
  ntp: [
    ['Why does accurate time matter for security?', ['Certificates, Kerberos, MFA codes and logs depend on it', 'It speeds up TLS', 'It encrypts traffic'], 0, 'Clock drift breaks validation and confuses incident timelines.'],
    ['How many timestamps does an NTP exchange use to compute offset and delay?', ['One', 'Two', 'Four'], 2, 'T1 to T4: client send, server receive, server send, client receive.'],
    ['What is the secure version of NTP?', ['NTS (Network Time Security)', 'NTPv1', 'SNTP'], 0, 'NTS authenticates time responses.'],
  ],
  bgp: [
    ['What does BGP do?', ['Assigns IP addresses', 'Lets networks announce which address ranges they can reach', 'Encrypts web traffic'], 1, 'Autonomous systems exchange routes with BGP.'],
    ['Why can BGP hijacks happen?', ['BGP has no built-in proof of who owns a prefix', 'BGP uses UDP', 'BGP routes expire hourly'], 0, 'Routers may accept a false announcement unless they validate it.'],
    ['What does RPKI provide?', ['Signed records of which AS may originate a prefix', 'Faster routing', 'DNS for routers'], 0, 'Routes from an unauthorized origin are marked invalid and dropped.'],
  ],

  /* ---- Web ---- */
  sqli: [
    ['What is the root cause of SQL injection?', ['Weak passwords', 'User input concatenated into SQL text', 'Missing HTTPS'], 1, 'The input stops being data and becomes part of the command.'],
    ['What does a leaked SQL error tell an attacker?', ['Nothing useful', 'That their input reaches a query', 'The admin password'], 1, 'Error messages confirm injection and reveal structure.'],
    ['What actually fixes SQL injection?', ['A WAF', 'Parameterized queries', 'Hiding error messages'], 1, 'With parameters the database never parses input as SQL.'],
  ],
  'xss-reflected': [
    ['Where does reflected XSS run?', ['On the server', 'In the victim\'s browser, as the trusted site', 'In the attacker\'s browser'], 1, 'The browser can\'t tell the injected script from the site\'s own code.'],
    ['How is reflected XSS usually delivered?', ['A crafted link', 'A stored comment', 'A DNS record'], 0, 'The payload sits in the URL and is echoed back by the page.'],
    ['Which cookie flag stops JavaScript from reading the session cookie?', ['Secure', 'HttpOnly', 'Path'], 1, 'HttpOnly cookies can\'t be read by scripts, though XSS can still act as the user.'],
  ],
  'xss-stored': [
    ['How does stored XSS differ from reflected XSS?', ['It\'s saved on the server and hits every viewer', 'It only works on mobile', 'It needs a phishing link'], 0, 'No link is needed; viewing the page is enough.'],
    ['When should you encode user content?', ['Only when saving', 'Every time it\'s rendered', 'Never, if you use HTTPS'], 1, 'Data can reach the database through other paths too.'],
    ['What can stored XSS do even if cookies are HttpOnly?', ['Nothing', 'Send requests as the victim, like changing their email', 'Read the server\'s files'], 1, 'Scripts run with the user\'s session, so they can act on their behalf.'],
  ],
  csrf: [
    ['Why does CSRF work?', ['Browsers attach cookies to requests automatically', 'The attacker steals the password', 'HTTPS is missing'], 0, 'The forged request carries the victim\'s valid session.'],
    ['Which cookie setting blocks most CSRF?', ['SameSite=Lax or Strict', 'Max-Age', 'Domain'], 0, 'The browser leaves the cookie off cross-site POSTs.'],
    ['Why use a CSRF token as well?', ['The attacker\'s page can\'t read it, so forged requests lack it', 'It speeds up forms', 'It encrypts the form'], 0, 'Tokens and SameSite together cover older browsers and edge cases.'],
  ],
  ssrf: [
    ['What makes SSRF dangerous?', ['The server fetches attacker-chosen URLs from inside the network', 'It crashes browsers', 'It reveals DNS records'], 0, 'The server becomes a proxy past the firewall.'],
    ['When should a fetcher check the destination IP?', ['Before DNS resolution', 'After DNS resolution, on every redirect', 'Only once at startup'], 1, 'Attackers use names that resolve to internal IPs.'],
    ['Which address is a classic SSRF target in the cloud?', ['8.8.8.8', '169.254.169.254', '1.1.1.1'], 1, 'The instance metadata service can hand out credentials.'],
  ],
  idor: [
    ['What is missing in an IDOR bug?', ['Authentication', 'An ownership/authorization check', 'Encryption'], 1, 'The user is logged in, but the API never checks the object is theirs.'],
    ['Why do sequential IDs make IDOR worse?', ['They make enumeration trivial', 'They\'re slower', 'They break caching'], 0, 'A script can walk every ID in minutes.'],
    ['What is the real fix?', ['Use UUIDs', 'Scope every query to the authenticated user', 'Hide the IDs in the UI'], 1, 'Random IDs help, but only an authorization check fixes it.'],
  ],
  'path-traversal': [
    ['What does "../" do in a file path?', ['Moves up one directory', 'Opens a new folder', 'Nothing'], 0, 'Chained "../" sequences climb out of the intended folder.'],
    ['Why do "strip ../" filters often fail?', ['Encodings and tricks like "....//" rebuild "../"', 'They\'re too slow', 'They block valid files'], 0, 'Blocklist filters lose to creative input.'],
    ['What reliably prevents traversal?', ['Canonicalize the path and check it starts with the base directory', 'Use longer filenames', 'Use HTTPS'], 0, 'Or serve files by ID from a lookup table.'],
  ],
  cmdi: [
    ['Which character lets an attacker add a command in a shell?', [';', '@', '#'], 0, 'Shell metacharacters like ; && and $( ) chain commands.'],
    ['What is the safest fix?', ['Escape semicolons', 'Don\'t use a shell: call the program with an argument array', 'Run as root'], 1, 'With no shell involved, metacharacters have no meaning.'],
    ['Which control would have stopped the reverse shell callback?', ['Egress filtering', 'A longer password', 'HSTS'], 0, 'Blocking unexpected outbound connections cuts off the attacker.'],
  ],

  /* ---- API ---- */
  'api-gateway': [
    ['What should the gateway check on every call?', ['Token validity, rate limits and request schema', 'Only the URL', 'Nothing; the service does it all'], 0, 'The gateway handles authentication and abuse limits centrally.'],
    ['Who decides whether alice may see order 5521?', ['The gateway', 'The service, which knows who owns the order', 'The client app'], 1, 'Object-level authorization needs business data only the service has.'],
    ['Why return an explicit response model?', ['To avoid leaking internal fields', 'To make JSON smaller', 'For caching'], 0, 'Returning whole database rows exposes data clients shouldn\'t see.'],
  ],
  'mass-assignment': [
    ['What causes mass assignment?', ['Binding a request body straight onto a database object', 'Weak TLS', 'Missing rate limits'], 0, 'Every key in the body gets copied, including role or plan.'],
    ['How did the attacker learn the field names?', ['From the API\'s full-object response', 'From DNS', 'By guessing passwords'], 0, 'Excessive data exposure hands out the property names.'],
    ['What is the fix?', ['Explicit input models with allow-listed fields', 'Hide the API', 'Use PUT instead of PATCH'], 0, 'Reject unknown fields and only accept what the endpoint needs.'],
  ],
  bfla: [
    ['What does BFLA stand for?', ['Broken Function Level Authorization', 'Basic Firewall Layer Access', 'Bound File Lookup API'], 0, 'Users can call functions their role shouldn\'t allow.'],
    ['Is hiding the admin button in the UI enough?', ['Yes', 'No; the API must enforce roles itself', 'Only on mobile'], 1, 'Routes are often visible in JavaScript bundles.'],
    ['What is the safest default for new routes?', ['Allow all', 'Deny unless a permission is declared', 'Allow logged-in users'], 1, 'Deny-by-default means forgotten routes stay closed.'],
  ],
  'api-rate-limit': [
    ['Which OWASP API risk covers missing limits?', ['API4: Unrestricted Resource Consumption', 'API1: BOLA', 'API9: Inventory'], 0, 'No limits means scraping, outages and surprise bills.'],
    ['What status code tells a client to slow down?', ['200', '429', '301'], 1, '429 Too Many Requests, often with Retry-After.'],
    ['Why cap page sizes?', ['One request could pull millions of rows', 'To save bandwidth on images', 'For SEO'], 0, 'Unbounded queries tie up the database and leak data quickly.'],
  ],
  'webhook-hmac': [
    ['What proves a webhook really came from the provider?', ['An HMAC signature made with a shared secret', 'The sender\'s IP', 'The User-Agent'], 0, 'Without the secret, attackers can\'t produce a valid signature.'],
    ['How do you stop replay of a genuine old webhook?', ['Check the timestamp and event ID', 'Use HTTPS', 'Rotate the URL daily'], 0, 'Each delivery is usable once and only for a few minutes.'],
    ['How should signatures be compared?', ['With ==', 'In constant time', 'By length only'], 1, 'Constant-time comparison avoids timing leaks.'],
  ],

  /* ---- Network ---- */
  'port-scan': [
    ['In a SYN scan, what reply means the port is open?', ['RST', 'SYN-ACK', 'No reply'], 1, 'RST means closed; silence usually means filtered.'],
    ['Why is it called a "half-open" scan?', ['The scanner never completes the handshake', 'It scans half the ports', 'It only uses UDP'], 0, 'The scanner sends RST instead of the final ACK.'],
    ['Why do version banners matter?', ['They let attackers look up known vulnerabilities', 'They slow scans', 'They enable encryption'], 0, 'Exact versions map straight to CVEs.'],
  ],
  'arp-spoof': [
    ['Why is ARP easy to spoof?', ['It has no authentication', 'It uses TCP', 'It\'s encrypted'], 0, 'Devices accept unsolicited replies and overwrite their caches.'],
    ['What can an attacker do once traffic flows through them?', ['Read or alter anything not encrypted', 'Only slow it down', 'Nothing'], 0, 'Plain HTTP logins are exposed.'],
    ['Which switch feature blocks ARP spoofing?', ['Dynamic ARP Inspection', 'Port mirroring', 'Jumbo frames'], 0, 'DAI checks ARP replies against DHCP snooping bindings.'],
  ],
  'dns-spoof': [
    ['What must a forged DNS answer match to be accepted?', ['The transaction ID and source port', 'The TTL', 'The MX record'], 0, 'Randomizing both makes blind guessing far harder.'],
    ['What makes cache poisoning so harmful?', ['Every user of the resolver gets the fake answer', 'It deletes the domain', 'It only affects one device'], 0, 'The poisoned entry is served until its TTL expires.'],
    ['Which control lets a resolver reject forged answers outright?', ['DNSSEC validation', 'Longer TTLs', 'IPv6'], 0, 'Unsigned or badly signed answers are discarded.'],
  ],
  'syn-flood': [
    ['What does a SYN flood exhaust?', ['The server\'s queue of half-open connections', 'Disk space', 'DNS cache'], 0, 'Spoofed SYNs never complete, filling the backlog.'],
    ['How do SYN cookies help?', ['The server keeps no state until the client\'s ACK proves it\'s real', 'They encrypt SYNs', 'They block all UDP'], 0, 'Spoofed sources never answer, so they cost nothing.'],
    ['What handles very large volumetric floods?', ['Upstream scrubbing or a CDN', 'A longer timeout', 'More disk'], 0, 'Absorb the traffic before it reaches your link.'],
  ],
  'evil-twin': [
    ['How does an evil twin knock you off the real Wi-Fi?', ['Forged deauthentication frames', 'Changing your password', 'DNS spoofing'], 0, 'Without Protected Management Frames, deauth frames can be forged.'],
    ['Which feature makes your device ignore forged deauth frames?', ['802.11w PMF (required by WPA3)', 'WPS', 'Hidden SSIDs'], 0, 'Management frames are integrity-protected.'],
    ['What protects you on untrusted Wi-Fi?', ['A VPN and HTTPS everywhere', 'Turning off Bluetooth', 'A strong Wi-Fi password at home'], 0, 'Even if the network is hostile, your traffic stays encrypted.'],
  ],

  /* ---- Crypto ---- */
  tls13: [
    ['How many round trips does a full TLS 1.3 handshake take?', ['One', 'Two', 'Three'], 0, 'Key shares are sent in the first messages.'],
    ['Which part of the handshake proves the server owns its certificate?', ['CertificateVerify', 'ClientHello', 'SNI'], 0, 'The server signs the handshake transcript with its private key.'],
    ['What does forward secrecy protect against?', ['Decrypting recorded traffic after the server key is stolen', 'Phishing', 'DNS spoofing'], 0, 'Each session uses temporary keys that are thrown away.'],
  ],
  'diffie-hellman': [
    ['What do Alice and Bob send each other?', ['Their private secrets', 'g^secret mod p', 'The shared key'], 1, 'Only the public values cross the network.'],
    ['What hard problem protects the shared secret?', ['Factoring', 'The discrete logarithm', 'Sorting'], 1, 'Recovering a from g^a mod p is infeasible at real key sizes.'],
    ['What attack does plain, unauthenticated DH not stop?', ['A passive eavesdropper', 'An active man-in-the-middle', 'Brute force on the shared key'], 1, 'TLS signs the exchange with a certificate to prevent this.'],
  ],
  'cert-chain': [
    ['Which certificate is NOT sent by the server?', ['Leaf', 'Intermediate', 'Root'], 2, 'The root must already be in the browser\'s trust store.'],
    ['What must match the URL\'s hostname?', ['A Subject Alternative Name in the leaf', 'The issuer name', 'The root\'s name'], 0, 'Otherwise the browser shows a name-mismatch error.'],
    ['What do Certificate Transparency logs help catch?', ['Mis-issued certificates for your domain', 'Expired passwords', 'Slow servers'], 0, 'Every certificate is publicly logged and can be monitored.'],
  ],
  'password-storage': [
    ['Which is a good password hashing algorithm?', ['MD5', 'SHA-256 alone', 'Argon2id'], 2, 'Slow, memory-hard hashes make guessing expensive.'],
    ['What does a per-user salt prevent?', ['Precomputed lookup tables and identical hashes', 'Phishing', 'Brute force entirely'], 0, 'Each account must be attacked separately.'],
    ['Why should hashing be slow?', ['To multiply the cost of every guess for an attacker', 'To save CPU', 'To shorten hashes'], 0, '100 ms is invisible at login but huge across billions of guesses.'],
  ],

  /* ---- Defense ---- */
  waf: [
    ['Where does a WAF usually sit?', ['In front of the app as a reverse proxy', 'Inside the database', 'On the user\'s laptop'], 0, 'It inspects every request before the app sees it.'],
    ['Why do you still need secure code behind a WAF?', ['WAF rules can be bypassed', 'WAFs slow down apps', 'WAFs only block bots'], 0, 'The WAF buys time; fixing the bug closes the hole.'],
    ['How should a new WAF be rolled out?', ['Detection-only first, tune, then block', 'Block everything on day one', 'Disable logging'], 0, 'Tuning avoids blocking real customers.'],
  ],
  ids: [
    ['How does a passive IDS see traffic?', ['From a SPAN port or TAP copy', 'By sitting inline and blocking', 'From DNS logs only'], 0, 'It analyses copies without affecting the real traffic.'],
    ['How does an IPS differ?', ['It sits inline and can drop packets', 'It only reads logs', 'It encrypts traffic'], 0, 'More protection, but a bad rule can block real users.'],
    ['What limits network IDS visibility?', ['Encrypted payloads', 'IPv6', 'Short TTLs'], 0, 'Pair it with endpoint telemetry and metadata logging.'],
  ],
  siem: [
    ['Why normalise logs into common fields?', ['So one rule can work across many log sources', 'To save disk', 'To encrypt them'], 0, 'user.name and source.ip mean the same thing everywhere.'],
    ['What made the brute-force alert high severity?', ['Many failures followed by a success from the same IP', 'One failed login', 'A password change'], 0, 'Success after a failure burst suggests a compromised account.'],
    ['What is the first response step after confirming the incident?', ['Contain: disable the account and block the IP', 'Delete the logs', 'Wait for more alerts'], 0, 'Contain first, then investigate and recover.'],
  ],
  'zero-trust': [
    ['What is the core idea of Zero Trust?', ['Never trust a request because of its network location', 'Trust everything inside the VPN', 'Block all remote work'], 0, 'Every request is checked against identity, device and policy.'],
    ['Which signals does the policy engine consider?', ['User, group, device health and risk', 'Only the IP address', 'Only the password'], 0, 'Access is granted per app based on context.'],
    ['What happens when the device falls out of compliance?', ['The session is revoked straight away', 'Nothing until the session expires', 'The user is emailed'], 0, 'Continuous evaluation is what sets Zero Trust apart from a VPN.'],
  ],

  /* ---- AI ---- */
  'rag-pipeline': [
    ['What does the vector database return?', ['Document chunks closest in meaning to the question', 'The final answer', 'The user\'s password'], 0, 'Embeddings let the app search by meaning.'],
    ['Why filter retrieval by the user\'s permissions?', ['So the assistant can\'t quote documents the user couldn\'t open', 'To speed up search', 'To shorten answers'], 0, 'Without ACL filtering, the AI becomes a data-leak path.'],
    ['What is the key security fact about the prompt?', ['The model sees instructions and data as one stream of text', 'Prompts are encrypted', 'The model ignores retrieved text'], 0, 'That\'s why injected text can be mistaken for instructions.'],
  ],
  'prompt-injection': [
    ['What was the real bug in the leaked-secret example?', ['A secret was placed in the system prompt', 'The model was too small', 'HTTPS was missing'], 0, 'Assume anything the model can see, the user can extract.'],
    ['Where should permissions be enforced?', ['In application code, outside the model', 'In the system prompt', 'In the user\'s message'], 0, 'Prompts are not access control.'],
    ['Is prompt injection fully solved today?', ['Yes, with good wording', 'No; design so a successful injection does little harm', 'Yes, with a WAF'], 1, 'Limit what the model can reach and do.'],
  ],
  'indirect-injection': [
    ['Who wrote the malicious instructions in the email example?', ['The user', 'An outside sender, hidden in the email', 'The AI vendor'], 1, 'Anyone who can put text in front of the agent can try this.'],
    ['Which design change breaks the attack chain?', ['Read-only tools for summarising and confirmation before sending', 'A longer system prompt', 'Faster models'], 0, 'Remove at least one of: untrusted input, private data, outbound channel.'],
    ['Which OWASP LLM risk covers agents with too much power?', ['LLM06 Excessive Agency', 'LLM09 Misinformation', 'LLM03 Supply Chain'], 0, 'Give agents the least access the task needs.'],
  ],
  'llm-output': [
    ['How should model output be treated?', ['Like untrusted user input', 'As trusted code', 'As already sanitised'], 0, 'Its content is shaped by whatever text went in.'],
    ['How did the Markdown image leak data?', ['The browser loaded the image URL, sending data to an outside server', 'It ran JavaScript', 'It changed DNS'], 0, 'No click needed; the image request carried the data.'],
    ['Which control blocks that leak?', ['A CSP limiting img-src plus sanitised Markdown', 'Bigger models', 'HTTPS only'], 0, 'External images never load.'],
  ],
  'mcp-protocol': [
    ['What does an MCP server tell the host in `tools/list`?', ['Each tool\'s name, description and input schema', 'The user\'s password', 'The model\'s weights'], 0, 'The host passes these descriptions to the model so it knows what it can call.'],
    ['Who actually sends the `tools/call` request?', ['The host (MCP client), after the model asks for it', 'The model connects to the server directly', 'The user\'s browser'], 0, 'The model only proposes a call; the host decides and makes it.'],
    ['Why is a remote MCP server\'s access token bound to that server (its audience)?', ['So it can\'t be replayed against other APIs', 'To make it shorter', 'So it never expires'], 0, 'Token passthrough to other services is not allowed.'],
  ],
  'mcp-tool-poisoning': [
    ['Where did the malicious instructions hide?', ['In the tool\'s description, which the model reads', 'In the TLS certificate', 'In the user\'s question'], 0, 'Tool metadata goes straight into the model\'s context.'],
    ['How did a "weather" server get file contents it had no access to?', ['It instructed the model to use another, trusted tool and pass the result back', 'It hacked the file system', 'The user uploaded them'], 0, 'Cross-tool misuse: the model borrows another server\'s access.'],
    ['Which host feature would have exposed the theft?', ['Approval prompts that show every argument in full', 'A dark theme', 'Faster responses'], 0, 'The secrets inside `notes` would have been visible before sending.'],
  ],
  'ai-guardrails': [
    ['Which guardrails hold up best against evasion?', ['Deterministic ones: permissions, approvals, allow-lists', 'Clever prompt wording', 'Input classifiers alone'], 0, 'Classifiers help, but code-enforced rules don\'t get talked around.'],
    ['When should a human approve an AI action?', ['For high-impact actions like sharing, paying or deleting', 'Never', 'For every single message'], 0, 'Approvals belong where mistakes are costly.'],
    ['Why log prompts, tool calls and decisions?', ['To investigate incidents and improve rules', 'To train ads', 'It\'s not needed'], 0, 'Audit trails show what led to each action.'],
  ],

  /* ---- Secure Development ---- */
  'threat-modeling': [
    ['When is threat modelling most useful?', ['During design, before the code is written', 'Only after a breach', 'Only during a pen test'], 0, 'Design flaws are cheapest to fix before they are built.'],
    ['What does the "T" in STRIDE stand for?', ['Tampering', 'Tracking', 'Timeout'], 0, 'Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege.'],
    ['Where should you look hardest for threats?', ['Data flows that cross a trust boundary', 'Comments in the code', 'The colour scheme'], 0, 'Crossing from less-trusted to more-trusted is where checks are needed.'],
  ],
  pasta: [
    ['What makes PASTA different from STRIDE?', ['It is risk-centric: it starts from business objectives and ranks threats by business impact', 'It only covers privacy', 'It needs no diagrams'], 0, 'PASTA ties every threat back to what the business cares about.'],
    ['How many stages does PASTA have?', ['Seven', 'Three', 'Twelve'], 0, 'From business objectives to risk and impact analysis.'],
    ['What happens in the attack modelling stage?', ['Likely attacks are simulated, often using attack trees', 'The code is rewritten', 'Logs are deleted'], 0, 'Simulation shows which attack paths actually work.'],
  ],
  linddun: [
    ['What kind of threats does LINDDUN focus on?', ['Privacy threats', 'Network outages', 'Hardware failures'], 0, 'It complements security methods like STRIDE.'],
    ['Why can a run that always starts at the same place be a privacy threat?', ['It can reveal where the person lives (identifying)', 'It makes the app slower', 'It breaks GPS'], 0, 'Seemingly harmless data can identify people.'],
    ['Which fix supports privacy by design?', ['Private by default and collecting only what is needed', 'Sharing more data with analytics', 'Keeping all data forever'], 0, 'Defaults and data minimisation matter most.'],
  ],
  'attack-trees': [
    ['What does an OR branch in an attack tree mean?', ['Any one of the children is enough', 'All children are needed', 'The branch is optional for defenders'], 0, 'AND branches need every child.'],
    ['Why annotate leaves with cost or difficulty?', ['To find the cheapest, most likely attack path', 'To make the tree longer', 'To hide the root goal'], 0, 'Defend the cheapest paths first.'],
    ['In the example, what was the cheapest way past MFA?', ['Tricking the help desk into resetting it', 'Breaking the encryption', 'Guessing the code'], 0, 'People and processes are often the weakest branch.'],
  ],
  asvs: [
    ['What is OWASP ASVS?', ['A list of security requirements for verifying web apps and APIs', 'A web application firewall', 'A vulnerability scanner'], 0, 'It defines what to build and what to test.'],
    ['Which ASVS level suits most apps that handle sensitive data?', ['Level 2', 'Level 1', 'Level 3'], 0, 'L1 is the baseline, L3 is for the most critical systems.'],
    ['What should happen to a failed requirement?', ['It becomes a ticket, gets fixed and gets a test so it stays fixed', 'It is ignored until the next audit', 'It is removed from the standard'], 0, 'ASVS works best as living acceptance criteria.'],
  ],
  masvs: [
    ['Where should a mobile app store a refresh token?', ['In the Android Keystore or iOS Keychain', 'In a plain text file', 'In the app\'s log'], 0, 'Platform key stores are protected by the OS and often by hardware.'],
    ['What is OWASP MASTG?', ['The testing guide that explains how to test each MASVS control', 'A mobile antivirus', 'An app store'], 0, 'MASVS says what, MASTG says how to test it.'],
    ['Why must authentication decisions happen on the server?', ['The app runs on a device the user fully controls', 'Servers are faster', 'Phones can\'t do cryptography'], 0, 'A local "logged in" flag can be changed; a server-verified signature can\'t.'],
  ],

  /* ---- Penetration Testing ---- */
  /* ---- Cloud ---- */
  'imds-ssrf': [
    ['What address do cloud VMs use for the metadata service?', ['169.254.169.254', '127.0.0.1', '10.0.0.1'], 0, 'A link-local address reachable only from the instance itself.'],
    ['Why does IMDSv2 stop most SSRF attacks?', ['It needs a session token from a PUT request with a special header first', 'It encrypts the metadata', 'It blocks all HTTP'], 0, 'Typical SSRF can only send simple GET requests.'],
    ['What limits the damage if role credentials are stolen anyway?', ['A least-privilege instance role', 'A longer password', 'Turning off logging'], 0, 'The attacker only gets what the role can do.'],
  ],
  'public-bucket': [
    ['Which policy element made the bucket public?', ['"Principal": "*"', '"Effect": "Deny"', '"Version"'], 0, 'A wildcard principal means anyone.'],
    ['Which account-wide setting prevents public buckets?', ['S3 Block Public Access', 'Versioning', 'Lifecycle rules'], 0, 'It rejects public policies and ACLs.'],
    ['How should one invoice be shared safely?', ['A short-lived presigned URL after checking ownership', 'Make the bucket public', 'Email the bucket name'], 0, 'The bucket stays private.'],
  ],
  'cloud-iam-privesc': [
    ['Why is iam:PassRole on "*" dangerous?', ['It lets a user attach any role, even admin, to resources they create', 'It deletes users', 'It disables MFA'], 0, 'Code they create then runs with that role.'],
    ['What caps the permissions of roles a developer creates?', ['A permission boundary', 'A longer session', 'A new region'], 0, 'Boundaries limit maximum permissions.'],
    ['How should permissions be reviewed?', ['As combinations, looking for escalation paths', 'One at a time only', 'Never'], 0, 'Harmless permissions can combine into admin.'],
  ],
  'kubernetes-security': [
    ['What can a stolen pod service account token be used for?', ['Calling the Kubernetes API with that account\'s permissions', 'Logging into the cloud console', 'Nothing'], 0, 'Limit it with RBAC or don\'t mount it.'],
    ['What stops one pod from reaching every other pod?', ['Network policies', 'Labels', 'Bigger nodes'], 0, 'Default-deny then allow what\'s needed.'],
    ['Which setting makes escaping to the host much easier?', ['Running the pod as privileged', 'Using a read-only filesystem', 'Running as non-root'], 0, 'The restricted Pod Security Standard forbids it.'],
  ],
  'cloud-detection': [
    ['Where should audit logs be stored?', ['In a separate, locked-down log account', 'Only in the production account', 'On a developer laptop'], 0, 'So attackers in production can\'t delete them.'],
    ['Which attempted action should always trigger a critical alert?', ['Stopping CloudTrail logging', 'Reading a public web page', 'Listing your own profile'], 0, 'Attackers try to hide their tracks.'],
    ['What does a CSPM tool do?', ['Checks cloud settings against a security benchmark', 'Writes application code', 'Replaces backups'], 0, 'It finds risky settings before attackers do.'],
  ],

  /* ---- GRC ---- */
  'security-governance': [
    ['Which function did NIST CSF 2.0 add at the centre of the framework?', ['Govern', 'Encrypt', 'Audit'], 0, 'The six functions are Govern, Identify, Protect, Detect, Respond and Recover.'],
    ['Which document holds measurable requirements like "restore test every quarter"?', ['A standard', 'A policy', 'A guideline'], 0, 'Policies state intent; standards make it specific.'],
    ['How should a system that can\'t meet a standard yet be handled?', ['A documented exception with an owner and expiry date', 'Ignore it quietly', 'Delete the standard'], 0, 'Exceptions make risk explicit and temporary.'],
  ],
  'risk-assessment': [
    ['What two factors are combined to rate a risk?', ['Likelihood and impact', 'Cost and colour', 'Speed and size'], 0, 'Risk ≈ likelihood × impact.'],
    ['Buying cyber insurance is which risk treatment?', ['Transfer', 'Avoid', 'Mitigate'], 0, 'Part of the financial impact moves to the insurer.'],
    ['What is residual risk?', ['The risk that remains after treatment', 'Risk that never existed', 'A type of malware'], 0, 'It should be within the risk appetite.'],
  ],
  iso27001: [
    ['What does the Statement of Applicability record?', ['Which Annex A controls apply, why, and how they are implemented', 'The company\'s revenue', 'Employee holidays'], 0, 'It links risk decisions to controls.'],
    ['What happens in a stage 2 certification audit?', ['The auditor tests that the ISMS actually operates', 'Only the documents are read', 'The certificate is printed'], 0, 'Stage 1 is documents; stage 2 is operation.'],
    ['How long is an ISO/IEC 27001 certificate valid?', ['Three years, with yearly surveillance audits', 'Forever', 'One month'], 0, 'Recertification follows after three years.'],
  ],
  soc2: [
    ['What is the difference between SOC 2 Type I and Type II?', ['Type I is a point in time; Type II tests controls over a period', 'Type II is only for banks', 'They are identical'], 0, 'Type II shows controls actually ran.'],
    ['Which Trust Services Criterion is always included?', ['Security', 'Privacy', 'Processing Integrity'], 0, 'The others are optional.'],
    ['What is an "exception" in a SOC 2 report?', ['A sampled case where a control didn\'t operate as described', 'A special discount', 'A system outside scope'], 0, 'Customers read exceptions and management responses.'],
  ],
  'gdpr-breach': [
    ['How long does GDPR allow before notifying the supervisory authority of a reportable breach?', ['72 hours from becoming aware', '30 days', '1 year'], 0, 'Article 33; details can follow in phases.'],
    ['When must affected individuals be told directly?', ['When the breach is likely to cause a high risk to them', 'Never', 'Only if they ask'], 0, 'Article 34.'],
    ['Which breaches must be recorded internally?', ['All of them, even those not reported', 'Only reported ones', 'None'], 0, 'Accountability requires a breach register.'],
  ],
  'pci-dss': [
    ['What is the most effective way to reduce PCI DSS scope?', ['Keep card numbers out of your systems with hosted fields and tokens', 'Encrypt the logo', 'Add more servers'], 0, 'Systems that never see card data are largely out of scope.'],
    ['What does the store keep after tokenisation?', ['A token and the last four digits', 'The full card number and security code', 'Nothing about the order'], 0, 'A token is useless outside that provider.'],
    ['What do PCI DSS v4 requirements 6.4.3 and 11.6.1 address?', ['Scripts and tampering on payment pages', 'Office Wi-Fi', 'Password length'], 0, 'They target web skimming.'],
  ],
  'vendor-risk': [
    ['Why tier vendors?', ['So the depth of review matches the data and access they get', 'To rank them alphabetically', 'To pay them less'], 0, 'High-risk vendors get full reviews.'],
    ['Which evidence is stronger than a self-completed questionnaire?', ['An independent SOC 2 report or ISO 27001 certificate', 'A marketing brochure', 'A phone call'], 0, 'Independent auditors test the controls.'],
    ['What should happen when a vendor relationship ends?', ['Revoke access and confirm data deletion', 'Nothing', 'Keep their access just in case'], 0, 'Offboarding closes the loop.'],
  ],

  /* ---- DevSecOps ---- */
  'secure-pipeline': [
    ['What does SCA check?', ['Third-party dependencies for known vulnerabilities', 'The UI colours', 'Network speed'], 0, 'Software composition analysis.'],
    ['What is DAST?', ['Testing the running app from the outside', 'Reading source code', 'Scanning Terraform'], 0, 'Dynamic application security testing.'],
    ['Why fail builds only on high-confidence, high-severity findings?', ['Noisy gates get ignored or bypassed', 'Low issues don\'t exist', 'To save disk'], 0, 'Fast, trusted feedback works best.'],
  ],
  'secrets-leak': [
    ['A cloud key was pushed to a public repo. What do you do first?', ['Revoke the key', 'Delete the commit', 'Make the repo private'], 0, 'Copies already exist; only revocation stops use.'],
    ['How fast can leaked keys in public repos be abused?', ['Within minutes', 'After a few months', 'Never'], 0, 'Bots watch public commits continuously.'],
    ['What removes the need for stored CI keys?', ['Short-lived OIDC credentials', 'Longer keys', 'Base64 encoding'], 0, 'No long-lived secret exists to leak.'],
  ],
  'supply-chain': [
    ['What is dependency confusion?', ['A public package with an internal package\'s name gets installed instead', 'Two developers editing the same file', 'A slow download'], 0, 'Higher public versions can win if resolution isn\'t scoped.'],
    ['What does an SBOM provide?', ['A list of every component in a build', 'A firewall', 'A password'], 0, 'It shows quickly which apps include a bad package.'],
    ['Why pin CI actions and base images by digest?', ['Tags can be moved to point at different code', 'Digests are shorter', 'It\'s required by Git'], 0, 'A digest always refers to the exact same content.'],
  ],
  'cicd-oidc': [
    ['What does the CI job exchange for cloud credentials?', ['A signed OIDC identity token', 'A stored access key', 'A username and password'], 0, 'AssumeRoleWithWebIdentity verifies the token.'],
    ['Which trust policy condition is risky?', ['sub matching repo:acme/* or no sub check', 'sub equal to one repo and branch', 'Checking the audience'], 0, 'Wildcards let other repos assume the role.'],
    ['How long do OIDC-issued cloud credentials typically last?', ['Minutes to an hour', 'Forever', 'One year'], 0, 'Short-lived by design.'],
  ],

  'ethical-hacking': [
    ['What separates ethical hacking from a crime?', ['Written permission from the system owner', 'Good intentions', 'Using well-known tools'], 0, 'Unauthorised access is illegal whatever the intent.'],
    ['Which assessment tests whether the defenders can detect a realistic attacker?', ['A red team exercise', 'A vulnerability scan', 'A code review'], 0, 'Red teams are goal-based and test detection and response.'],
    ['You find real customer data during a test. What do you do?', ['Stop, take the minimum evidence and tell the client immediately', 'Download it all for the report', 'Wait for the final report'], 0, 'Minimise data and escalate critical issues at once.'],
  ],
  'recon-mapping': [
    ['Which public source lists hostnames from every issued TLS certificate?', ['Certificate Transparency logs', 'robots.txt', 'WHOIS only'], 0, 'CT logs record every publicly trusted certificate.'],
    ['What is the difference between passive and active recon?', ['Passive uses public sources; active sends traffic to the target', 'Passive is illegal', 'There is no difference'], 0, 'Active recon must stay inside the authorised scope.'],
    ['Why are forgotten hosts like api-old a priority?', ['They are often outdated and unmonitored', 'They are always faster', 'They have no data'], 0, 'Old assets are a favourite way in for attackers.'],
  ],
  'api-pentest': [
    ['What is BOLA?', ['Accessing another user\'s object by changing its ID', 'A slow API', 'A type of encryption'], 0, 'Broken Object Level Authorization is API1 in the OWASP API Top 10.'],
    ['A customer can call an admin-only refund endpoint. Which category is that?', ['BFLA (function-level authorization)', 'SSRF', 'Injection'], 0, 'API5 Broken Function Level Authorization.'],
    ['Why test old API versions like /v1?', ['They may still be live without current security fixes', 'They are faster', 'They are required by law'], 0, 'API9 Improper Inventory Management.'],
  ],
  'multitenant-pentest': [
    ['What is the most serious risk in a multi-tenant SaaS?', ['One tenant reaching another tenant\'s data', 'Slow page loads', 'Too many features'], 0, 'Cross-tenant access breaks the core promise of SaaS.'],
    ['Where should the app take the tenant from?', ['The authenticated session', 'An X-Tenant-ID header', 'The URL'], 0, 'Anything in the request can be changed by the user.'],
    ['Which is a strong safety net for tenant isolation?', ['Database row-level security', 'A bigger server', 'Hiding tenant IDs'], 0, 'It enforces isolation even if application code slips.'],
  ],
  'network-pentest': [
    ['What does an "assumed breach" internal test start with?', ['A network connection and one ordinary user account', 'Domain admin rights', 'Nothing at all'], 0, 'It models what happens after a successful phishing attack.'],
    ['What does BloodHound show?', ['Attack paths through Active Directory permissions', 'Open web ports', 'Email headers'], 0, 'It graphs how a user could reach admin rights.'],
    ['Which fix stops LLMNR-based credential capture?', ['Disable LLMNR and require SMB signing', 'Longer screen savers', 'More VLANs only'], 0, 'Both are standard hardening steps.'],
  ],
  'linux-privesc': [
    ['What usually enables privilege escalation on Linux?', ['Misconfiguration, like broad sudo rules', 'Always a zero-day exploit', 'Slow disks'], 0, 'Convenience shortcuts are the most common cause.'],
    ['Why was the writable cron script dangerous?', ['Root runs it, and anyone can edit it', 'It used too much CPU', 'It was too long'], 0, 'Whatever is added runs as root.'],
    ['How should a tester prove a privesc finding?', ['Harmlessly, then clean up', 'By deleting files', 'By leaving a backdoor'], 0, 'Prove impact without causing damage.'],
  ],
  'web-pentest': [
    ['What must be in place before any pen test starts?', ['Written authorisation with an agreed scope', 'A fast internet connection', 'A list of passwords'], 0, 'Testing without permission is illegal in most countries.'],
    ['Which guide lists web test cases like ATHN, ATHZ and INPV?', ['OWASP WSTG', 'OWASP MASVS', 'NIST CSF'], 0, 'The Web Security Testing Guide organises tests by category.'],
    ['What makes a finding useful to developers?', ['Clear impact, reproduction steps and a specific fix', 'A long list of tool output', 'Only a severity number'], 0, 'Reports should be specific and fixable.'],
  ],
  'burp-proxy': [
    ['Why must the test browser trust Burp\'s CA certificate?', ['So Burp can show HTTPS traffic without certificate errors', 'To speed up the browser', 'To bypass logins'], 0, 'Burp signs a certificate for each site with its own CA.'],
    ['What does setting the target scope do?', ['Limits recording and testing to authorised hosts', 'Blocks all websites', 'Encrypts traffic'], 0, 'It helps avoid testing third parties by accident.'],
    ['What did changing the price in an intercepted request show?', ['The server correctly used its own price', 'The app was hacked', 'Burp was broken'], 0, 'Servers must never trust client-supplied prices.'],
  ],
  'burp-workflow': [
    ['Which Burp tool is best for editing and resending one request by hand?', ['Repeater', 'Decoder', 'Sequencer'], 0, 'Repeater is the workhorse for confirming findings.'],
    ['How does Burp Collaborator help confirm SSRF?', ['It records DNS/HTTP requests the target server makes to a unique address', 'It scans ports', 'It decodes Base64'], 0, 'An interaction from the app server proves it fetched the URL.'],
    ['What should you do with scanner findings before reporting?', ['Confirm them by hand', 'Report them all as-is', 'Ignore them'], 0, 'Scanners produce false positives.'],
  ],
  'mobile-pentest': [
    ['What is the difference between static and dynamic analysis?', ['Static inspects the app package; dynamic watches it run', 'Static is only for iOS', 'They are the same'], 0, 'Good mobile tests use both.'],
    ['Why might an Android app\'s traffic not appear in Burp?', ['Android 7+ apps ignore user-installed CAs, and the app may pin certificates', 'Burp doesn\'t support Android', 'Phones don\'t use HTTP'], 0, 'A debug build that trusts the test CA is the cleanest fix.'],
    ['Where are the most serious mobile findings often found?', ['In the backend API', 'In the app icon', 'In the app store listing'], 0, 'The API holds the data; anyone can call it directly.'],
  ],

  /* ---- Identity & Access ---- */
  'oauth-pkce': [
    ['What does PKCE protect against?', ['A stolen authorization code being redeemed by another app', 'Weak passwords', 'Expired certificates'], 0, 'Without the original code_verifier, an intercepted code can\'t be exchanged for tokens.'],
    ['Why does the app send a random `state` value?', ['To stop an attacker slipping their own login into the user\'s session (login CSRF)', 'To pick the token format', 'To speed up the redirect'], 0, 'The app only accepts a callback whose state matches what it sent.'],
    ['Which grant is recommended for single-page and mobile apps today?', ['Authorization code with PKCE', 'Implicit grant', 'Password grant'], 0, 'Implicit and password grants are deprecated by current best practice.'],
  ],
  'saml-sso': [
    ['What makes a SAML assertion trustworthy to the app?', ['The IdP\'s digital signature, checked against a pinned certificate', 'It arrives over POST', 'It is XML'], 0, 'Without a correct signature check, anyone could write an assertion.'],
    ['Why check the Audience element?', ['To make sure the assertion was issued for this app, not another one', 'To find the user\'s email', 'To choose the binding'], 0, 'An assertion meant for a different app must not be accepted.'],
    ['What is the safest way to implement SAML in an app?', ['Use a well-maintained SAML library', 'Write your own XML signature parser', 'Skip signature checks behind a VPN'], 0, 'Most SAML bypasses come from hand-rolled or misconfigured validation.'],
  ],
  kerberos: [
    ['What does a user receive from the KDC at logon?', ['A ticket-granting ticket (TGT)', 'Their password hash', 'A TLS certificate'], 0, 'The TGT is later traded for service tickets.'],
    ['Does the file server contact the domain controller to check a service ticket?', ['No, it decrypts the ticket with its own key', 'Yes, every time', 'Only for admins'], 0, 'That\'s what makes Kerberos efficient.'],
    ['Which control best protects service accounts from offline cracking of their tickets?', ['Long random passwords or gMSA, with AES only', 'Shorter ticket lifetimes alone', 'Turning off logging'], 0, 'Strong keys make captured tickets useless to crack.'],
  ],
  'mfa-fatigue': [
    ['What does a burst of MFA denials for one user tell you?', ['Their password is probably known to an attacker', 'Their phone is broken', 'Nothing important'], 0, 'Prompts only appear after the password step succeeds.'],
    ['How does number matching help?', ['The user must type a number only visible on the real sign-in screen', 'It blocks all logins at night', 'It hides the app name'], 0, 'A prompt someone else triggered can\'t be approved by accident.'],
    ['Which MFA type makes push bombing impossible?', ['Phishing-resistant MFA like passkeys or FIDO2 keys', 'SMS codes', 'Security questions'], 0, 'There is no remote prompt to spam.'],
  ],
  'pam-jit': [
    ['What does "zero standing access" mean?', ['No one keeps permanent admin rights; access is granted when needed and expires', 'Admins share one password', 'Nobody can ever be an admin'], 0, 'Time-boxed access leaves attackers little to steal.'],
    ['Why does the broker inject the credential instead of showing it?', ['So the admin never sees or copies the password', 'To make logins faster', 'Because passwords are optional'], 0, 'And the password is rotated after the session.'],
    ['Which alert is a strong sign of a stolen admin credential?', ['An admin login that didn\'t go through the PAM broker', 'A request approved by a manager', 'A recorded session'], 0, 'Legitimate admin access should always be brokered.'],
  ],

  /* ---- Security Operations ---- */
  'phishing-triage': [
    ['Why did SPF pass on the phishing email?', ['It was sent from the attacker\'s own lookalike domain', 'SPF was broken', 'The email came from Microsoft'], 0, 'SPF only proves the server may send for that domain, not that the domain is legitimate.'],
    ['How should an analyst check a suspicious link?', ['In an isolated sandbox', 'By clicking it on their laptop', 'By forwarding it to colleagues'], 0, 'Detonation in a sandbox keeps the analyst and network safe.'],
    ['After confirming a phish, what should happen to the other copies?', ['Find and purge every copy from all mailboxes', 'Leave them; users will ignore them', 'Delete only the reported one'], 0, 'Scope first, then clean up everywhere.'],
  ],
  'edr-detection': [
    ['Why was the Excel → PowerShell chain suspicious?', ['Office apps rarely need to start encoded script interpreters', 'PowerShell is always malware', 'Excel files can\'t have macros'], 0, 'Behaviour, not a known-bad file, triggered the alert.'],
    ['What does host isolation do?', ['Cuts the device off the network except for the EDR console', 'Deletes all files', 'Shuts the device down'], 0, 'The attacker loses access while the analyst can still investigate.'],
    ['What was the program trying to do by reading LSASS memory?', ['Steal logon credentials', 'Update Windows', 'Print a document'], 0, 'LSASS holds logon secrets, so access to it is closely watched.'],
  ],
  'incident-response': [
    ['Which phase comes right after detection and analysis?', ['Containment', 'Lessons learned', 'Preparation'], 0, 'Stop the spread before the full clean-up.'],
    ['Why preserve memory and disk before reimaging?', ['Evidence is lost once the system is wiped', 'It makes the server faster', 'It is required by DNS'], 0, 'You need it to understand scope and root cause.'],
    ['What made recovery possible without paying anyone?', ['Immutable backups the attacker couldn\'t reach', 'Antivirus', 'Turning the server off and on'], 0, 'Offline or immutable, tested backups are the ransomware safety net.'],
  ],
  'threat-hunting': [
    ['What does a threat hunt start with?', ['A hypothesis about attacker behaviour', 'An existing alert', 'A random IP list'], 0, 'Hunting looks for what alerts haven\'t caught.'],
    ['Which two signals pointed to beaconing?', ['A rare domain contacted at very regular intervals', 'Large downloads during work hours', 'Many users visiting a news site'], 0, 'Implants on timers are regular; people are not.'],
    ['What should a successful hunt produce besides an incident?', ['A new automatic detection', 'Nothing else', 'A firewall reboot'], 0, 'So the same thing is caught automatically next time.'],
  ],
  'soar-playbook': [
    ['What does a SOAR playbook usually do first?', ['Enrich the alert with lookups', 'Disable every account', 'Delete the alert'], 0, 'Context makes the decision fast and consistent.'],
    ['Which actions should need human approval?', ['High-impact or disruptive ones', 'All lookups', 'None at all'], 0, 'Automation is great for low-risk steps; people decide the big ones.'],
    ['Why test playbooks regularly?', ['A changed API or permission can silently break them', 'To use more storage', 'It is not needed'], 0, 'A broken playbook can fail quietly when you need it.'],
  ],
};
