/* Domain: Cryptography */

SE.register({
  id: 'tls13', domain: 'crypto', kind: 'protocol', level: 'Beginner', severity: 'Protocol',
  name: 'TLS 1.3 Handshake', full: 'How HTTPS sets up an encrypted channel',
  tags: ['tls', 'https', 'ssl', 'handshake', 'ecdhe', 'x25519'],
  summary: 'TLS is the "S" in HTTPS. In a single round trip the client and server agree on keys, the server proves its identity with a certificate, and everything after that is encrypted and tamper-proof.',
  facts: [['Defined in', 'RFC 8446'], ['Port', '443 (HTTPS)'], ['Round trips', '1-RTT (0-RTT optional)'], ['Key exchange', 'ECDHE (X25519, P-256)'], ['Ciphers', 'AES-GCM, ChaCha20-Poly1305'], ['Removed vs 1.2', 'RSA key exchange, CBC, SHA-1']],
  defenses: [
    'Disable TLS 1.0/1.1; prefer 1.3, allow 1.2 with AEAD ciphers only',
    'Use certificates from a trusted CA and automate renewal (ACME)',
    'Send HSTS so browsers never fall back to plain HTTP',
    'Be careful with 0-RTT data: it can be replayed, so use it only for idempotent requests',
  ],
  nodes: [
    { id: 'c', type: 'browser', label: 'Browser', sub: '192.168.1.10', x: 140, y: 245 },
    { id: 's', type: 'server', label: 'Web Server', sub: 'example.com', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'TCP connection', sub: 'A reliable pipe first',
      text: 'TLS runs on top of TCP, so the usual three-way handshake comes first. (HTTP/3 uses QUIC instead, which builds TLS 1.3 in.)',
      fields: [['Port', '443'], ['Transport', 'TCP']],
      packets: [
        ['c', 's', 'TCP', '52344 → 443 [SYN]', 66, 'ctl'],
        ['s', 'c', 'TCP', '443 → 52344 [SYN, ACK]', 66, 'ctl'],
        ['c', 's', 'TCP', '52344 → 443 [ACK]', 54, 'ctl'],
      ],
    },
    {
      title: 'ClientHello', sub: 'Offering options and a key share',
      text: 'The browser lists the TLS versions and cipher suites it supports, names the site it wants (SNI), and optimistically sends its half of a key exchange: a fresh, one-time `key_share` public key.',
      fields: [['SNI', 'example.com'], ['key_share', 'X25519 public key (32 bytes)']],
      packets: [
        ['c', 's', 'TLS', 'ClientHello (TLS 1.3, AES-128-GCM, ChaCha20, key_share X25519, SNI=example.com)', 517, 'ctl',
          `Handshake Type: ClientHello
  supported_versions: TLS 1.3, TLS 1.2
  cipher_suites: TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256
  server_name: example.com
  supported_groups: x25519, secp256r1
  key_share: x25519 <32-byte ephemeral public key>
  signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256`],
      ],
    },
    {
      title: 'ServerHello + encrypted', sub: 'Keys agreed, then proof of identity',
      text: 'The server picks a cipher and sends its own `key_share`. Both sides can now compute the same secret, so everything after ServerHello is already encrypted, including the certificate. The server signs the handshake transcript (`CertificateVerify`) to prove it holds the certificate\'s private key.',
      fields: [['Cipher', 'TLS_AES_128_GCM_SHA256'], ['Encrypted from', 'EncryptedExtensions onward']],
      packets: [
        ['s', 'c', 'TLS', 'ServerHello (key_share X25519)', 122, 'ctl'],
        ['s', 'c', 'TLS', '{EncryptedExtensions} {Certificate} {CertificateVerify} {Finished}', 3100, 'res'],
      ],
    },
    {
      title: 'Client verifies & finishes', sub: 'Trust check',
      text: 'The browser checks the certificate chain up to a trusted root, checks the hostname, and verifies the signature. Then it sends its own `Finished` message, a MAC over the whole handshake, so any tampering would be detected.',
      fields: [['Checks', 'Chain, hostname, validity, signature'], ['See also', 'Certificate Chain module']],
      packets: [
        ['c', 'c', 'X.509', 'Validate certificate chain + CertificateVerify signature', 0, 'def'],
        ['c', 's', 'TLS', '{Finished}', 74, 'ctl'],
      ],
    },
    {
      title: 'Application data', sub: 'Encrypted HTTP',
      text: 'HTTP now flows inside encrypted, authenticated records. An eavesdropper sees only sizes, timing and the server\'s IP, not URLs, cookies or content. Because the keys were ephemeral, recording traffic now and stealing the server key later still won\'t decrypt it (forward secrecy).',
      fields: [['Total setup', '1 round trip'], ['Property', 'Forward secrecy']],
      packets: [
        ['c', 's', 'TLS', 'Application Data (encrypted HTTP GET /)', 610, 'req'],
        ['s', 'c', 'TLS', 'Application Data (encrypted HTTP 200 OK)', 14200, 'res'],
      ],
    },
  ],
});

SE.register({
  id: 'diffie-hellman', domain: 'crypto', kind: 'protocol', level: 'Beginner', severity: 'Protocol',
  name: 'Diffie-Hellman', full: 'Agreeing on a secret over a public channel',
  tags: ['dh', 'ecdh', 'key exchange', 'modular arithmetic', 'forward secrecy'],
  summary: 'Diffie-Hellman lets two parties who have never met create a shared secret while an eavesdropper watches every message. It\'s the core of key exchange in TLS, SSH, Signal and WireGuard. Here it is with tiny numbers you can check by hand.',
  facts: [['Published', '1976 (Diffie & Hellman)'], ['Hard problem', 'Discrete logarithm'], ['Modern form', 'ECDH (X25519)'], ['Used in', 'TLS, SSH, IPsec, WireGuard, Signal'], ['Needs', 'Authentication against MITM'], ['Toy numbers', 'p = 23, g = 5']],
  defenses: [
    'Use ephemeral keys (DHE/ECDHE) for forward secrecy',
    'Use standard groups: X25519, P-256, or ≥2048-bit finite-field groups',
    'Always authenticate the exchange (certificates, signatures, pinned keys); plain DH is open to man-in-the-middle',
    'Validate received public values (reject 0, 1, p−1 and small-subgroup points)',
  ],
  nodes: [
    { id: 'a', type: 'user', label: 'Alice', sub: 'secret a = 6', x: 140, y: 200 },
    { id: 'b', type: 'user', label: 'Bob', sub: 'secret b = 15', x: 760, y: 200 },
    { id: 'e', type: 'ids', label: 'Eve (listening)', sub: 'sees all public values', x: 450, y: 400, evil: true },
  ],
  steps: [
    {
      title: 'Public parameters', sub: 'Everyone knows p and g',
      text: 'Alice and Bob agree on a prime `p = 23` and a base `g = 5`. These are public, and Eve sees them too.',
      fields: [['p', '23'], ['g', '5']],
      packets: [
        ['a', 'b', 'DH', 'Parameters p = 23, g = 5', 16, 'ctl'],
        ['a', 'e', 'Tap', 'Eve copies: p = 23, g = 5', 16, 'data'],
      ],
    },
    {
      title: 'Private secrets', sub: 'Never sent anywhere',
      text: 'Each side picks a random private number and keeps it to themselves. Alice picks `a = 6`, Bob picks `b = 15`. In real systems these are 256-bit or larger random values.',
      fields: [['Alice', 'a = 6 (private)'], ['Bob', 'b = 15 (private)']],
      packets: [
        ['a', 'a', 'Local', 'Pick private a = 6', 0, 'ctl'],
        ['b', 'b', 'Local', 'Pick private b = 15', 0, 'ctl'],
      ],
    },
    {
      title: 'Exchange public values', sub: 'g^secret mod p',
      text: 'Alice sends `A = 5^6 mod 23 = 8`. Bob sends `B = 5^15 mod 23 = 19`. Eve sees both numbers.',
      fields: [['A', '5^6 mod 23 = 8'], ['B', '5^15 mod 23 = 19']],
      packets: [
        ['a', 'b', 'DH', 'A = 8', 16, 'req'],
        ['b', 'a', 'DH', 'B = 19', 16, 'res'],
        ['a', 'e', 'Tap', 'Eve copies: A = 8, B = 19', 16, 'data'],
      ],
    },
    {
      title: 'Same secret, both sides', sub: 'The magic step',
      text: 'Alice computes `B^a mod p = 19^6 mod 23 = 2`. Bob computes `A^b mod p = 8^15 mod 23 = 2`. Both equal `g^(a·b) mod p`, so they share the secret `2` without ever sending it.',
      fields: [['Alice', '19^6 mod 23 = 2'], ['Bob', '8^15 mod 23 = 2']],
      packets: [
        ['a', 'a', 'Local', 'K = 19^6 mod 23 = 2', 0, 'def'],
        ['b', 'b', 'Local', 'K = 8^15 mod 23 = 2', 0, 'def'],
      ],
    },
    {
      title: "Eve's problem", sub: 'And the one real weakness',
      text: 'Eve knows p, g, A and B, but to get the secret she must recover `a` from `5^a mod 23 = 8`: the discrete logarithm. With toy numbers that\'s easy; with X25519 or 2048-bit groups it\'s infeasible. Plain DH doesn\'t prove *who* you\'re talking to, though. An active attacker could run separate exchanges with each side, which is why TLS signs the exchange with a certificate.',
      fields: [['Passive eavesdropper', 'Defeated'], ['Active MITM', 'Needs authentication']],
      defend: 'Never use unauthenticated key exchange for anything that matters.',
      packets: [
        ['e', 'e', 'Local', 'Must solve 5^a ≡ 8 (mod 23): infeasible at real key sizes', 0, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'cert-chain', domain: 'crypto', kind: 'protocol', level: 'Intermediate', severity: 'Protocol',
  name: 'Certificate Chains', full: 'How browsers decide to trust a site',
  tags: ['pki', 'x509', 'certificate', 'ca', 'ocsp', 'certificate transparency'],
  summary: 'A TLS certificate is only trusted if it links, signature by signature, to a root certificate already in the browser\'s trust store. This module walks through the checks a browser runs before showing the padlock.',
  facts: [['Standard', 'X.509 v3 (RFC 5280)'], ['Chain', 'Leaf → Intermediate → Root'], ['Root keys', 'Kept offline by CAs'], ['Revocation', 'OCSP stapling, CRLs'], ['Transparency', 'CT logs (SCTs)'], ['Typical leaf life', '≤ 398 days, trending shorter']],
  defenses: [
    'Automate issuance and renewal (ACME / Let\'s Encrypt) to avoid expiry outages',
    'Always send the full intermediate chain from the server',
    'Enable OCSP stapling',
    'Monitor Certificate Transparency logs for certificates issued for your domains',
    'Use CAA DNS records to limit which CAs may issue for you',
  ],
  nodes: [
    { id: 'br', type: 'browser', label: 'Browser', sub: 'trust store', x: 140, y: 245 },
    { id: 'srv', type: 'server', label: 'Web Server', sub: 'www.example.com', x: 770, y: 245 },
    { id: 'int', type: 'cert', label: 'Intermediate CA', sub: 'Example Issuing CA', x: 455, y: 100 },
    { id: 'root', type: 'cert', label: 'Root CA', sub: 'in OS/browser store', x: 455, y: 390, good: true },
  ],
  steps: [
    {
      title: 'Server sends its chain', sub: 'Leaf + intermediate',
      text: 'During the TLS handshake the server sends its own (leaf) certificate plus the intermediate that signed it. The root is not sent; the browser must already have it.',
      fields: [['Leaf', 'CN/SAN = www.example.com'], ['Sent chain', 'Leaf, Intermediate']],
      packets: [
        ['br', 'srv', 'TLS', 'ClientHello SNI=www.example.com', 517, 'ctl'],
        ['srv', 'br', 'TLS', '{Certificate} leaf + intermediate', 3400, 'res',
          `Certificate[0] (leaf)
  Subject:  CN=www.example.com
  SAN:      www.example.com, example.com
  Issuer:   CN=Example Issuing CA
  Validity: 2026-09-01 → 2026-11-30
  Key Usage: digitalSignature   EKU: serverAuth
Certificate[1] (intermediate)
  Subject:  CN=Example Issuing CA
  Issuer:   CN=Example Root CA
  Basic Constraints: CA=TRUE, pathlen=0`],
      ],
    },
    {
      title: 'Check the leaf', sub: 'Is it for this site, right now?',
      text: 'The browser checks that a Subject Alternative Name matches the hostname in the URL, that today is inside the validity period, and that the certificate is allowed to be used for server authentication.',
      fields: [['Hostname', 'www.example.com ✓'], ['Dates', 'Valid ✓'], ['EKU', 'serverAuth ✓']],
      packets: [
        ['br', 'br', 'X.509', 'SAN match, validity period, key usage', 0, 'def'],
      ],
    },
    {
      title: 'Walk the chain', sub: 'Signature by signature',
      text: 'The leaf\'s signature is verified with the intermediate\'s public key. The intermediate\'s signature is verified with the root\'s public key. The root is trusted because it ships in the operating system or browser store.',
      fields: [['Leaf', 'signed by Intermediate ✓'], ['Intermediate', 'signed by Root ✓ (CA=TRUE)']],
      packets: [
        ['br', 'int', 'Verify', "Leaf signature checks out with Intermediate's public key", 0, 'def'],
        ['br', 'root', 'Verify', "Intermediate signature checks out with Root's public key", 0, 'def'],
        ['root', 'br', 'Trust', 'Root found in trust store → anchor reached', 0, 'def'],
      ],
    },
    {
      title: 'Revocation & transparency', sub: 'Was it revoked? Is it public?',
      text: 'The server staples a fresh signed OCSP response saying the certificate is not revoked. The certificate also carries Signed Certificate Timestamps proving it was logged in public Certificate Transparency logs, so mis-issued certificates can be spotted.',
      fields: [['OCSP', 'good (stapled)'], ['SCTs', '2 logs ✓']],
      packets: [
        ['srv', 'br', 'TLS', 'Stapled OCSP response: status=good', 1500, 'res'],
        ['br', 'br', 'CT', 'Embedded SCTs verified', 0, 'def'],
      ],
    },
    {
      title: 'When a check fails', sub: 'The warning page',
      text: 'If any check fails (wrong hostname, expired, unknown root, revoked), the browser stops and shows a full-page warning. Clicking through it defeats the point of TLS, because this is exactly what a man-in-the-middle looks like.',
      fields: [['Wrong host', 'ERR_CERT_COMMON_NAME_INVALID'], ['Expired', 'ERR_CERT_DATE_INVALID'], ['Unknown CA', 'ERR_CERT_AUTHORITY_INVALID']],
      defend: 'With HSTS enabled, browsers don\'t offer users a way to click through certificate errors at all.',
      packets: [
        ['br', 'srv', 'TLS', 'Alert: bad_certificate, connection closed', 31, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'password-storage', domain: 'crypto', kind: 'defense', level: 'Beginner', severity: 'Best practice',
  name: 'Password Storage', full: 'Salted, slow hashing with Argon2id',
  tags: ['hashing', 'argon2', 'bcrypt', 'salt', 'pepper', 'passwords'],
  summary: 'Servers should never be able to read users\' passwords. They store a slow, salted hash instead, so that if the database ever leaks, attackers face years of work per password rather than a ready-made list.',
  facts: [['CWE', 'CWE-916'], ['OWASP', 'A02:2021 Cryptographic Failures'], ['Recommended', 'Argon2id, scrypt, bcrypt'], ['Never use', 'Plain text, MD5, SHA-1/256 alone'], ['Salt', 'Unique random value per user'], ['Guidance', 'OWASP Password Storage Cheat Sheet']],
  defenses: [
    'Hash with Argon2id (or bcrypt/scrypt) and tune the cost for ~100 ms per hash',
    'Use a unique random salt per password (libraries do this for you)',
    'Optionally add a pepper kept outside the database (e.g. in a KMS)',
    'Check new passwords against known-breached lists',
    'Add MFA; a strong hash protects stored data, not phished logins',
    'Rehash with stronger settings when users next log in',
  ],
  nodes: [
    { id: 'u', type: 'user', label: 'User', sub: 'alice', x: 130, y: 245 },
    { id: 'app', type: 'server', label: 'App Server', sub: 'auth service', x: 450, y: 245 },
    { id: 'db', type: 'db', label: 'User DB', sub: 'password_hash column', x: 780, y: 245 },
  ],
  steps: [
    {
      title: 'Sign-up', sub: 'Hash before storing',
      text: 'The password arrives over TLS. The server generates a random salt and runs Argon2id, a deliberately slow, memory-hungry function. Only the resulting string (algorithm, settings, salt and hash) is saved.',
      fields: [['Algorithm', 'Argon2id m=64 MiB, t=3, p=4'], ['Stored', 'Hash string, never the password']],
      packets: [
        ['u', 'app', 'HTTPS', 'POST /signup (password over TLS)', 640, 'req'],
        ['app', 'app', 'Argon2id', 'hash(password, random 16-byte salt) ≈ 100 ms', 0, 'def'],
        ['app', 'db', 'SQL', 'INSERT users (name, password_hash) VALUES (?, ?)', 220, 'req',
          `password_hash = $argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQxMjM0NTY$
                 4vT1x0x0Yk7j3m0bQf1Q8bS7rKcF6yq2nQm1v7uYp0A
   (algorithm $ version $ cost settings $ salt $ hash)`],
        ['app', 'u', 'HTTPS', '201 Created', 180, 'res'],
      ],
    },
    {
      title: 'Login', sub: 'Recompute and compare',
      text: 'At login the server loads the stored string, re-runs Argon2id on the typed password with the same salt and settings, and compares the results in constant time. The real password is never stored or logged.',
      fields: [['Compare', 'Constant-time'], ['Result', 'Match → session issued']],
      packets: [
        ['u', 'app', 'HTTPS', 'POST /login (password over TLS)', 600, 'req'],
        ['app', 'db', 'SQL', 'SELECT password_hash FROM users WHERE name = ?', 90, 'req'],
        ['db', 'app', 'SQL', '$argon2id$v=19$m=65536,t=3,p=4$…', 140, 'res'],
        ['app', 'app', 'Argon2id', 'verify(password, stored) → true', 0, 'def'],
        ['app', 'u', 'HTTPS', '200 OK Set-Cookie: session=…; HttpOnly; Secure', 420, 'res'],
      ],
    },
    {
      title: 'Why salt?', sub: 'Same password, different hashes',
      text: 'Because every user has a different salt, two people using `Summer2026!` get completely different hashes. Precomputed lookup tables are useless, and each account has to be attacked separately.',
      fields: [['alice', '…$c29tZXNhbHQ…$4vT1x0…'], ['bob (same password)', '…$Zm9vYmFyMTI…$Qm9i9z…']],
      packets: [
        ['app', 'app', 'Salt', 'Same password + different salts → unrelated hashes', 0, 'def'],
      ],
    },
    {
      title: 'Why slow?', sub: 'Cost is the defense',
      text: '~100 ms per login is invisible to a user but multiplies the cost of every guess for someone holding a leaked database. Fast hashes like MD5 or plain SHA-256 were built for speed, which is exactly the wrong property here. Memory-hard Argon2id also blunts GPU and ASIC speed-ups.',
      fields: [['Fast hash', 'Built for speed: wrong tool'], ['Argon2id', 'Slow + memory-hard: right tool']],
      defend: 'Store the cost settings with each hash (as Argon2 does) so you can raise them over time.',
      packets: [
        ['app', 'app', 'Policy', 'Tune cost so one hash ≈ 100 ms on production hardware', 0, 'def'],
      ],
    },
  ],
});
