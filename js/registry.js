/*
 * Security Explorer — module registry.
 * Every module file calls SE.register({...}). See CONTRIBUTING.md for the schema.
 */
window.SE = (() => {
  const domains = [
    { id: 'protocols', name: 'Internet Protocols', short: 'Protocols', icon: 'dns',
      blurb: 'How the internet actually works: DNS, TCP, HTTP, SSH, email and more, message by message, with the security notes for each.' },
    { id: 'web', name: 'Web Application Security', short: 'Web', icon: 'browser',
      blurb: 'How web apps get broken: injection, XSS, CSRF, SSRF, access-control flaws and how to fix them.' },
    { id: 'api', name: 'API Security', short: 'API', icon: 'api',
      blurb: 'Authorization gaps, mass assignment, missing limits and webhook spoofing, based on the OWASP API Top 10.' },
    { id: 'appsec', name: 'Secure Development', short: 'AppSec', icon: 'repo',
      blurb: 'Building security in from the start: threat modelling with STRIDE, PASTA, LINDDUN and attack trees, and the OWASP ASVS and MASVS standards for verifying web and mobile apps.' },
    { id: 'pentest', name: 'Penetration Testing', short: 'Pentest', icon: 'shell',
      blurb: 'How professional testers assess web and mobile apps: methodology, scoping, Burp Suite workflows and reporting. Only ever test with written permission.' },
    { id: 'network', name: 'Network Security', short: 'Network', icon: 'router',
      blurb: 'Reconnaissance, spoofing, man-in-the-middle and denial-of-service on the wire.' },
    { id: 'identity', name: 'Identity & Access', short: 'Identity', icon: 'idp',
      blurb: 'Identity and access management (IAM): OAuth, SAML, Kerberos, MFA and privileged access, and how attackers abuse weak logins.' },
    { id: 'crypto', name: 'Cryptography', short: 'Crypto', icon: 'lock',
      blurb: 'TLS, key exchange, certificates and password storage, step by step.' },
    { id: 'cloud', name: 'Cloud Security', short: 'Cloud', icon: 'cloud',
      blurb: 'Metadata theft, exposed storage and IAM privilege escalation in the cloud.' },
    { id: 'threats', name: 'Threats & Malware', short: 'Threats', icon: 'attacker',
      blurb: 'Phishing, ransomware, command-and-control and software supply-chain attacks.' },
    { id: 'defense', name: 'Defense & Blue Team', short: 'Defense', icon: 'shield',
      blurb: 'WAFs, IDS, SIEM and Zero Trust: how defenders see and stop attacks.' },
    { id: 'soc', name: 'Security Operations (SOC)', short: 'SOC', icon: 'siem',
      blurb: 'How a security operations center works: phishing triage, EDR, incident response, threat hunting and automation.' },
    { id: 'ai', name: 'AI & LLM Security', short: 'AI', icon: 'ai',
      blurb: 'How LLM apps, agents and MCP tool connections work, how prompt injection and unsafe output break them, and how to build guardrails.' },
  ];

  // Packet colour categories used in the diagram, sequence view and table.
  const kinds = {
    req: { label: 'Request' },
    res: { label: 'Response' },
    ctl: { label: 'Handshake / control' },
    atk: { label: 'Malicious' },
    data: { label: 'Sensitive data' },
    def: { label: 'Defense / blocked' },
  };

  // Curated, ordered tracks. Module ids that don't exist yet are skipped automatically.
  const paths = [
    { id: 'networking', level: 'Beginner', title: 'Networking fundamentals',
      desc: 'What happens between typing a URL and seeing a page: switching, addressing, routing, transport, names and the web.',
      modules: ['ethernet', 'dhcp', 'ip-routing', 'icmp', 'tcp', 'udp', 'dns', 'http', 'tls13'] },
    { id: 'app-protocols', level: 'Beginner', title: 'Everyday application protocols',
      desc: 'The protocols behind email, remote access, file transfer, real-time apps, clocks and internet routing.',
      modules: ['smtp', 'imap', 'ssh', 'ftp', 'websocket', 'quic', 'ntp', 'bgp'] },
    { id: 'web-fundamentals', level: 'Beginner', title: 'Web application fundamentals',
      desc: 'The bugs behind most web breaches, from injection to broken access control. Start here if you build or test websites.',
      modules: ['sqli', 'xss-reflected', 'xss-stored', 'csrf', 'idor', 'path-traversal', 'cmdi', 'ssrf'] },
    { id: 'apis', level: 'Beginner', title: 'Securing APIs',
      desc: 'How a well-protected API call works, and the authorization and abuse problems that show up most in real APIs.',
      modules: ['api-gateway', 'idor', 'mass-assignment', 'bfla', 'api-rate-limit', 'webhook-hmac'] },
    { id: 'secure-dev', level: 'Intermediate', title: 'Secure development lifecycle',
      desc: 'Design securely with threat modelling, verify web apps against OWASP ASVS and mobile apps against OWASP MASVS, then check the bugs those standards prevent.',
      modules: ['threat-modeling', 'attack-trees', 'pasta', 'linddun', 'asvs', 'masvs', 'sqli', 'xss-stored', 'idor', 'oauth-pkce'] },
    { id: 'pentester', level: 'Intermediate', title: 'Web and mobile pen testing',
      desc: 'How an authorised pen test runs, how to use Burp Suite, and the bugs testers find most often in web and mobile apps.',
      modules: ['web-pentest', 'burp-proxy', 'burp-workflow', 'idor', 'sqli', 'xss-reflected', 'ssrf', 'mobile-pentest', 'masvs'] },
    { id: 'ai-apps', level: 'Intermediate', title: 'Building secure AI apps',
      desc: 'How LLM apps, agents and MCP servers are put together, where prompt injection and unsafe output come in, and how to contain them.',
      modules: ['rag-pipeline', 'prompt-injection', 'indirect-injection', 'llm-output', 'mcp-protocol', 'mcp-tool-poisoning', 'ai-guardrails'] },
    { id: 'crypto', level: 'Beginner', title: 'Cryptography essentials',
      desc: 'What actually happens when you see the padlock, and how passwords should be stored.',
      modules: ['diffie-hellman', 'tls13', 'cert-chain', 'password-storage'] },
    { id: 'network', level: 'Intermediate', title: 'Network attacks and detection',
      desc: 'Reconnaissance, spoofing and denial of service on the wire, and how a sensor picks them up.',
      modules: ['port-scan', 'arp-spoof', 'dns-spoof', 'syn-flood', 'evil-twin', 'ids'] },
    { id: 'blue-team', level: 'Intermediate', title: 'Blue team basics',
      desc: 'Controls and workflows defenders rely on every day, from the edge to the SOC.',
      modules: ['waf', 'ids', 'siem', 'zero-trust'] },
    { id: 'iam', level: 'Intermediate', title: 'Identity and access (IAM)',
      desc: 'How modern login and single sign-on work, why MFA can still be beaten, and how to lock down admin access.',
      modules: ['oauth-pkce', 'saml-sso', 'kerberos', 'mfa-fatigue', 'pam-jit', 'zero-trust'] },
    { id: 'soc-analyst', level: 'Intermediate', title: 'SOC analyst essentials',
      desc: 'A day in the SOC: from logs and alerts to investigations, containment, hunting and automation.',
      modules: ['siem', 'phishing-triage', 'edr-detection', 'incident-response', 'threat-hunting', 'soar-playbook'] },
  ];

  const modules = [];

  function register(m) {
    const ids = new Set(m.nodes.map((n) => n.id));
    m.steps.forEach((s, i) => {
      s.packets = (s.packets || []).map((p) =>
        Array.isArray(p)
          ? { f: p[0], t: p[1], proto: p[2], info: p[3], size: p[4], kind: p[5] || 'req', raw: p[6] }
          : p
      );
      s.packets.forEach((p) => {
        if (!ids.has(p.f) || !ids.has(p.t)) console.warn(`[${m.id}] step ${i + 1}: unknown node in packet`, p);
        if (!kinds[p.kind]) console.warn(`[${m.id}] step ${i + 1}: unknown packet kind "${p.kind}"`);
      });
    });
    if (modules.some((x) => x.id === m.id)) console.warn(`Duplicate module id "${m.id}"`);
    modules.push(m);
  }

  return { domains, kinds, paths, modules, register };
})();
