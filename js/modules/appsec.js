/* Domain: Secure Development (threat modelling, OWASP ASVS, OWASP MASVS) */

SE.register({
  id: 'threat-modeling', domain: 'appsec', kind: 'defense', level: 'Beginner', severity: 'Process',
  name: 'Threat Modelling (STRIDE)', full: 'Finding design flaws before writing code',
  tags: ['threat modeling', 'threat modelling', 'stride', 'data flow diagram', 'dfd', 'trust boundary', 'secure design', 'appsec', 'sdlc'],
  summary: 'Threat modelling is a structured way to ask "what could go wrong?" while a feature is still being designed, when fixes are cheapest. You draw how data flows, mark where trust changes, walk each flow through the STRIDE categories, and turn the answers into concrete requirements and tests. STRIDE is the most widely used method; PASTA (risk-centric), LINDDUN (privacy) and attack trees (attack paths) are covered in their own modules.',
  facts: [['Four questions', 'What are we building? What can go wrong? What will we do? Did we do a good job?'], ['Model', 'Data flow diagram + trust boundaries'], ['Threat categories', 'STRIDE'], ['Other methods', 'PASTA, LINDDUN, attack trees, OCTAVE, VAST, Trike'], ['Free tools', 'OWASP Threat Dragon, Microsoft TM Tool'], ['Relates to', 'OWASP A04 Insecure Design']],
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
  id: 'pasta', domain: 'appsec', kind: 'defense', level: 'Advanced', severity: 'Process',
  name: 'Threat Modelling (PASTA)', full: 'Risk-centric threat modelling in seven stages',
  tags: ['pasta', 'threat modeling', 'threat modelling', 'risk', 'attack simulation', 'business impact', 'appsec'],
  summary: 'PASTA (Process for Attack Simulation and Threat Analysis) is a risk-centric method. Where STRIDE asks "what kinds of things can go wrong?", PASTA starts from business goals, studies how real attackers operate, simulates their attacks against your design, and ranks threats by business impact. It takes more effort and suits high-value systems.',
  facts: [['Full name', 'Process for Attack Simulation and Threat Analysis'], ['Authors', 'Tony UcedaVélez & Marco Morana (2015)'], ['Stages', '7, from business objectives to risk'], ['Focus', 'Attacker view + business impact'], ['Best for', 'High-value, regulated systems'], ['Compared with STRIDE', 'Heavier, more risk-driven']],
  defenses: [
    'Involve business owners early: impact on the business drives the ranking',
    'Use real threat intelligence for the attacker view, not guesses',
    'Map threats to concrete weaknesses (CWE) and to attack techniques (ATT&CK)',
    'Simulate attacks with attack trees or tests to see which ones actually work',
    'Feed the ranked risks into the backlog and the risk register',
  ],
  nodes: [
    { id: 'biz', type: 'user', label: 'Business Owner', sub: 'payments product', x: 120, y: 120 },
    { id: 'tm', type: 'user', label: 'Threat Modeller', sub: 'security team', x: 120, y: 380, good: true },
    { id: 'app', type: 'server', label: 'Payments Platform', sub: 'web + API', x: 450, y: 245 },
    { id: 'ti', type: 'cloud', label: 'Threat Intel', sub: 'attacker behaviour', x: 780, y: 120 },
    { id: 'atk', type: 'attacker', label: 'Fraud Group', sub: 'simulated', x: 780, y: 380 },
  ],
  steps: [
    {
      title: 'Stage 1: Business objectives', sub: 'What must not go wrong?',
      text: 'The modeller starts with the business, not the technology. For a payments platform: no fraudulent transfers, stay compliant with PCI DSS, and keep the service available during peak hours. These goals decide later what counts as a high risk.',
      fields: [['Objectives', 'No fraud, PCI DSS compliance, 99.95% uptime'], ['Impact of failure', 'Financial loss, fines, reputation']],
      packets: [
        ['biz', 'tm', 'Workshop', 'Business goals, compliance needs, risk appetite', 900, 'ctl'],
      ],
    },
    {
      title: 'Stage 2: Technical scope', sub: 'What is in the system?',
      text: 'Next the team lists the technology in scope: web front end, transfer API, database, third-party fraud scoring service and the cloud platform underneath, along with versions and dependencies.',
      fields: [['Components', 'Web app, transfer API, DB, fraud API, cloud'], ['Out of scope', 'Corporate email, HR systems']],
      packets: [
        ['tm', 'app', 'Inventory', 'List components, frameworks, versions, dependencies', 600, 'req'],
        ['app', 'tm', 'Inventory', 'Architecture + dependency list', 4000, 'res'],
      ],
    },
    {
      title: 'Stage 3: Decompose the application', sub: 'Data flows and trust boundaries',
      text: 'Just as in STRIDE, the team draws data flow diagrams, marking entry points, trust boundaries, roles and the most valuable data: account balances and transfer approvals.',
      fields: [['Entry points', 'Login, transfer API, webhook from fraud service'], ['Crown jewels', 'Transfer approval, balances']],
      packets: [
        ['tm', 'tm', 'DFD', 'Entry points, trust boundaries, assets', 0, 'ctl'],
      ],
    },
    {
      title: 'Stage 4: Threat analysis', sub: 'Who attacks systems like ours, and how?',
      text: 'Using threat intelligence, the team looks at how real groups attack payment systems: account takeover with stolen passwords, abuse of transfer limits, and fake "beneficiary change" requests. This grounds the model in what actually happens.',
      fields: [['Threat actors', 'Fraud groups, insiders'], ['Common techniques', 'Account takeover, business logic abuse']],
      packets: [
        ['tm', 'ti', 'Query', 'Attacks against payment platforms, last 12 months', 300, 'req'],
        ['ti', 'tm', 'Report', 'Credential stuffing, limit abuse, beneficiary fraud', 9000, 'res'],
      ],
    },
    {
      title: 'Stage 5: Weakness analysis', sub: 'Where are we exposed?',
      text: 'The team matches those threats to weaknesses in this system, from pen-test results, code scans and design review: no limit on how often a beneficiary can be changed, and MFA is skipped for transfers under a threshold.',
      fields: [['Weakness 1', 'Beneficiary changes not rate-limited (CWE-799)'], ['Weakness 2', 'No step-up auth below threshold (CWE-306)']],
      packets: [
        ['tm', 'app', 'Review', 'Map threats to findings: scans, pen test, design', 800, 'req'],
        ['app', 'tm', 'Review', '2 relevant weaknesses found', 1200, 'atk'],
      ],
    },
    {
      title: 'Stage 6: Attack modelling', sub: 'Simulate the attack',
      text: 'The team builds attack trees and simulates the most likely path in a test environment: log in with a stolen password, add a new beneficiary, then send many small transfers just under the MFA threshold. The simulation succeeds.',
      fields: [['Path', 'Stolen login → new beneficiary → small transfers'], ['Result in test', 'Succeeded']],
      packets: [
        ['atk', 'app', 'Simulated', 'Login with stolen credentials', 900, 'atk'],
        ['atk', 'app', 'Simulated', 'Add beneficiary + 20 transfers of 490 (limit 500)', 18000, 'atk'],
        ['app', 'atk', 'Simulated', 'All accepted', 4000, 'atk'],
      ],
    },
    {
      title: 'Stage 7: Risk and impact', sub: 'Rank by business impact',
      text: 'Finally each threat is scored by likelihood and business impact and compared with the objectives from stage 1. The simulated fraud path is ranked critical, so step-up authentication on new beneficiaries and cumulative transfer limits go to the top of the backlog.',
      fields: [['Top risk', 'Fraud via small transfers: critical'], ['Fix', 'Step-up auth for new beneficiaries, cumulative limits']],
      defend: 'PASTA takes days rather than hours. Use it where the business impact justifies the effort, and lighter methods like STRIDE everywhere else.',
      packets: [
        ['tm', 'biz', 'Report', 'Ranked risks with business impact and fixes', 15000, 'def'],
        ['biz', 'tm', 'Decision', 'Approve fixes for top 3 risks this quarter', 300, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'linddun', domain: 'appsec', kind: 'defense', level: 'Intermediate', severity: 'Process',
  name: 'Privacy Threat Modelling (LINDDUN)', full: 'Finding privacy threats, not just security ones',
  tags: ['linddun', 'privacy', 'threat modeling', 'threat modelling', 'gdpr', 'privacy by design', 'data minimisation', 'appsec'],
  summary: 'A system can be perfectly secure and still harm people\'s privacy. LINDDUN, from KU Leuven, is a threat modelling method focused on privacy. It uses the same data flow diagrams as STRIDE but walks them through seven privacy threat categories.',
  facts: [['From', 'KU Leuven (DistriNet)'], ['Categories', 'Linking, Identifying, Non-repudiation, Detecting, Data disclosure, Unawareness & unintervenability, Non-compliance'], ['Model', 'Data flow diagram'], ['Variants', 'LINDDUN GO (cards), PRO, MAESTRO'], ['Supports', 'GDPR privacy by design'], ['Pairs with', 'STRIDE for security threats']],
  defenses: [
    'Collect only the data a feature truly needs, and delete it when it\'s no longer needed',
    'Use pseudonyms or aggregate data wherever individual identity isn\'t required',
    'Make data sharing visible and give people real choices and controls',
    'Keep third parties from receiving identifiers they don\'t need',
    'Document the legal basis and retention period for each type of personal data',
  ],
  nodes: [
    { id: 'app', type: 'phone', label: 'Fitness App', sub: 'runs + GPS', x: 120, y: 245 },
    { id: 'be', type: 'server', label: 'App Backend', sub: 'profiles + routes', x: 450, y: 245 },
    { id: 'an', type: 'cloud', label: 'Analytics SDK', sub: 'third party', x: 780, y: 100 },
    { id: 'feed', type: 'browser', label: 'Public Feed', sub: 'other users', x: 780, y: 390 },
    { id: 'db', type: 'db', label: 'Activity Store', sub: '5 years of runs', x: 450, y: 420 },
  ],
  steps: [
    {
      title: 'Linking and Identifying', sub: 'L and I of LINDDUN',
      text: 'The app shares every run on a public feed with a username and the full GPS route. Routes that always start at the same point reveal where someone lives (Identifying), and the same advertising ID sent to the analytics SDK lets it connect the person across apps (Linking).',
      fields: [['Identifying', 'Run start point = home address'], ['Linking', 'Advertising ID shared with analytics']],
      packets: [
        ['be', 'feed', 'HTTPS', 'Public run: full GPS route starting at home', 24000, 'data'],
        ['app', 'an', 'HTTPS', 'Event + advertising ID + device model', 1400, 'data'],
      ],
    },
    {
      title: 'Non-repudiation and Detecting', sub: 'N and D of LINDDUN',
      text: 'Sometimes being unable to deny something is a privacy harm: signed, permanent records of where someone was can be used against them (Non-repudiation). And simply seeing that a user has a "heart condition" training plan reveals something sensitive, even without reading the data (Detecting).',
      fields: [['Non-repudiation', 'Permanent signed location history'], ['Detecting', 'Plan type reveals health condition']],
      packets: [
        ['be', 'db', 'Store', 'Signed run records kept for 5 years', 900000, 'data'],
        ['app', 'an', 'HTTPS', 'event: joined "cardiac rehab" plan', 600, 'data'],
      ],
    },
    {
      title: 'Data disclosure', sub: 'D of LINDDUN',
      text: 'More personal data is collected and shared than the feature needs: exact birth date, precise location every second, and heart-rate data sent to the analytics provider.',
      fields: [['Needed', 'Distance, pace, rough area'], ['Collected', 'Birth date, 1 s GPS, heart rate to third party']],
      packets: [
        ['app', 'an', 'HTTPS', 'Heart-rate samples to analytics (not needed)', 32000, 'atk'],
      ],
    },
    {
      title: 'Unawareness and Non-compliance', sub: 'U and N of LINDDUN',
      text: 'Users don\'t know routes are public by default and can\'t easily delete old runs (Unawareness and unintervenability). Keeping health and location data for five years without a clear purpose or consent also breaks data-protection law (Non-compliance).',
      fields: [['Unawareness', 'Public by default, no delete-all option'], ['Non-compliance', 'Health data without explicit consent, long retention']],
      packets: [
        ['be', 'feed', 'HTTPS', 'Default visibility: public', 300, 'atk'],
      ],
    },
    {
      title: 'Privacy by design', sub: 'Turning threats into fixes',
      text: 'The fixes: routes are private by default, start and end points are hidden around home, the analytics SDK gets no identifiers or health data, sensitive data needs explicit consent, and old activity is deleted after a set period, with a "delete all my data" button.',
      fields: [['Default', 'Private, home zone hidden'], ['Analytics', 'Aggregated, no IDs or health data'], ['Retention', '24 months, user can delete anytime']],
      defend: 'Run LINDDUN alongside STRIDE: one finds security threats, the other finds privacy threats, from the same diagram.',
      packets: [
        ['be', 'feed', 'HTTPS', 'Shared run: private by default, home zone trimmed', 9000, 'def'],
        ['app', 'an', 'HTTPS', 'Aggregated usage counts only', 300, 'def'],
        ['be', 'db', 'Job', 'Delete activity older than 24 months', 0, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'attack-trees', domain: 'appsec', kind: 'defense', level: 'Intermediate', severity: 'Process',
  name: 'Attack Trees', full: 'Mapping every path to an attacker\'s goal',
  tags: ['attack tree', 'attack trees', 'threat modeling', 'threat modelling', 'and or', 'attack path', 'risk', 'appsec'],
  summary: 'An attack tree puts the attacker\'s goal at the root and breaks it down into the different ways to reach it. OR branches mean "any one of these works", AND branches mean "all of these are needed". Adding cost or difficulty to each leaf shows the cheapest path, which is where defenses matter most.',
  facts: [['Popularised by', 'Bruce Schneier (1999)'], ['Root', 'Attacker\'s goal'], ['Branches', 'OR (any) and AND (all)'], ['Leaves annotated with', 'Cost, skill, likelihood'], ['Used in', 'PASTA stage 6, safety and security analysis'], ['Pairs with', 'STRIDE, MITRE ATT&CK']],
  defenses: [
    'Start from a goal that matters to the business, such as "take over a customer account"',
    'Keep breaking branches down until each leaf is a concrete action',
    'Annotate leaves with cost or difficulty and find the cheapest complete path',
    'Defend the cheapest paths first, then recalculate',
    'Reuse trees for common goals and update them as attacks change',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: 'goal: take over account', x: 120, y: 245 },
    { id: 'login', type: 'browser', label: 'Login Page', sub: 'password', x: 450, y: 100 },
    { id: 'mail', type: 'mail', label: 'Phishing Email', sub: 'fake sign-in', x: 450, y: 245 },
    { id: 'help', type: 'user', label: 'Help Desk', sub: 'resets MFA', x: 450, y: 400 },
    { id: 'idp', type: 'idp', label: 'Identity Provider', sub: 'password + MFA', x: 780, y: 245, good: true },
  ],
  steps: [
    {
      title: 'Set the goal', sub: 'The root of the tree',
      text: 'The root is what the attacker wants: "take over a customer account". To log in, they need two things, a password AND a way past MFA, so the root has an AND branch with two children.',
      fields: [['Root', 'Take over a customer account'], ['Root branch', 'AND: password + get past MFA']],
      packets: [
        ['atk', 'idp', 'Goal', 'Sign in as the victim (needs password AND MFA)', 0, 'ctl'],
      ],
    },
    {
      title: 'Branch 1: get the password', sub: 'OR: any one works',
      text: 'There are several ways to get a password, and any one is enough, so this is an OR branch: phish the user, reuse a password leaked from another site (credential stuffing), or install malware on their device.',
      fields: [['OR', 'Phishing · credential stuffing · malware'], ['Cheapest', 'Credential stuffing (low cost)']],
      packets: [
        ['atk', 'mail', 'Path', 'Phishing email with fake sign-in page', 3000, 'atk'],
        ['atk', 'login', 'Path', 'Try passwords leaked from other breaches', 90000, 'atk'],
      ],
    },
    {
      title: 'Branch 2: get past MFA', sub: 'OR: any one works',
      text: 'To defeat MFA the attacker could flood the user with push prompts, take over their phone number (SIM swap), or call the help desk pretending to be the user and ask them to reset MFA.',
      fields: [['OR', 'Push fatigue · SIM swap · help-desk reset'], ['Cheapest', 'Help-desk social engineering']],
      packets: [
        ['atk', 'idp', 'Path', 'Push bombing until approved', 16000, 'atk'],
        ['atk', 'help', 'Path', '"I lost my phone, please reset my MFA"', 800, 'atk'],
      ],
    },
    {
      title: 'Find the cheapest path', sub: 'Annotate the leaves',
      text: 'Each leaf gets a rough cost and skill level. Combining the cheapest option from each AND child gives the most likely attack: reused password plus a help-desk MFA reset. That single path is where defending pays off most.',
      fields: [['Cheapest path', 'Credential stuffing AND help-desk reset'], ['Estimated cost', 'Low; no special skills']],
      packets: [
        ['atk', 'login', 'Path', 'Leaked password works', 600, 'atk'],
        ['help', 'idp', 'Path', 'MFA reset for "the user"', 400, 'atk'],
        ['atk', 'idp', 'Path', 'Signed in as victim', 1200, 'atk'],
      ],
    },
    {
      title: 'Prune the tree', sub: 'Defend, then recalculate',
      text: 'The team blocks breached passwords and rate-limits logins, and makes the help desk verify identity strongly before any MFA reset. Those branches become expensive, so the next-cheapest path is recalculated, and passkeys are planned to close the MFA branch entirely.',
      fields: [['Fixes', 'Breached-password check, verified MFA resets'], ['New cheapest path', 'Phishing + push fatigue (harder)'], ['Next', 'Passkeys']],
      defend: 'Attack trees work well with other methods: use STRIDE to find threats, and attack trees to see which combinations are realistic.',
      packets: [
        ['atk', 'login', 'Path', 'Leaked password → rejected (breached list)', 300, 'def'],
        ['help', 'atk', 'Path', 'MFA reset denied: identity not verified', 300, 'def'],
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
