/* Domain: Governance, Risk & Compliance (GRC) */

SE.register({
  id: 'security-governance', domain: 'grc', kind: 'defense', level: 'Beginner', severity: 'Process',
  name: 'Security Governance (NIST CSF 2.0)', full: 'Who decides, who owns, and how security is steered',
  tags: ['governance', 'grc', 'nist csf', 'csf 2.0', 'ciso', 'policy', 'standard', 'procedure', 'board', 'metrics'],
  summary: 'Governance is how an organisation decides what security it needs, who is accountable, and how it checks that things are working. The NIST Cybersecurity Framework 2.0 puts "Govern" at the centre of its six functions. This module follows one decision from the board down to a technical control and back up as a metric.',
  facts: [['Framework', 'NIST Cybersecurity Framework 2.0 (2024)'], ['Functions', 'Govern, Identify, Protect, Detect, Respond, Recover'], ['Document levels', 'Policy → standard → procedure → guideline'], ['Key roles', 'Board, executives, CISO, risk owners'], ['Also see', 'ISO/IEC 27001, COBIT'], ['Output', 'Risk appetite, policies, metrics']],
  defenses: [
    'Give every important risk and system a named business owner',
    'Keep policies short and stable; put technical detail in standards and procedures',
    'Run a formal exception process with an owner and an expiry date',
    'Report a few meaningful metrics to leadership, tied to risk',
    'Review policies at least yearly and after major incidents',
  ],
  nodes: [
    { id: 'board', type: 'user', label: 'Board & Executives', sub: 'risk appetite', x: 120, y: 110 },
    { id: 'ciso', type: 'user', label: 'CISO', sub: 'security programme', x: 450, y: 110, good: true },
    { id: 'pol', type: 'doc', label: 'Policies & Standards', sub: 'what and how', x: 780, y: 110 },
    { id: 'it', type: 'server', label: 'IT & Engineering', sub: 'implement controls', x: 780, y: 390 },
    { id: 'metrics', type: 'siem', label: 'Metrics', sub: 'dashboards', x: 450, y: 390 },
  ],
  steps: [
    {
      title: 'Set direction', sub: 'Risk appetite from the top',
      text: 'After a competitor suffers a ransomware attack, the board asks: how much downtime could we tolerate? They agree a risk appetite: critical customer systems must be restorable within 24 hours, and the CISO is accountable for the programme to get there.',
      fields: [['Risk appetite', 'Max 24 h outage for critical systems'], ['Accountable', 'CISO, reporting quarterly']],
      packets: [
        ['board', 'ciso', 'Decision', 'Risk appetite: critical systems restorable within 24 h', 900, 'ctl'],
      ],
    },
    {
      title: 'Write it down', sub: 'Policy, standard, procedure',
      text: 'The CISO updates the documents in layers. The policy states the rule ("critical data must be backed up and recoverable"). A standard gives specifics (daily immutable backups, 30-day retention, quarterly restore tests). Procedures explain step by step how teams do it. Guidelines offer optional advice.',
      fields: [['Policy', 'What and why (rarely changes)'], ['Standard', 'Measurable requirements'], ['Procedure', 'Step-by-step how-to']],
      packets: [
        ['ciso', 'pol', 'Update', 'Backup policy + standard + restore procedure', 6000, 'ctl',
          `Level       Example                                          Changes
Policy      Critical data must be backed up and recoverable   Rarely
            within the agreed recovery time.
Standard    Daily immutable backups · 30-day retention ·      Yearly
            restore test every quarter · RTO 24 h
Procedure   1. Open backup console  2. Select snapshot        Often
            3. Restore to isolated network  4. Verify  ...
Guideline   Tag non-critical data so it can use cheaper        Anytime
            storage tiers.`],
      ],
    },
    {
      title: 'Implement and own', sub: 'Controls with owners',
      text: 'Engineering teams implement the standard. Each critical system gets a business owner and a technical owner. One legacy system can\'t meet the standard yet, so its owner files an exception, which is approved for six months with a plan to replace it.',
      fields: [['Owners', 'Business + technical for each system'], ['Exception', 'Legacy billing: 6 months, with remediation plan']],
      packets: [
        ['pol', 'it', 'Standard', 'Daily immutable backups, quarterly restore tests', 3000, 'req'],
        ['it', 'ciso', 'Exception', 'Legacy billing can\'t do immutable backups yet', 900, 'atk'],
        ['ciso', 'it', 'Approval', 'Exception approved until May, replacement planned', 600, 'def'],
      ],
    },
    {
      title: 'Measure', sub: 'Is it working?',
      text: 'Tooling reports simple metrics: percentage of critical systems with tested restores, time taken in the last restore test, and open exceptions. These map to the "Govern" and "Recover" functions of NIST CSF 2.0.',
      fields: [['Restore-tested', '92% of critical systems'], ['Last restore time', '9 h (target 24 h)'], ['Open exceptions', '1']],
      packets: [
        ['it', 'metrics', 'Data', 'Backup jobs, restore test results', 40000, 'ctl'],
        ['metrics', 'ciso', 'Report', 'Quarterly KPIs', 9000, 'res'],
      ],
    },
    {
      title: 'Report and adjust', sub: 'Closing the loop',
      text: 'The CISO reports to the board in business terms: "We can restore 92% of critical systems within 9 hours; the remaining risk is the legacy billing system, which is being replaced by May." The board can then decide whether to accept that risk or fund a faster fix.',
      fields: [['Message', 'Business terms, not tool output'], ['Decision', 'Accept residual risk until May']],
      defend: 'Good governance makes security decisions explicit and owned, instead of accidental.',
      packets: [
        ['ciso', 'board', 'Report', 'Status vs risk appetite + remaining risks', 12000, 'def'],
        ['board', 'ciso', 'Decision', 'Accept residual risk until May; review next quarter', 600, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'risk-assessment', domain: 'grc', kind: 'defense', level: 'Beginner', severity: 'Process',
  name: 'Risk Assessment & Treatment', full: 'From threats to a risk register with owners',
  tags: ['risk assessment', 'risk management', 'risk register', 'likelihood', 'impact', 'risk treatment', 'iso 27005', 'nist 800-30', 'grc'],
  summary: 'Security budgets are limited, so organisations decide what to fix first by assessing risk: how likely something is to happen and how bad it would be. Each risk is then treated (reduced, transferred, avoided or accepted) and tracked in a register with a named owner.',
  facts: [['Guidance', 'NIST SP 800-30, ISO/IEC 27005'], ['Formula', 'Risk ≈ likelihood × impact'], ['Treatments', 'Mitigate, transfer, avoid, accept'], ['Output', 'Risk register'], ['Every risk needs', 'An owner and a review date'], ['Residual risk', 'What remains after treatment']],
  defenses: [
    'Start from what the business values most, not from a list of tools',
    'Use a simple, consistent scale so different risks can be compared',
    'Assign each risk to a business owner who can make decisions about it',
    'Record the treatment decision and the residual risk',
    'Review the register regularly and after incidents or big changes',
  ],
  nodes: [
    { id: 'owner', type: 'user', label: 'Business Owner', sub: 'online store', x: 120, y: 245 },
    { id: 'analyst', type: 'user', label: 'Risk Analyst', sub: 'security team', x: 450, y: 110, good: true },
    { id: 'asset', type: 'db', label: 'Customer Database', sub: 'key asset', x: 450, y: 390 },
    { id: 'reg', type: 'doc', label: 'Risk Register', sub: 'tracked risks', x: 800, y: 245 },
  ],
  steps: [
    {
      title: 'Identify assets and threats', sub: 'What could go wrong?',
      text: 'The analyst works with the store\'s owner to list what matters: the customer database, the payment flow, and the website being available. For the database, plausible threats include stolen admin credentials, an injection bug, and a misconfigured backup.',
      fields: [['Asset', 'Customer database (200k records)'], ['Threats', 'Credential theft, injection, exposed backup']],
      packets: [
        ['owner', 'analyst', 'Workshop', 'Critical assets and business impact', 900, 'ctl'],
        ['analyst', 'asset', 'Review', 'Architecture, access, existing controls', 3000, 'req'],
      ],
    },
    {
      title: 'Rate likelihood and impact', sub: 'A simple 1–5 scale',
      text: 'Each scenario gets a likelihood and an impact score on a 1–5 scale, based on existing controls, past incidents and threat intelligence. "Admin credentials phished" is likely (4) with severe impact (5), giving a high risk of 20. "Data centre flood" is rare (1) but severe (5): 5.',
      fields: [['Phished admin credentials', 'L4 × I5 = 20 (high)'], ['Exposed backup', 'L3 × I5 = 15 (high)'], ['Data centre flood', 'L1 × I5 = 5 (low)']],
      packets: [
        ['analyst', 'reg', 'Score', '3 scenarios rated', 1200, 'ctl',
          `           Impact →  1     2     3     4     5
Likelihood 5         5    10    15    20    25
           4         4     8    12    16   [20] phished admin creds
           3         3     6     9    12   [15] exposed backup
           2         2     4     6     8    10
           1         1     2     3     4    [5] data centre flood
Low 1–6 · Medium 8–12 · High 15–25`],
      ],
    },
    {
      title: 'Decide the treatment', sub: 'Mitigate, transfer, avoid or accept',
      text: 'The owner decides how to handle each risk. Phished credentials: mitigate with phishing-resistant MFA. Exposed backup: mitigate with encryption and access reviews. Flood: transfer through cyber insurance and use a second region. A minor risk might simply be accepted, in writing.',
      fields: [['Mitigate', 'Passkeys for admins; encrypted backups'], ['Transfer', 'Cyber insurance + second region'], ['Accept', 'Only with a documented decision']],
      packets: [
        ['analyst', 'owner', 'Options', 'Treatment options with cost and effect', 4000, 'req'],
        ['owner', 'analyst', 'Decision', 'Mitigate R1, R2; transfer R3', 600, 'def'],
      ],
    },
    {
      title: 'Record in the register', sub: 'Owner, plan, residual risk',
      text: 'Each risk goes into the register with its owner, treatment, due date and expected residual risk after the fix. The register becomes the single place leadership and auditors look to see what the organisation knows and is doing about it.',
      fields: [['R1 residual', '20 → 8 after passkeys'], ['R2 residual', '15 → 6 after encryption'], ['Review', 'Quarterly']],
      packets: [
        ['analyst', 'reg', 'Update', 'R1–R3 with owners, plans, due dates, residual risk', 3000, 'def'],
      ],
    },
    {
      title: 'Monitor and review', sub: 'Risk changes over time',
      text: 'Three months later, passkeys are rolled out and R1 drops to medium. A new risk appears from a planned AI chatbot that will read customer data, so it is assessed and added. Risk management is a cycle, not a one-off document.',
      fields: [['R1', 'Closed to residual 8'], ['New', 'R4: AI chatbot data exposure']],
      defend: 'A risk without an owner is a risk nobody will fix.',
      packets: [
        ['owner', 'reg', 'Review', 'Quarterly review: R1 reduced, R4 added', 2000, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'iso27001', domain: 'grc', kind: 'defense', level: 'Intermediate', severity: 'Standard',
  name: 'ISO/IEC 27001 Certification', full: 'Building and certifying an ISMS',
  tags: ['iso 27001', 'iso/iec 27001:2022', 'isms', 'annex a', 'statement of applicability', 'certification audit', 'internal audit', 'grc', 'compliance'],
  summary: 'ISO/IEC 27001 is the international standard for an information security management system (ISMS): a repeatable way to manage security risks. Certification means an accredited auditor has checked that the ISMS exists and works. This module follows a company from scoping to its certificate.',
  facts: [['Current version', 'ISO/IEC 27001:2022'], ['Annex A', '93 controls in 4 themes'], ['Themes', 'Organisational, people, physical, technological'], ['Key document', 'Statement of Applicability (SoA)'], ['Audit', 'Stage 1 (documents) + stage 2 (operation)'], ['Cycle', '3-year certificate, yearly surveillance audits']],
  defenses: [
    'Define a scope that matches what customers actually rely on',
    'Base control choices on the risk assessment, not on ticking every box',
    'Keep evidence as part of normal work, not a scramble before the audit',
    'Run a real internal audit and management review before certification',
    'Treat nonconformities as improvement items with owners and dates',
  ],
  nodes: [
    { id: 'mgmt', type: 'user', label: 'Top Management', sub: 'commitment', x: 120, y: 110 },
    { id: 'isms', type: 'shield', label: 'ISMS Team', sub: 'security + compliance', x: 450, y: 245, good: true },
    { id: 'soa', type: 'doc', label: 'Statement of Applicability', sub: 'Annex A decisions', x: 120, y: 390 },
    { id: 'teams', type: 'server', label: 'Teams & Systems', sub: 'in scope', x: 780, y: 110 },
    { id: 'aud', type: 'cert', label: 'Certification Body', sub: 'accredited auditor', x: 780, y: 390 },
  ],
  steps: [
    {
      title: 'Scope and commitment', sub: 'What does the ISMS cover?',
      text: 'Top management commits resources and sets the scope: "the development and operation of our SaaS platform, including the people and offices that support it". A clear scope tells customers exactly what the certificate covers.',
      fields: [['Scope', 'SaaS platform, its teams and offices'], ['Commitment', 'Security policy signed by CEO']],
      packets: [
        ['mgmt', 'isms', 'Mandate', 'Scope, resources, information security policy', 1500, 'ctl'],
      ],
    },
    {
      title: 'Risk assessment and SoA', sub: 'Choosing the controls',
      text: 'The ISMS team runs a risk assessment, then goes through all 93 Annex A controls and records in the Statement of Applicability whether each one applies, why, and how it\'s implemented. For example, "secure coding" applies; "physical security of data centres" is handled by the cloud provider.',
      fields: [['Annex A controls', '93 reviewed'], ['Applicable', '86'], ['Excluded with reason', '7']],
      packets: [
        ['isms', 'soa', 'Write', 'For each control: applicable? justification, implementation', 30000, 'ctl'],
      ],
    },
    {
      title: 'Operate the ISMS', sub: 'Evidence from normal work',
      text: 'For several months the organisation runs its controls and keeps records: access reviews, training completion, incident tickets, supplier assessments, change approvals. Then an internal auditor checks a sample, and management reviews the results.',
      fields: [['Evidence', 'Access reviews, training, incidents, changes'], ['Internal audit', '3 minor findings'], ['Management review', 'Held and minuted']],
      packets: [
        ['teams', 'isms', 'Evidence', 'Quarterly access reviews, training records, tickets', 90000, 'res'],
        ['isms', 'mgmt', 'Review', 'Internal audit results + ISMS performance', 6000, 'res'],
      ],
    },
    {
      title: 'Certification audit', sub: 'Stage 1 and stage 2',
      text: 'In stage 1 the auditor reviews the documents: scope, policies, risk assessment and SoA. In stage 2, a few weeks later, they test whether the ISMS actually operates, interviewing staff and sampling evidence. They find one minor nonconformity: a leaver\'s access was removed late.',
      fields: [['Stage 1', 'Documentation ready'], ['Stage 2', 'Operating effectively'], ['Nonconformity', '1 minor (late access removal)']],
      packets: [
        ['aud', 'isms', 'Audit', 'Stage 1: document review', 9000, 'req'],
        ['aud', 'teams', 'Audit', 'Stage 2: interviews + evidence samples', 40000, 'req'],
        ['teams', 'aud', 'Evidence', 'Leaver access removed 9 days late', 900, 'atk'],
      ],
    },
    {
      title: 'Certificate and continual improvement', sub: 'Not a one-time project',
      text: 'The company submits a corrective action plan for the nonconformity, and the certificate is issued for three years. Surveillance audits happen every year, and full recertification every three years, so the ISMS has to keep working and improving.',
      fields: [['Certificate', 'ISO/IEC 27001:2022, 3 years'], ['Surveillance', 'Yearly'], ['Corrective action', 'Automated leaver deprovisioning']],
      defend: 'Certification proves a management system works. It doesn\'t guarantee no breaches, which is why the risk assessment must stay real.',
      packets: [
        ['isms', 'aud', 'Plan', 'Corrective action: automatic deprovisioning from HR system', 1500, 'def'],
        ['aud', 'mgmt', 'Certificate', 'ISO/IEC 27001:2022 certificate issued', 2000, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'soc2', domain: 'grc', kind: 'defense', level: 'Intermediate', severity: 'Standard',
  name: 'SOC 2 Audit', full: 'Proving your controls to customers',
  tags: ['soc 2', 'soc2', 'aicpa', 'trust services criteria', 'type i', 'type ii', 'audit', 'evidence', 'saas', 'compliance', 'grc'],
  summary: 'SOC 2 is an audit report, common in North America, that SaaS companies give customers to show their security controls are designed and working. An independent CPA firm tests the controls against the AICPA Trust Services Criteria and writes a report that customers read under NDA.',
  facts: [['Defined by', 'AICPA'], ['Criteria', 'Security (required) + Availability, Processing Integrity, Confidentiality, Privacy'], ['Type I', 'Controls designed, at a point in time'], ['Type II', 'Controls operating over a period (often 6–12 months)'], ['Auditor', 'Licensed CPA firm'], ['Shared', 'With customers under NDA']],
  defenses: [
    'Start with a readiness assessment to find gaps before the audit window',
    'Write controls you actually perform, not ideal ones you can\'t evidence',
    'Automate evidence collection from your cloud, identity and ticketing tools',
    'Fix and explain exceptions honestly; customers read them',
    'Review your own vendors\' SOC 2 reports too (complementary controls)',
  ],
  nodes: [
    { id: 'cust', type: 'user', label: 'Enterprise Customer', sub: 'security review', x: 120, y: 110 },
    { id: 'co', type: 'shield', label: 'SaaS Company', sub: 'compliance team', x: 450, y: 245, good: true },
    { id: 'tools', type: 'cloud', label: 'Cloud, IdP, Tickets', sub: 'evidence sources', x: 800, y: 110 },
    { id: 'cpa', type: 'cert', label: 'CPA Firm', sub: 'independent auditor', x: 800, y: 390 },
    { id: 'report', type: 'doc', label: 'SOC 2 Type II Report', sub: 'under NDA', x: 120, y: 390 },
  ],
  steps: [
    {
      title: 'A customer asks', sub: '"Do you have a SOC 2?"',
      text: 'A large customer\'s security team won\'t sign until they see an independent audit report. The company chooses SOC 2 with the Security and Availability criteria, and plans a Type I report first, then a Type II.',
      fields: [['Criteria', 'Security + Availability'], ['Plan', 'Type I now, Type II after 6 months']],
      packets: [
        ['cust', 'co', 'Request', 'Security questionnaire + "please share your SOC 2"', 3000, 'req'],
      ],
    },
    {
      title: 'Define controls', sub: 'What you promise to do',
      text: 'The company writes its controls in plain terms: "Access to production requires MFA", "Access is reviewed quarterly", "Changes are peer-reviewed before deploy", "Backups are tested". Each one maps to the Trust Services Criteria, such as CC6.1 for logical access.',
      fields: [['Controls', '78'], ['Example', 'CC6.1: production access requires MFA']],
      packets: [
        ['co', 'co', 'Design', 'Control matrix mapped to Trust Services Criteria', 0, 'ctl'],
      ],
    },
    {
      title: 'The audit window', sub: 'Controls must run every time',
      text: 'For a Type II report, the controls are watched over a period, here six months. Evidence is collected automatically from the cloud account, identity provider and ticketing system: MFA settings, access review tickets, pull request approvals, backup test results.',
      fields: [['Period', '6 months'], ['Evidence', 'Automated where possible']],
      packets: [
        ['tools', 'co', 'API', 'MFA config, access reviews, PR approvals, backup tests', 400000, 'res'],
      ],
    },
    {
      title: 'Auditor testing', sub: 'Samples and exceptions',
      text: 'The CPA firm samples evidence for each control: for example, 25 production changes to see they were all reviewed. One change was deployed without a second reviewer during an incident. That becomes an "exception" in the report, with the company\'s response.',
      fields: [['Samples', '25 changes, 4 access reviews, 6 backup tests'], ['Exception', '1 emergency change without review']],
      packets: [
        ['cpa', 'co', 'Request', 'Samples: 25 changes, Q1–Q2 access reviews', 2000, 'req'],
        ['co', 'cpa', 'Evidence', 'Tickets, approvals, screenshots', 90000, 'res'],
        ['cpa', 'co', 'Finding', 'Exception: 1 of 25 changes not peer-reviewed', 900, 'atk'],
      ],
    },
    {
      title: 'The report', sub: 'Shared with customers under NDA',
      text: 'The final report contains the auditor\'s opinion, a description of the system, every control and test result, exceptions with management\'s response, and the controls customers must run themselves. The customer\'s security team reads it, notes the single explained exception, and signs.',
      fields: [['Opinion', 'Unqualified (controls operated effectively)'], ['Exceptions', '1, with response'], ['Renewal', 'Every year']],
      defend: 'A SOC 2 report is only as useful as its scope. Customers should check which systems and criteria it actually covers.',
      packets: [
        ['cpa', 'report', 'Issue', 'SOC 2 Type II report', 1200000, 'def'],
        ['report', 'cust', 'NDA', 'Report shared via trust portal', 1200000, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'gdpr-breach', domain: 'grc', kind: 'defense', level: 'Intermediate', severity: 'Regulation',
  name: 'GDPR Breach Response', full: 'The 72-hour clock after a personal data breach',
  tags: ['gdpr', 'data protection', 'personal data breach', '72 hours', 'dpo', 'supervisory authority', 'privacy', 'article 33', 'article 34', 'compliance', 'grc'],
  summary: 'The EU General Data Protection Regulation (GDPR) applies to anyone handling personal data of people in the EU. When personal data is breached, the organisation must assess the risk, notify the supervisory authority within 72 hours if people could be harmed, and tell affected individuals directly when the risk is high.',
  facts: [['Law', 'EU GDPR (Regulation 2016/679)'], ['Notify authority', 'Within 72 hours (Article 33)'], ['Notify individuals', 'If high risk (Article 34)'], ['Record', 'Every breach, even unreported'], ['Maximum fine', '€20M or 4% of global annual turnover'], ['Similar laws', 'UK GDPR, CCPA/CPRA, LGPD, DPDP Act']],
  defenses: [
    'Know where personal data lives, so breaches can be scoped quickly',
    'Have a breach procedure that names the DPO, legal and decision makers',
    'Start the 72-hour clock from when you become aware, and document everything',
    'Encrypt personal data, which can reduce the risk and notification duty',
    'Keep a breach log, including incidents that didn\'t need reporting',
  ],
  nodes: [
    { id: 'soc', type: 'siem', label: 'Security Team', sub: 'detects incident', x: 120, y: 245 },
    { id: 'dpo', type: 'user', label: 'DPO + Legal', sub: 'assess + decide', x: 450, y: 110, good: true },
    { id: 'db', type: 'db', label: 'CRM Database', sub: 'EU customers', x: 450, y: 390 },
    { id: 'sa', type: 'cert', label: 'Supervisory Authority', sub: 'data protection regulator', x: 800, y: 110 },
    { id: 'people', type: 'user', label: 'Affected People', sub: 'EU customers', x: 800, y: 390 },
  ],
  steps: [
    {
      title: 'Become aware', sub: 'The clock starts',
      text: 'Monday 09:00: the security team confirms that an attacker used a stolen support account to export records from the CRM. Once the organisation is reasonably certain personal data was affected, it is "aware", and the 72-hour notification clock starts.',
      fields: [['Aware at', 'Mon 09:00'], ['Deadline', 'Thu 09:00 (72 h)']],
      packets: [
        ['db', 'soc', 'Alert', 'Unusual export: 48,000 records by support account', 1200, 'atk'],
        ['soc', 'dpo', 'Escalate', 'Confirmed personal data breach, starting procedure', 900, 'def'],
      ],
    },
    {
      title: 'Contain and assess', sub: 'What data, whose, how risky?',
      text: 'While the account is disabled and the export blocked, the DPO assesses the breach: 48,000 EU customers, names, emails, phone numbers and order history, not encrypted. No payment data. The likely risk is phishing and fraud targeted at those customers.',
      fields: [['Data', 'Name, email, phone, order history'], ['People', '48,000 in the EU'], ['Risk', 'Likely harm (targeted phishing)']],
      packets: [
        ['soc', 'db', 'Action', 'Disable account, revoke sessions, block exports', 400, 'def'],
        ['dpo', 'db', 'Scope', 'Which fields and which people were exported?', 600, 'req'],
      ],
    },
    {
      title: 'Notify the authority', sub: 'Within 72 hours',
      text: 'Because there is a risk to people, the breach must be reported to the lead supervisory authority. On Wednesday the DPO files the notification: what happened, the categories and approximate numbers of people and records, likely consequences, and measures taken. Facts still unknown can follow in phases.',
      fields: [['Filed', 'Wed 15:00 (54 h)'], ['Contents', 'Nature, numbers, consequences, measures, DPO contact']],
      packets: [
        ['dpo', 'sa', 'Report', 'Article 33 breach notification', 9000, 'def'],
        ['sa', 'dpo', 'Receipt', 'Reference number + follow-up questions', 1200, 'res'],
      ],
    },
    {
      title: 'Tell the people affected', sub: 'When the risk is high',
      text: 'Because targeted phishing is a high risk for these customers, they are told directly, in clear language: what happened, what data was involved, what the company is doing, and what they should watch out for, plus a contact point.',
      fields: [['Channel', 'Email + website notice'], ['Advice', 'Watch for fake order emails; we\'ll never ask for passwords']],
      packets: [
        ['dpo', 'people', 'Email', 'Breach notice in plain language (Article 34)', 48000000, 'def'],
      ],
    },
    {
      title: 'Document and improve', sub: 'Accountability',
      text: 'The breach goes into the internal breach register with the timeline and decisions. The root causes, a support account without MFA that could export unlimited records, are fixed with MFA, export limits and alerts, and the authority is told about these measures.',
      fields: [['Register', 'Updated'], ['Fixes', 'MFA for support, export limits, alerts']],
      defend: 'GDPR expects "appropriate technical and organisational measures". Being able to show what you did, and when, matters as much as the fix.',
      packets: [
        ['dpo', 'dpo', 'Record', 'Breach register: facts, effects, decisions, actions', 0, 'def'],
        ['dpo', 'sa', 'Update', 'Follow-up: root cause and remediation', 6000, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'pci-dss', domain: 'grc', kind: 'defense', level: 'Intermediate', severity: 'Standard',
  name: 'PCI DSS & Scope Reduction', full: 'Protecting card data, and keeping it out of your systems',
  tags: ['pci dss', 'pci dss 4.0', 'cardholder data', 'cde', 'tokenization', 'scope reduction', 'qsa', 'saq', 'asv scan', 'payments', 'compliance', 'grc'],
  summary: 'The Payment Card Industry Data Security Standard (PCI DSS) applies to anyone who stores, processes or transmits payment card data. The most effective strategy is to shrink the scope: keep card numbers out of your systems entirely by using a payment provider\'s hosted fields and tokens.',
  facts: [['Standard', 'PCI DSS v4.0.1'], ['Structure', '12 principal requirements'], ['In scope', 'The cardholder data environment (CDE) and connected systems'], ['Assessment', 'SAQ (self-assessment) or ROC by a QSA'], ['External scans', 'Quarterly by an ASV'], ['Best strategy', 'Tokenisation to reduce scope']],
  defenses: [
    'Never store full card numbers or security codes unless you truly must',
    'Use hosted payment fields or redirects so card data goes straight to the provider',
    'Segment any systems that do touch card data from the rest of the network',
    'Protect payment pages from script tampering (PCI DSS v4 requirements 6.4.3 and 11.6.1)',
    'Run quarterly external ASV scans and an annual assessment',
  ],
  nodes: [
    { id: 'shopper', type: 'browser', label: 'Shopper', sub: 'checkout page', x: 120, y: 245 },
    { id: 'shop', type: 'server', label: 'Online Store', sub: 'web + API', x: 450, y: 110 },
    { id: 'db', type: 'db', label: 'Order Database', sub: 'stores tokens only', x: 450, y: 390 },
    { id: 'psp', type: 'cloud', label: 'Payment Provider', sub: 'PCI DSS Level 1', x: 800, y: 245, good: true },
    { id: 'qsa', type: 'cert', label: 'Assessor', sub: 'QSA / SAQ', x: 800, y: 420 },
  ],
  steps: [
    {
      title: 'Before: card data everywhere', sub: 'A large scope',
      text: 'The old checkout posted the card number to the store\'s own server, which forwarded it to the payment provider and kept the last orders "for refunds". That made the web servers, API, database, backups and the network connecting them all part of the cardholder data environment.',
      fields: [['Card data touches', 'Web, API, database, backups, logs'], ['Scope', 'Large (most of the infrastructure)']],
      packets: [
        ['shopper', 'shop', 'HTTPS', 'POST /checkout card=4111…1111&cvv=…', 900, 'data'],
        ['shop', 'db', 'SQL', 'INSERT order (full card number stored)', 600, 'data'],
        ['shop', 'psp', 'HTTPS', 'Charge card', 900, 'data'],
      ],
    },
    {
      title: 'Hosted fields', sub: 'Card data skips your servers',
      text: 'The redesign embeds the provider\'s hosted payment fields in the checkout page. The shopper types the card number into a frame served by the provider, so the number goes straight from the browser to the provider and never reaches the store.',
      fields: [['Card number goes to', 'Payment provider only'], ['Store receives', 'A token']],
      packets: [
        ['shopper', 'psp', 'HTTPS', 'Card details in provider-hosted field', 900, 'data'],
        ['psp', 'shopper', 'HTTPS', 'Token tok_7Hx…', 300, 'def'],
      ],
    },
    {
      title: 'Tokens, not card numbers', sub: 'Useless if stolen',
      text: 'The store sends the token to its backend, which asks the provider to charge it. The database stores only the token and the last four digits for receipts. A stolen database no longer contains anything that can be used to make payments elsewhere.',
      fields: [['Stored', 'Token + last 4 digits'], ['Not stored', 'Full number, security code']],
      packets: [
        ['shopper', 'shop', 'HTTPS', 'POST /checkout token=tok_7Hx…', 500, 'req'],
        ['shop', 'psp', 'HTTPS', 'Charge token tok_7Hx…', 500, 'req'],
        ['shop', 'db', 'SQL', 'INSERT order (token, last4=1111)', 300, 'def'],
      ],
    },
    {
      title: 'Protect the payment page', sub: 'Script tampering',
      text: 'Attackers sometimes inject a script into checkout pages to copy card details as they\'re typed ("web skimming"). PCI DSS v4 requires an inventory and authorisation of scripts on payment pages and a mechanism to detect changes, for example a strict Content Security Policy and change monitoring.',
      fields: [['Requirement 6.4.3', 'Authorise and justify every payment page script'], ['Requirement 11.6.1', 'Detect unauthorised page changes']],
      packets: [
        ['shop', 'shopper', 'HTTPS', 'Checkout page with CSP (only approved scripts)', 30000, 'def'],
      ],
    },
    {
      title: 'Validate compliance', sub: 'Smaller scope, simpler assessment',
      text: 'With card data handled entirely by the provider, the store qualifies for a much shorter self-assessment questionnaire instead of a full on-site assessment, plus quarterly external vulnerability scans by an approved scanning vendor.',
      fields: [['Before', 'Full assessment, large CDE'], ['After', 'Short SAQ + quarterly ASV scans']],
      defend: 'The cheapest card data to protect is card data you never have.',
      packets: [
        ['qsa', 'shop', 'Scan', 'Quarterly ASV external scan: pass', 90000, 'def'],
        ['shop', 'qsa', 'SAQ', 'Self-assessment questionnaire + attestation', 20000, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'vendor-risk', domain: 'grc', kind: 'defense', level: 'Beginner', severity: 'Process',
  name: 'Third-Party Risk Management', full: 'Checking the vendors that handle your data',
  tags: ['vendor risk', 'third party risk', 'tprm', 'supplier security', 'security questionnaire', 'dpa', 'soc 2 report', 'due diligence', 'grc'],
  summary: 'Many breaches start at a supplier: a SaaS tool, an IT contractor, a marketing agency. Third-party risk management checks vendors before they get data, writes security into the contract, keeps watching them, and takes access back when the relationship ends.',
  facts: [['Lifecycle', 'Due diligence → contract → monitoring → offboarding'], ['Evidence', 'SOC 2 report, ISO 27001 certificate, questionnaire'], ['Questionnaires', 'SIG, CAIQ (cloud)'], ['Contract', 'Data processing agreement, breach notice clause'], ['Risk-based', 'Deeper review for critical vendors'], ['Related', 'Supply chain security']],
  defenses: [
    'Tier vendors by the data and access they get, and review accordingly',
    'Ask for independent evidence (SOC 2, ISO 27001) rather than only questionnaires',
    'Put breach notification, audit rights and data deletion in the contract',
    'Give vendors the least access needed, and review it regularly',
    'Offboard properly: revoke access and confirm data deletion',
  ],
  nodes: [
    { id: 'biz', type: 'user', label: 'Marketing Team', sub: 'wants a new tool', x: 120, y: 245 },
    { id: 'tprm', type: 'shield', label: 'Vendor Risk Team', sub: 'security + legal', x: 450, y: 245, good: true },
    { id: 'vendor', type: 'cloud', label: 'SaaS Vendor', sub: 'email platform', x: 800, y: 110 },
    { id: 'data', type: 'db', label: 'Customer List', sub: '120k contacts', x: 800, y: 390 },
    { id: 'contract', type: 'doc', label: 'Contract + DPA', sub: 'security terms', x: 450, y: 420 },
  ],
  steps: [
    {
      title: 'Intake and tiering', sub: 'How risky is this vendor?',
      text: 'Marketing wants a new email platform and plans to upload 120,000 customer contacts. The intake form asks what data and access the vendor will get. Customer personal data puts it in the "high" tier, so it gets a full review.',
      fields: [['Data shared', 'Names, emails, purchase history'], ['Tier', 'High (personal data at scale)']],
      packets: [
        ['biz', 'tprm', 'Intake', 'New vendor: email platform, customer contacts', 1200, 'req'],
      ],
    },
    {
      title: 'Due diligence', sub: 'Evidence, not promises',
      text: 'The team asks for the vendor\'s SOC 2 Type II report and ISO 27001 certificate, and a short questionnaire on the gaps they don\'t cover. The SOC 2 report is clean, but shows that customers must turn on SSO and MFA themselves (a complementary user control).',
      fields: [['SOC 2 Type II', 'Clean opinion'], ['ISO 27001', 'Valid certificate'], ['Customer duty', 'Enable SSO + MFA']],
      packets: [
        ['tprm', 'vendor', 'Request', 'SOC 2 report, ISO certificate, questionnaire', 2000, 'req'],
        ['vendor', 'tprm', 'Evidence', 'Reports under NDA + answers', 900000, 'res'],
      ],
    },
    {
      title: 'Contract terms', sub: 'Security in writing',
      text: 'Legal adds a data processing agreement and security clauses: notify us of breaches within 48 hours, use data only for our purposes, allow audits, list sub-processors, and delete all data within 30 days of termination.',
      fields: [['Breach notice', '48 hours'], ['Sub-processors', 'Listed, changes notified'], ['Exit', 'Data deleted in 30 days']],
      packets: [
        ['tprm', 'contract', 'Draft', 'DPA + security schedule', 30000, 'def'],
        ['contract', 'vendor', 'Sign', 'Signed agreement', 30000, 'def'],
      ],
    },
    {
      title: 'Onboard with least privilege', sub: 'Only what\'s needed',
      text: 'Before upload, SSO and MFA are turned on, only marketing staff get accounts, and only the fields needed for campaigns are exported. Purchase history stays behind because the campaigns don\'t need it.',
      fields: [['Access', 'SSO + MFA, marketing group only'], ['Data shared', 'Name + email (purchase history excluded)']],
      packets: [
        ['data', 'vendor', 'Upload', '120,000 contacts (name, email only)', 9000000, 'data'],
      ],
    },
    {
      title: 'Monitor and offboard', sub: 'The relationship isn\'t static',
      text: 'The vendor is reviewed every year, and the team watches for news of incidents. Two years later the company switches providers: access is revoked, the API key is deleted, and the vendor confirms in writing that the data has been deleted.',
      fields: [['Review', 'Annual + on incidents'], ['Offboarding', 'Access revoked, deletion confirmed']],
      defend: 'Your data is only as safe as the weakest vendor that holds it. Keep an up-to-date list of who has what.',
      packets: [
        ['tprm', 'vendor', 'Offboard', 'Revoke SSO app + API key; request deletion', 600, 'def'],
        ['vendor', 'tprm', 'Letter', 'Certificate of data deletion', 2000, 'def'],
      ],
    },
  ],
});
