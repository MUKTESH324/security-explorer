/* Domain: DevSecOps (security built into the delivery pipeline) */

SE.register({
  id: 'secure-pipeline', domain: 'devsecops', kind: 'defense', level: 'Beginner', severity: 'Architecture',
  name: 'Secure CI/CD Pipeline', full: 'Security checks from commit to production',
  tags: ['devsecops', 'ci/cd', 'pipeline', 'sast', 'sca', 'dast', 'iac scanning', 'container scanning', 'shift left', 'github actions'],
  summary: 'DevSecOps builds security checks into the same automated pipeline that builds, tests and deploys code. Each stage catches a different kind of problem early, when it\'s cheapest to fix, without slowing developers down with manual gates.',
  facts: [['Code scanning', 'SAST: Semgrep, CodeQL'], ['Dependencies', 'SCA: Dependabot, Trivy, OSV-Scanner'], ['Secrets', 'Gitleaks, push protection'], ['Infrastructure code', 'Checkov, tfsec / Trivy config'], ['Running app', 'DAST: OWASP ZAP'], ['Framework', 'OWASP SAMM, NIST SSDF (SP 800-218)']],
  defenses: [
    'Start with fast, low-noise checks (secrets, dependencies) and add more over time',
    'Fail the build only on high-confidence, high-severity findings; report the rest',
    'Show results inside pull requests where developers already work',
    'Scan infrastructure code and container images, not just application code',
    'Track fix times and recurring issues to guide training',
  ],
  nodes: [
    { id: 'dev', type: 'workstation', label: 'Developer', sub: 'commit + PR', x: 110, y: 245 },
    { id: 'repo', type: 'repo', label: 'Git Repository', sub: 'pull request', x: 330, y: 110 },
    { id: 'ci', type: 'gateway', label: 'CI Pipeline', sub: 'build + scan', x: 330, y: 380, good: true },
    { id: 'reg', type: 'registry', label: 'Image Registry', sub: 'signed images', x: 580, y: 245 },
    { id: 'stg', type: 'server', label: 'Staging', sub: 'DAST', x: 800, y: 110 },
    { id: 'prod', type: 'cloud', label: 'Production', sub: 'policy-checked deploy', x: 800, y: 390 },
  ],
  steps: [
    {
      title: 'Before the commit', sub: 'Pre-commit secret scanning',
      text: 'A pre-commit hook scans changes on the developer\'s machine. It spots an API key pasted into a config file and blocks the commit before it ever leaves the laptop. The repository also has push protection as a second safety net.',
      fields: [['Tool', 'Gitleaks pre-commit hook'], ['Found', 'API key in config.yaml'], ['Result', 'Commit blocked']],
      packets: [
        ['dev', 'dev', 'Hook', 'Scan staged changes → secret found, commit blocked', 0, 'def'],
        ['dev', 'repo', 'Git', 'Push (secret removed, uses environment variable)', 4200, 'req'],
      ],
    },
    {
      title: 'Pull request checks', sub: 'SAST and dependency scanning',
      text: 'Opening a pull request starts the pipeline. Static analysis (SAST) reads the code and flags a SQL query built from user input. Software composition analysis (SCA) checks dependencies and finds a library with a known critical vulnerability. Both show up as comments on the pull request.',
      fields: [['SAST', 'SQL built from input (CWE-89): high'], ['SCA', 'Library with known critical CVE'], ['Shown in', 'PR comments']],
      packets: [
        ['repo', 'ci', 'Webhook', 'PR #412 opened', 600, 'ctl'],
        ['ci', 'repo', 'Check', 'SAST: 1 high · SCA: 1 critical (upgrade available)', 2400, 'atk'],
        ['dev', 'repo', 'Git', 'Fix: parameterised query + upgrade library', 3800, 'def'],
      ],
    },
    {
      title: 'Infrastructure and image checks', sub: 'IaC and container scanning',
      text: 'The same pull request changes Terraform. The IaC scanner flags a security group that opens SSH to the whole internet. After the build, the container image is scanned for vulnerable OS packages, and only images that pass are signed and pushed to the registry.',
      fields: [['IaC', 'SSH open to 0.0.0.0/0: blocked'], ['Image scan', 'No critical CVEs'], ['Signing', 'Image signed (Sigstore cosign)']],
      packets: [
        ['ci', 'ci', 'IaC scan', 'Checkov: security group allows 0.0.0.0/0 on 22', 0, 'atk'],
        ['ci', 'reg', 'OCI', 'Push signed image shop:1.42 (scan passed)', 180000000, 'def'],
      ],
    },
    {
      title: 'Test the running app', sub: 'DAST in staging',
      text: 'The new version is deployed to staging, where a dynamic scanner (DAST) tests it from the outside like an attacker would: missing security headers, cookie flags, reflected input. It reports a missing Content-Security-Policy header, which becomes a ticket rather than a blocker.',
      fields: [['Tool', 'OWASP ZAP baseline scan'], ['Found', 'Missing CSP header (medium)'], ['Gate', 'Report, don\'t block']],
      packets: [
        ['reg', 'stg', 'Deploy', 'shop:1.42 → staging', 900, 'req'],
        ['ci', 'stg', 'HTTPS', 'ZAP baseline scan', 300000, 'req'],
        ['stg', 'ci', 'HTTPS', 'Report: 1 medium, 3 low', 9000, 'res'],
      ],
    },
    {
      title: 'Deploy with guardrails', sub: 'Only verified images reach production',
      text: 'Production only accepts images that are signed by the pipeline and passed the scans. An admission policy checks the signature at deploy time, and runtime monitoring watches for anything unusual. Security became part of the normal flow, not a separate phase at the end.',
      fields: [['Admission check', 'Signature + scan attestation required'], ['Unsigned image', 'Rejected']],
      defend: 'The goal is fast feedback, not more gates. A check that developers ignore because it\'s noisy is worse than no check.',
      packets: [
        ['reg', 'prod', 'Deploy', 'shop:1.42 (signature verified) → production', 900, 'def'],
        ['dev', 'prod', 'Deploy', 'Manual deploy of unsigned image', 900, 'atk'],
        ['prod', 'dev', 'Policy', 'Rejected: image not signed by pipeline', 300, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'secrets-leak', domain: 'devsecops', kind: 'attack', level: 'Beginner', severity: 'Critical',
  name: 'Leaked Secrets in Code', full: 'From a pushed key to a cloud bill in minutes',
  tags: ['secrets', 'leaked credentials', 'api key', 'github', 'secret scanning', 'push protection', 'rotation', 'vault', 'devsecops'],
  summary: 'Passwords, API keys and cloud credentials committed to a repository are among the most common causes of cloud breaches. Bots watch public code platforms continuously, and a leaked cloud key can be abused within minutes. Deleting the commit isn\'t enough: the key must be revoked.',
  facts: [['Technique', 'T1552.001 (Credentials In Files)'], ['Also', 'CWE-798 (Hard-coded Credentials)'], ['Detection', 'Secret scanning, push protection'], ['First response', 'Revoke and rotate, then clean history'], ['Better design', 'Secrets manager or short-lived OIDC credentials'], ['Common abuse', 'Crypto-mining, data theft']],
  defenses: [
    'Turn on secret scanning and push protection for every repository',
    'Keep secrets in a secrets manager or vault, never in code or images',
    'Prefer short-lived credentials (OIDC, instance roles) over long-lived keys',
    'If a secret leaks, revoke it first; cleaning Git history comes second',
    'Set billing and usage alerts so abuse is noticed quickly',
  ],
  nodes: [
    { id: 'dev', type: 'workstation', label: 'Developer', sub: 'debugging late', x: 120, y: 245 },
    { id: 'git', type: 'repo', label: 'Public Repository', sub: 'open source', x: 450, y: 110 },
    { id: 'bot', type: 'attacker', label: 'Scanning Bots', sub: 'watch new commits', x: 450, y: 390 },
    { id: 'cloud', type: 'cloud', label: 'Cloud Account', sub: 'production', x: 800, y: 245 },
    { id: 'vault', type: 'lock', label: 'Secrets Manager', sub: 'rotated secrets', x: 800, y: 420, good: true },
  ],
  steps: [
    {
      title: 'A key in a commit', sub: '"Just for testing"',
      text: 'While debugging, a developer hard-codes a cloud access key in a script and pushes the branch to a public repository. They remove it in the next commit an hour later, but the key is still in the Git history.',
      fields: [['File', 'scripts/sync.py'], ['Secret', 'Cloud access key (long-lived)'], ['Removed later', 'Yes, but still in history']],
      packets: [
        ['dev', 'git', 'Git', 'Push commit with AWS_SECRET_ACCESS_KEY in sync.py', 3000, 'data'],
      ],
    },
    {
      title: 'Found in minutes', sub: 'Automated scanning',
      text: 'Bots monitor public commit feeds for anything that looks like a credential. Within minutes, one extracts the key and tests it with a harmless "who am I" call. It works.',
      fields: [['Time to discovery', 'Minutes'], ['Test call', 'GetCallerIdentity: valid']],
      packets: [
        ['git', 'bot', 'Feed', 'New public commit', 3000, 'data'],
        ['bot', 'cloud', 'API', 'GetCallerIdentity with leaked key', 400, 'atk'],
        ['cloud', 'bot', 'API', 'Valid: user ci-deploy', 300, 'atk'],
      ],
    },
    {
      title: 'Abuse', sub: 'Mining and data access',
      text: 'The attacker launches large compute instances in several regions to mine cryptocurrency and lists storage buckets to look for data. The first sign for the company is a usage alert and a surprising bill.',
      fields: [['Activity', '120 GPU instances in 6 regions'], ['Cost', 'Thousands per day']],
      packets: [
        ['bot', 'cloud', 'API', 'RunInstances × 120 (GPU) across regions', 90000, 'atk'],
        ['bot', 'cloud', 'API', 'ListBuckets, GetObject', 40000, 'atk'],
      ],
    },
    {
      title: 'Respond: revoke first', sub: 'History cleanup comes second',
      text: 'The right order matters. First, deactivate and delete the key, so nothing else can use it. Then terminate the attacker\'s resources, check the audit log for everything the key did, and only then rewrite Git history. Removing the commit alone does nothing, because copies already exist.',
      fields: [['1', 'Deactivate + delete key'], ['2', 'Terminate resources, review CloudTrail'], ['3', 'Clean history, rotate related secrets']],
      packets: [
        ['dev', 'cloud', 'API', 'Delete access key for ci-deploy', 300, 'def'],
        ['dev', 'cloud', 'API', 'Terminate 120 instances; review audit log', 9000, 'def'],
      ],
    },
    {
      title: 'Prevent it next time', sub: 'No long-lived keys in reach',
      text: 'Push protection now blocks commits that contain credentials. The script reads secrets from a secrets manager at runtime, and the CI system uses short-lived OIDC credentials instead of a stored key, so there is no long-lived key to leak.',
      fields: [['Push protection', 'On'], ['Runtime secrets', 'From secrets manager'], ['CI', 'OIDC, no stored keys']],
      defend: 'The safest secret is one that doesn\'t exist: use identity-based, short-lived credentials wherever possible.',
      packets: [
        ['dev', 'git', 'Git', 'Push with a credential', 3000, 'atk'],
        ['git', 'dev', 'Git', 'Rejected: push protection detected a secret', 400, 'def'],
        ['vault', 'dev', 'API', 'Secret fetched at runtime (rotated weekly)', 300, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'supply-chain', domain: 'devsecops', kind: 'attack', level: 'Intermediate', severity: 'Critical',
  name: 'Software Supply Chain Attacks', full: 'Malicious packages and how to trust what you build',
  tags: ['supply chain', 'dependency confusion', 'typosquatting', 'malicious package', 'sbom', 'slsa', 'sigstore', 'npm', 'pypi', 'devsecops'],
  summary: 'Modern apps are mostly other people\'s code. Attackers target that supply chain: publishing look-alike packages, claiming internal package names on public registries, or compromising a real maintainer. One bad dependency runs inside your build with all its secrets.',
  facts: [['Technique', 'T1195.001 (Compromise Software Dependencies)'], ['Common tricks', 'Typosquatting, dependency confusion'], ['Real incidents', 'event-stream (2018), SolarWinds (2020), xz Utils (2024)'], ['Inventory', 'SBOM (CycloneDX, SPDX)'], ['Provenance', 'SLSA, Sigstore signing'], ['OWASP', 'Top 10 2025 A03: Software Supply Chain Failures']],
  defenses: [
    'Use lockfiles with hashes, and review new dependencies before adding them',
    'Scope internal package names to your private registry so public ones can\'t replace them',
    'Run builds with minimal secrets and no network access beyond what\'s needed',
    'Pin CI actions and base images by digest, not by moving tags',
    'Generate an SBOM and verify signatures and provenance of what you deploy',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: 'publishes packages', x: 120, y: 110 },
    { id: 'pub', type: 'registry', label: 'Public Registry', sub: 'npm / PyPI', x: 450, y: 110 },
    { id: 'priv', type: 'registry', label: 'Private Registry', sub: 'internal packages', x: 450, y: 390, good: true },
    { id: 'ci', type: 'gateway', label: 'Build Server', sub: 'has deploy secrets', x: 780, y: 245 },
    { id: 'c2', type: 'c2', label: 'Attacker Server', sub: 'collects secrets', x: 120, y: 390 },
  ],
  steps: [
    {
      title: 'Typosquatting', sub: 'One letter off',
      text: 'The attacker publishes a package named like a popular one with a small typo. A developer mistypes the name once in a dependency file. The fake package works like the real one, but also runs code during installation.',
      fields: [['Real', 'requests'], ['Fake', 'reqeusts'], ['Payload', 'Install script']],
      packets: [
        ['atk', 'pub', 'Publish', 'reqeusts 2.31.0 (copy of real code + install script)', 90000, 'atk'],
      ],
    },
    {
      title: 'Dependency confusion', sub: 'Internal name, public package',
      text: 'The company uses an internal package called `acme-auth` from its private registry. The attacker publishes `acme-auth` on the public registry with a higher version number. A build tool that checks both registries picks the higher version: the attacker\'s.',
      fields: [['Internal', 'acme-auth 1.4.2 (private)'], ['Public impostor', 'acme-auth 99.0.0'], ['Chosen', 'Highest version → public']],
      packets: [
        ['atk', 'pub', 'Publish', 'acme-auth 99.0.0', 40000, 'atk'],
        ['ci', 'pub', 'HTTPS', 'Resolve acme-auth (any registry, highest version)', 600, 'req'],
        ['pub', 'ci', 'HTTPS', 'acme-auth 99.0.0', 40000, 'atk'],
      ],
    },
    {
      title: 'Code runs in the build', sub: 'Where the secrets are',
      text: 'During installation, the malicious package\'s script reads environment variables on the build server, which contain deploy tokens and cloud credentials, and sends them to the attacker. Nothing in the finished app looks different.',
      fields: [['Ran during', 'npm install / pip install'], ['Stolen', 'Deploy token, cloud keys from environment']],
      packets: [
        ['ci', 'ci', 'Install', 'postinstall script runs', 0, 'atk'],
        ['ci', 'c2', 'HTTPS', 'POST environment variables', 3000, 'data'],
      ],
    },
    {
      title: 'Lock down resolution', sub: 'Know exactly what you install',
      text: 'The fixes start with where packages come from. Internal names are scoped (for example `@acme/auth`) and only resolved from the private registry. Lockfiles with hashes mean a build only installs the exact versions and contents that were reviewed, and new dependencies get a quick review in the pull request.',
      fields: [['Scope', '@acme/* → private registry only'], ['Lockfile', 'Exact versions + hashes'], ['Install scripts', 'Disabled where possible']],
      packets: [
        ['ci', 'priv', 'HTTPS', 'Resolve @acme/auth (private only)', 600, 'def'],
        ['priv', 'ci', 'HTTPS', '@acme/auth 1.4.2 (hash matches lockfile)', 40000, 'def'],
      ],
    },
    {
      title: 'Prove what you shipped', sub: 'SBOM, signing and provenance',
      text: 'Each build produces an SBOM listing every component, and the artifact is signed with a record of how and where it was built (SLSA provenance). Deploys verify the signature and provenance, and when a new vulnerable or malicious package is announced, the SBOM shows in seconds which apps include it.',
      fields: [['SBOM', 'CycloneDX per build'], ['Provenance', 'SLSA level 3 build'], ['Signature', 'Verified at deploy']],
      defend: 'Give builds the fewest secrets possible. A build that can\'t reach production credentials limits what a bad package can steal.',
      packets: [
        ['ci', 'priv', 'OCI', 'Push artifact + SBOM + signed provenance', 200000, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'cicd-oidc', domain: 'devsecops', kind: 'protocol', level: 'Intermediate', severity: 'Protocol',
  name: 'Keyless CI/CD with OIDC', full: 'Short-lived cloud credentials for pipelines',
  tags: ['oidc', 'github actions', 'workload identity', 'assumerolewithwebidentity', 'sts', 'keyless', 'ci/cd', 'trust policy', 'devsecops'],
  summary: 'Pipelines used to deploy with long-lived cloud keys stored as CI secrets. With OpenID Connect (OIDC), the CI platform gives each job a signed identity token, and the cloud exchanges it for credentials that last minutes. There is no stored key to leak, but the trust policy must be precise.',
  facts: [['Standard', 'OpenID Connect'], ['AWS call', 'AssumeRoleWithWebIdentity'], ['Also on', 'Azure workload identity federation, GCP Workload Identity'], ['Token issuer', 'token.actions.githubusercontent.com'], ['Key check', 'Trust policy on the "sub" claim'], ['Credential lifetime', 'Minutes to an hour']],
  defenses: [
    'Restrict the trust policy to the exact repository and branch or environment',
    'Check the audience claim as well as the subject',
    'Give each pipeline role only the permissions that deployment needs',
    'Protect the production environment with required reviewers',
    'Remove old long-lived keys once OIDC works',
  ],
  nodes: [
    { id: 'job', type: 'gateway', label: 'CI Job', sub: 'acme/shop · main', x: 120, y: 245 },
    { id: 'idp', type: 'idp', label: 'CI OIDC Provider', sub: 'signs job tokens', x: 450, y: 100, good: true },
    { id: 'sts', type: 'cloud', label: 'Cloud STS', sub: 'checks trust policy', x: 450, y: 390 },
    { id: 'target', type: 'server', label: 'Deploy Target', sub: 'production', x: 800, y: 245 },
    { id: 'fork', type: 'attacker', label: 'Other Repo', sub: 'acme/experiments', x: 800, y: 420 },
  ],
  steps: [
    {
      title: 'The job asks for an identity token', sub: 'Signed by the CI platform',
      text: 'When the deploy job starts, it requests an OIDC token from the CI platform. The token is signed and says exactly which repository, branch and workflow is running, and which cloud it\'s meant for.',
      fields: [['iss', 'https://token.actions.githubusercontent.com'], ['sub', 'repo:acme/shop:ref:refs/heads/main'], ['aud', 'sts.amazonaws.com']],
      packets: [
        ['job', 'idp', 'HTTPS', 'Request OIDC token (audience: sts.amazonaws.com)', 400, 'req'],
        ['idp', 'job', 'HTTPS', 'Signed JWT (valid ~5 min)', 1200, 'ctl',
          `{
  "iss": "https://token.actions.githubusercontent.com",
  "aud": "sts.amazonaws.com",
  "sub": "repo:acme/shop:ref:refs/heads/main",
  "repository": "acme/shop",
  "ref": "refs/heads/main",
  "workflow": "deploy",
  "exp": 1794600300
}`],
      ],
    },
    {
      title: 'Exchange it for cloud credentials', sub: 'AssumeRoleWithWebIdentity',
      text: 'The job sends the token to the cloud\'s security token service and asks to assume the deploy role. The cloud verifies the token\'s signature against the CI provider\'s published keys, then checks the role\'s trust policy.',
      fields: [['Role', 'shop-deploy-role'], ['Verified', 'Signature, issuer, audience, expiry']],
      packets: [
        ['job', 'sts', 'HTTPS', 'AssumeRoleWithWebIdentity (role: shop-deploy-role, token)', 1500, 'req'],
        ['sts', 'idp', 'HTTPS', 'Fetch signing keys (JWKS)', 300, 'ctl'],
      ],
    },
    {
      title: 'The trust policy decides', sub: 'Exactly which repo and branch',
      text: 'The trust policy only allows tokens whose subject is the `main` branch of `acme/shop`. This token matches, so STS returns credentials valid for one hour, and the job deploys. Nothing long-lived was ever stored.',
      fields: [['Condition', 'sub = repo:acme/shop:ref:refs/heads/main'], ['Credentials', '1 hour']],
      packets: [
        ['sts', 'job', 'HTTPS', 'Temporary credentials (1 h)', 1200, 'data'],
        ['job', 'target', 'HTTPS', 'Deploy shop:1.42', 90000, 'req'],
      ],
    },
    {
      title: 'A too-broad trust policy', sub: 'Wildcards trust everyone',
      text: 'If the condition had been `repo:acme/*` or, worse, missing, any repository in the organisation (or on the platform) could assume the production role. Here a job in an experimental repo tries, and is rejected because the subject doesn\'t match.',
      fields: [['Risky', 'sub like repo:acme/* or no sub check'], ['This request', 'sub = repo:acme/experiments:… → denied']],
      packets: [
        ['fork', 'sts', 'HTTPS', 'AssumeRoleWithWebIdentity (sub: repo:acme/experiments:…)', 1500, 'atk'],
        ['sts', 'fork', 'HTTPS', 'AccessDenied: not authorised to assume role', 300, 'def'],
      ],
    },
    {
      title: 'Production approvals', sub: 'People still decide',
      text: 'For production, the trust policy can require a deployment environment instead of a branch, and that environment needs a reviewer\'s approval. The result: short-lived credentials, issued only to the right workflow, only after a human approves.',
      fields: [['sub', 'repo:acme/shop:environment:production'], ['Approval', 'Required reviewers']],
      defend: 'Once OIDC deploys work, delete the old stored cloud keys from CI secrets.',
      packets: [
        ['job', 'idp', 'HTTPS', 'Token for environment: production (after approval)', 400, 'def'],
      ],
    },
  ],
});
