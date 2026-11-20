/* Domain: Cloud Security (AWS used for concrete examples; ideas apply to Azure and GCP too) */

SE.register({
  id: 'imds-ssrf', domain: 'cloud', kind: 'attack', level: 'Intermediate', severity: 'Critical',
  name: 'Cloud Metadata Credential Theft', full: 'SSRF to the instance metadata service',
  tags: ['imds', 'instance metadata', '169.254.169.254', 'ssrf', 'aws', 'imdsv2', 'iam role', 'credentials', 'cloud'],
  summary: 'Every cloud virtual machine can ask a special internal address for information about itself, including temporary credentials for its IAM role. If a web app on that machine has an SSRF bug, an attacker can make the server fetch those credentials and then use them from anywhere. This is how several major cloud breaches happened.',
  facts: [['Metadata address', '169.254.169.254'], ['Technique', 'T1552.005 (Cloud Instance Metadata API)'], ['Entry point', 'SSRF (CWE-918)'], ['Key defense', 'IMDSv2 (session tokens) + hop limit'], ['Detection', 'GuardDuty: credentials used outside AWS'], ['Same idea on', 'Azure IMDS, GCP metadata server']],
  defenses: [
    'Require IMDSv2 on every instance so a simple GET request can\'t read metadata',
    'Keep the metadata hop limit at 1 unless containers truly need more',
    'Fix SSRF: allow-list destinations and block internal and link-local addresses',
    'Give instance roles only the permissions the app needs',
    'Alert when instance credentials are used from outside your cloud account',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: '203.0.113.66', x: 120, y: 245 },
    { id: 'app', type: 'server', label: 'Web App on EC2', sub: 'image preview feature', x: 430, y: 245 },
    { id: 'imds', type: 'cloud', label: 'Metadata Service', sub: '169.254.169.254', x: 430, y: 420 },
    { id: 's3', type: 'bucket', label: 'S3 Buckets', sub: 'customer exports', x: 780, y: 120 },
    { id: 'gd', type: 'siem', label: 'GuardDuty', sub: 'threat detection', x: 780, y: 380, good: true },
  ],
  steps: [
    {
      title: 'An SSRF in the app', sub: 'The server fetches any URL',
      text: 'The app has a "preview image from URL" feature that downloads whatever address the user supplies. The attacker gives it an internal address instead of an image, and the server makes the request from inside the cloud network.',
      fields: [['Feature', 'GET /preview?url=…'], ['Weakness', 'No destination allow-list (CWE-918)']],
      packets: [
        ['atk', 'app', 'HTTPS', 'GET /preview?url=http://169.254.169.254/latest/meta-data/', 500, 'atk'],
        ['app', 'imds', 'HTTP', 'GET /latest/meta-data/ (from the server itself)', 200, 'atk'],
        ['imds', 'app', 'HTTP', 'ami-id, hostname, iam/, …', 600, 'res'],
      ],
    },
    {
      title: 'Find the role', sub: 'What credentials does this machine have?',
      text: 'The metadata service lists the IAM role attached to the instance. With the older IMDSv1, a plain GET request is all it takes, so the SSRF can walk the metadata tree like a website.',
      fields: [['Role', 'web-app-role'], ['IMDS version', 'v1 allowed (no session token needed)']],
      packets: [
        ['atk', 'app', 'HTTPS', 'url=…/latest/meta-data/iam/security-credentials/', 520, 'atk'],
        ['app', 'imds', 'HTTP', 'GET …/iam/security-credentials/', 200, 'atk'],
        ['imds', 'app', 'HTTP', 'web-app-role', 120, 'res'],
      ],
    },
    {
      title: 'Steal temporary credentials', sub: 'Keys returned through the app',
      text: 'Requesting the role name returns a temporary access key, secret key and session token. The vulnerable preview feature passes the response straight back to the attacker.',
      fields: [['Returned', 'AccessKeyId, SecretAccessKey, Token'], ['Lifetime', 'Hours, refreshed automatically']],
      packets: [
        ['app', 'imds', 'HTTP', 'GET …/security-credentials/web-app-role', 200, 'atk'],
        ['imds', 'app', 'HTTP', '{AccessKeyId: ASIA…, SecretAccessKey: …, Token: …}', 1400, 'data'],
        ['app', 'atk', 'HTTPS', 'Preview response contains the credentials', 1400, 'data'],
      ],
    },
    {
      title: 'Use them from outside', sub: 'The role\'s permissions are now the attacker\'s',
      text: 'From their own machine, the attacker uses the keys with the cloud CLI. The role was given broad S3 read access "to make things work", so they can list and download customer export buckets. GuardDuty notices the instance credentials being used from an IP address outside AWS and raises a high-severity finding.',
      fields: [['Role permissions', 's3:* on many buckets (too broad)'], ['GuardDuty finding', 'InstanceCredentialExfiltration.OutsideAWS']],
      packets: [
        ['atk', 's3', 'HTTPS', 'ListBuckets + GetObject (stolen session)', 2000, 'atk'],
        ['s3', 'atk', 'HTTPS', 'customer-exports/…', 9000000, 'data'],
        ['s3', 'gd', 'CloudTrail', 'Instance credentials used from 203.0.113.66', 900, 'def'],
      ],
    },
    {
      title: 'Defend with IMDSv2', sub: 'Tokens, hop limits and least privilege',
      text: 'IMDSv2 requires a session token obtained with a `PUT` request and a special header before any metadata can be read. A typical SSRF can only make simple `GET` requests, so it fails. A hop limit of 1 also stops the token from passing through proxies or containers. Fixing the SSRF and narrowing the role close the remaining gaps.',
      fields: [['IMDSv2', 'PUT /latest/api/token first'], ['Hop limit', '1'], ['Role', 'Read one bucket prefix only']],
      defend: 'Turn on "IMDSv2 required" as an account-wide default for new instances, and scan for any that still allow v1.',
      packets: [
        ['atk', 'app', 'HTTPS', 'url=http://169.254.169.254/latest/meta-data/…', 500, 'atk'],
        ['app', 'imds', 'HTTP', 'GET without session token', 200, 'atk'],
        ['imds', 'app', 'HTTP', '401 Unauthorized (IMDSv2 required)', 120, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'public-bucket', domain: 'cloud', kind: 'attack', level: 'Beginner', severity: 'High',
  name: 'Exposed Cloud Storage', full: 'A public bucket full of private files',
  tags: ['s3', 'bucket', 'public bucket', 'cloud storage', 'misconfiguration', 'block public access', 'presigned url', 'macie', 'cloud'],
  summary: 'Cloud storage buckets are private by default, but one wrong policy or setting can make them readable by anyone on the internet. Automated scanners look for exposed buckets constantly. This module shows how the mistake happens, how it\'s found, and how account-wide guardrails prevent it.',
  facts: [['Technique', 'T1530 (Data from Cloud Storage)'], ['Common cause', 'Policy with "Principal": "*"'], ['Guardrail', 'S3 Block Public Access (account level)'], ['Safe sharing', 'Short-lived presigned URLs'], ['Find sensitive data', 'Amazon Macie'], ['Same risk on', 'Azure Blob, Google Cloud Storage']],
  defenses: [
    'Turn on Block Public Access for the whole account, not bucket by bucket',
    'Share individual files with short-lived presigned URLs instead of public buckets',
    'Use a CDN with origin access control for public website assets',
    'Scan buckets for sensitive data and public exposure continuously',
    'Log access to buckets that hold sensitive data',
  ],
  nodes: [
    { id: 'dev', type: 'user', label: 'Developer', sub: 'quick fix', x: 120, y: 120 },
    { id: 'bucket', type: 'bucket', label: 'S3 Bucket', sub: 'acme-invoices', x: 450, y: 245 },
    { id: 'scan', type: 'attacker', label: 'Bucket Scanner', sub: 'automated', x: 120, y: 390 },
    { id: 'cust', type: 'browser', label: 'Customer', sub: 'downloads invoice', x: 800, y: 120 },
    { id: 'cspm', type: 'shield', label: 'Guardrails', sub: 'Block Public Access + CSPM', x: 800, y: 390, good: true },
    { id: 'app', type: 'server', label: 'Invoice App', sub: 'checks ownership', x: 450, y: 420 },
  ],
  steps: [
    {
      title: 'A quick fix', sub: '"Customers can\'t download invoices"',
      text: 'Customers report that invoice links don\'t work. Under pressure, a developer adds a bucket policy that lets everyone read objects, with `"Principal": "*"`. Downloads work again, and so does everything else in the bucket.',
      fields: [['Change', 'Bucket policy: Allow s3:GetObject for *'], ['Also allowed by mistake', 's3:ListBucket']],
      packets: [
        ['dev', 'bucket', 'API', 'PutBucketPolicy: Principal "*" → GetObject, ListBucket', 900, 'atk',
          `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": ["arn:aws:s3:::acme-invoices", "arn:aws:s3:::acme-invoices/*"]
  }]
}`],
        ['cust', 'bucket', 'HTTPS', 'GET /invoices/2026/inv-1182.pdf', 400, 'req'],
      ],
    },
    {
      title: 'Found by scanners', sub: 'Minutes, not months',
      text: 'Automated tools try likely bucket names (company name plus words like "invoices", "backup", "prod") all day. Because listing is allowed, one request returns every file name in the bucket.',
      fields: [['Guessed name', 'acme-invoices'], ['Listing', 'Allowed: 48,000 objects']],
      packets: [
        ['scan', 'bucket', 'HTTPS', 'GET https://acme-invoices.s3.amazonaws.com/', 300, 'atk'],
        ['bucket', 'scan', 'HTTPS', '<ListBucketResult> 48,000 keys', 4800000, 'data'],
      ],
    },
    {
      title: 'Data exposed', sub: 'Not just invoices',
      text: 'The listing shows invoices, but also a database export and a CSV of customer addresses that someone stored there "temporarily". The scanner downloads everything. This is a reportable data breach.',
      fields: [['Exposed', 'Invoices, db-export.sql.gz, customers.csv'], ['Impact', 'Personal data breach']],
      packets: [
        ['scan', 'bucket', 'HTTPS', 'GET /tmp/db-export.sql.gz', 300, 'atk'],
        ['bucket', 'scan', 'HTTPS', '200 (2.1 GB)', 2100000000, 'data'],
      ],
    },
    {
      title: 'Guardrails catch it', sub: 'Block Public Access + posture checks',
      text: 'With Block Public Access turned on for the whole account, the public policy would have been rejected outright. A cloud security posture (CSPM) tool also flags any bucket that becomes public and alerts within minutes.',
      fields: [['Account setting', 'Block Public Access: on'], ['CSPM', 'Alert: bucket made public']],
      packets: [
        ['dev', 'bucket', 'API', 'PutBucketPolicy with Principal "*"', 900, 'atk'],
        ['cspm', 'dev', 'API', 'AccessDenied: public policies blocked for this account', 300, 'def'],
      ],
    },
    {
      title: 'The right way to share', sub: 'Presigned URLs',
      text: 'The real fix for invoice downloads: the app checks the customer is logged in and owns the invoice, then creates a presigned URL valid for five minutes for that one file. The bucket stays completely private.',
      fields: [['Bucket', 'Private'], ['Link', 'Presigned, 5-minute expiry, one object']],
      defend: 'Treat a public bucket as an exception that needs approval, not a setting anyone can flip.',
      packets: [
        ['cust', 'app', 'HTTPS', 'Download invoice 1182 (logged in)', 400, 'req'],
        ['app', 'cust', 'HTTPS', '302 → presigned URL (expires in 300 s)', 600, 'def'],
        ['cust', 'bucket', 'HTTPS', 'GET inv-1182.pdf?X-Amz-Signature=…', 500, 'req'],
      ],
    },
  ],
});

SE.register({
  id: 'cloud-iam-privesc', domain: 'cloud', kind: 'attack', level: 'Advanced', severity: 'Critical',
  name: 'Cloud IAM Privilege Escalation', full: 'Small permissions that add up to admin',
  tags: ['iam', 'privilege escalation', 'passrole', 'aws iam', 'least privilege', 'permission boundary', 'scp', 'access analyzer', 'cloud'],
  summary: 'In the cloud, identity is the perimeter. A user who can\'t do anything dangerous directly may still hold a combination of permissions that lets them borrow a more powerful role. The classic example is being allowed to create a function and "pass" an admin role to it.',
  facts: [['Technique', 'T1098 (Account Manipulation), T1078.004 (Cloud Accounts)'], ['Classic combo', 'iam:PassRole + create/run compute'], ['Other paths', 'Edit own policy, create access keys for others'], ['Guardrails', 'Permission boundaries, SCPs'], ['Analysis', 'IAM Access Analyzer, path-finding tools'], ['Principle', 'Least privilege, no wildcards']],
  defenses: [
    'Avoid wildcards like iam:* and "Resource": "*" in policies',
    'Restrict iam:PassRole to specific roles that the user actually needs',
    'Use permission boundaries so roles a developer creates can\'t exceed their own rights',
    'Apply organisation-wide guardrails (SCPs) for actions nobody should take',
    'Review unused permissions and analyse escalation paths regularly',
  ],
  nodes: [
    { id: 'dev', type: 'user', label: 'Compromised Dev Key', sub: 'limited user', x: 120, y: 245 },
    { id: 'iam', type: 'idp', label: 'IAM', sub: 'roles + policies', x: 450, y: 100 },
    { id: 'fn', type: 'container', label: 'New Function', sub: 'runs as admin role', x: 450, y: 390 },
    { id: 'acct', type: 'cloud', label: 'Cloud Account', sub: 'all resources', x: 800, y: 245 },
    { id: 'trail', type: 'siem', label: 'CloudTrail', sub: 'audit log', x: 800, y: 420, good: true },
  ],
  steps: [
    {
      title: 'A limited foothold', sub: 'Leaked developer credentials',
      text: 'An attacker obtains a developer\'s access key, perhaps from a laptop or a leaked file. The developer\'s policy looks safe: no admin rights, no ability to edit IAM. The attacker starts by listing what this identity can do.',
      fields: [['Identity', 'dev-alice'], ['Looks like', 'Lambda developer, no IAM admin']],
      packets: [
        ['dev', 'iam', 'API', 'GetCallerIdentity + list attached policies', 700, 'atk'],
        ['iam', 'dev', 'API', 'lambda:CreateFunction, lambda:InvokeFunction, iam:PassRole on *', 1800, 'res'],
      ],
    },
    {
      title: 'The dangerous combination', sub: 'PassRole on any role',
      text: '`iam:PassRole` lets a user attach a role to a resource they create. It was granted on `*` "so deployments don\'t fail". Combined with permission to create functions, the user can create code that runs with any role in the account, including an admin role.',
      fields: [['iam:PassRole', 'Resource: * (too broad)'], ['Admin role exists', 'ops-admin-role']],
      packets: [
        ['dev', 'iam', 'API', 'ListRoles → ops-admin-role (AdministratorAccess)', 900, 'atk'],
      ],
    },
    {
      title: 'Borrow the admin role', sub: 'Code runs with someone else\'s rights',
      text: 'The attacker creates a small function, passes `ops-admin-role` to it, and invokes it. The function\'s code calls IAM to create a new access key for an admin user, which it returns. The developer key has become admin access.',
      fields: [['Function role', 'ops-admin-role'], ['Result', 'New admin access key returned']],
      packets: [
        ['dev', 'fn', 'API', 'CreateFunction (role: ops-admin-role) + Invoke', 2400, 'atk'],
        ['fn', 'iam', 'API', 'CreateAccessKey for admin user (as ops-admin-role)', 600, 'atk'],
        ['fn', 'dev', 'API', 'Return new admin key', 400, 'data'],
        ['dev', 'acct', 'API', 'Full access with the new key', 2000, 'atk'],
      ],
    },
    {
      title: 'Spotted in the audit log', sub: 'Unusual IAM activity',
      text: 'CloudTrail records every API call. Detection rules flag a function created with an admin role by a non-admin identity, and an access key created for an admin user from inside a function. The SOC disables the keys and deletes the function.',
      fields: [['Alerts', 'PassRole of admin role by dev; CreateAccessKey from function'], ['Response', 'Disable keys, delete function, review activity']],
      packets: [
        ['iam', 'trail', 'Log', 'PassRole ops-admin-role by dev-alice', 900, 'def'],
        ['iam', 'trail', 'Log', 'CreateAccessKey user=admin by ops-admin-role', 900, 'def'],
      ],
    },
    {
      title: 'Close the path', sub: 'Least privilege with guardrails',
      text: 'PassRole is limited to the specific role the developer\'s functions need. A permission boundary caps anything the developer creates at their own level, and an organisation policy blocks creating access keys for admin users except through a break-glass process. Path-analysis tools are run regularly to catch new combinations.',
      fields: [['PassRole', 'Only arn:…:role/app-function-role'], ['Boundary', 'Applied to all developer-created roles'], ['SCP', 'Deny CreateAccessKey on admins']],
      defend: 'Review permissions as combinations, not one by one. "Harmless" permissions together can equal admin.',
      packets: [
        ['dev', 'iam', 'API', 'CreateFunction with ops-admin-role', 900, 'atk'],
        ['iam', 'dev', 'API', 'AccessDenied: not allowed to pass ops-admin-role', 300, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'kubernetes-security', domain: 'cloud', kind: 'defense', level: 'Advanced', severity: 'Architecture',
  name: 'Kubernetes Security', full: 'From a compromised pod to cluster control, and how to stop it',
  tags: ['kubernetes', 'k8s', 'container security', 'rbac', 'service account', 'network policy', 'pod security', 'eks', 'aks', 'gke', 'cloud'],
  summary: 'Kubernetes runs containers across a cluster and is controlled through its API server. If an attacker compromises one application container, the next question is what that pod can reach: other services, cloud metadata, or the API server with a powerful service account. Good defaults contain the damage.',
  facts: [['Control plane', 'API server, controlled by RBAC'], ['Pod identity', 'Service account token'], ['Isolation', 'Network policies, namespaces'], ['Workload rules', 'Pod Security Standards (restricted)'], ['Escape technique', 'T1611 (Escape to Host)'], ['Benchmark', 'CIS Kubernetes Benchmark']],
  defenses: [
    'Don\'t mount service account tokens into pods that don\'t need the API',
    'Grant RBAC per namespace and per verb; avoid cluster-admin for workloads',
    'Default-deny network policies, then allow only needed traffic',
    'Enforce the "restricted" Pod Security Standard: no privileged pods, no host mounts, non-root',
    'Block pod access to the cloud metadata service and scan images before deploy',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'Attacker', sub: 'via app bug', x: 120, y: 245 },
    { id: 'pod', type: 'container', label: 'Web Pod', sub: 'namespace: shop', x: 420, y: 245 },
    { id: 'api', type: 'server', label: 'K8s API Server', sub: 'RBAC', x: 780, y: 110, good: true },
    { id: 'db', type: 'db', label: 'Payments DB Pod', sub: 'namespace: payments', x: 780, y: 270 },
    { id: 'node', type: 'server', label: 'Worker Node', sub: 'host', x: 780, y: 420 },
  ],
  steps: [
    {
      title: 'Foothold in a pod', sub: 'One vulnerable app container',
      text: 'An attacker exploits a bug in the web app and can run commands inside its container. They look around: environment variables, mounted files, and the service account token Kubernetes mounts into pods by default.',
      fields: [['Access', 'Shell in web pod'], ['Found', 'Service account token at /var/run/secrets/…']],
      packets: [
        ['atk', 'pod', 'HTTPS', 'Exploit app bug → command execution', 800, 'atk'],
        ['pod', 'pod', 'Local', 'Read mounted service account token', 0, 'data'],
      ],
    },
    {
      title: 'Ask the API server', sub: 'What can this service account do?',
      text: 'With the token, the attacker queries the API server. In a well-configured cluster, the web app\'s service account has no permissions at all, and every request is denied. In a poorly configured one, it might be able to list secrets or create pods.',
      fields: [['Good RBAC', 'Forbidden for everything'], ['Bad RBAC', 'list secrets, create pods = cluster takeover']],
      packets: [
        ['pod', 'api', 'HTTPS', 'GET /api/v1/namespaces/shop/secrets (Bearer SA token)', 900, 'atk'],
        ['api', 'pod', 'HTTPS', '403 Forbidden: serviceaccount shop:web cannot list secrets', 400, 'def'],
      ],
    },
    {
      title: 'Move sideways', sub: 'Network policies',
      text: 'Next the attacker tries to reach the payments database directly. Without network policies, every pod can talk to every other pod. Here a default-deny policy only lets the payments API reach the database, so the connection is dropped.',
      fields: [['Policy', 'Default deny; payments-api → payments-db only'], ['Result', 'Connection dropped']],
      packets: [
        ['pod', 'db', 'TCP', 'Connect payments-db:5432 from web pod', 74, 'atk'],
        ['db', 'pod', 'Policy', 'Dropped by NetworkPolicy', 0, 'def'],
      ],
    },
    {
      title: 'Try to escape', sub: 'Privileged containers and host mounts',
      text: 'If the pod ran as privileged or mounted the host filesystem, the attacker could break out to the worker node and every pod on it. The "restricted" Pod Security Standard blocks those settings, so this pod runs as non-root with no extra capabilities.',
      fields: [['Privileged', 'false'], ['runAsNonRoot', 'true'], ['Host mounts', 'None']],
      packets: [
        ['pod', 'node', 'Syscall', 'Attempt host access (mount / capabilities)', 0, 'atk'],
        ['node', 'pod', 'Kernel', 'Operation not permitted', 0, 'def'],
      ],
    },
    {
      title: 'Layered defaults', sub: 'Each layer limits the blast radius',
      text: 'Because the token wasn\'t useful, network policies blocked lateral movement and the pod couldn\'t escape, the compromise stayed inside one container. Runtime detection alerted on the unusual shell, and the pod was replaced from a clean image while the app bug was fixed.',
      fields: [['Contained to', 'One pod'], ['Detected by', 'Runtime security alert'], ['Recovery', 'Redeploy clean image + patch']],
      defend: 'Also set automountServiceAccountToken: false for apps that never call the Kubernetes API.',
      packets: [
        ['pod', 'api', 'Event', 'Runtime alert: shell spawned in web container', 600, 'def'],
        ['api', 'pod', 'HTTPS', 'Delete pod → replaced from patched image', 400, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'cloud-detection', domain: 'cloud', kind: 'defense', level: 'Intermediate', severity: 'Control',
  name: 'Cloud Logging & Detection', full: 'Seeing what happens in your cloud accounts',
  tags: ['cloudtrail', 'guardduty', 'security hub', 'cspm', 'cloud logging', 'detection', 'root account', 'mfa', 'cloud'],
  summary: 'In the cloud, almost everything is an API call, and every API call can be logged. Audit logs, managed threat detection and posture management tools together show who did what, flag suspicious behaviour, and catch risky settings before attackers do.',
  facts: [['Audit log', 'AWS CloudTrail (Azure Activity Log, GCP Cloud Audit Logs)'], ['Threat detection', 'Amazon GuardDuty'], ['Posture', 'CSPM / Security Hub'], ['Benchmark', 'CIS AWS Foundations'], ['Protect logs', 'Separate log account, immutable storage'], ['Alert on', 'Root use, logging changes, new keys']],
  defenses: [
    'Turn on audit logging in every account and region, sent to a separate log account',
    'Protect logs from deletion with object lock and restricted access',
    'Enable managed threat detection and route findings to the SOC',
    'Alert on root account use, MFA changes, new access keys and logging being disabled',
    'Continuously check settings against a benchmark and fix drift',
  ],
  nodes: [
    { id: 'user', type: 'user', label: 'Cloud Users', sub: 'console + API', x: 120, y: 120 },
    { id: 'atk', type: 'attacker', label: 'Intruder', sub: 'stolen key', x: 120, y: 380 },
    { id: 'aws', type: 'cloud', label: 'Cloud Account', sub: 'production', x: 450, y: 245 },
    { id: 'logs', type: 'bucket', label: 'Log Archive', sub: 'separate account', x: 800, y: 110, good: true },
    { id: 'soc', type: 'siem', label: 'SIEM / SOC', sub: 'alerts', x: 800, y: 380, good: true },
  ],
  steps: [
    {
      title: 'Every action is an API call', sub: 'Audit logging',
      text: 'Whether someone clicks in the console or runs a script, each action becomes an API call: who, what, when, from where and whether it succeeded. CloudTrail records these and delivers them to a log bucket in a separate, locked-down account, so an attacker in production can\'t erase them.',
      fields: [['Captured', 'Identity, action, source IP, time, result'], ['Stored in', 'Separate log archive account']],
      packets: [
        ['user', 'aws', 'API', 'RunInstances, PutObject, AssumeRole…', 40000, 'req'],
        ['aws', 'logs', 'CloudTrail', 'Event records (every region)', 120000, 'def'],
      ],
    },
    {
      title: 'Suspicious behaviour', sub: 'Managed threat detection',
      text: 'An intruder uses a stolen access key from an unusual country and starts listing everything: users, buckets, instances. GuardDuty analyses the logs and network data, recognises this reconnaissance pattern from an unfamiliar location, and raises a finding.',
      fields: [['Activity', 'Mass List*/Describe* calls'], ['Finding', 'Unusual discovery API calls from new location']],
      packets: [
        ['atk', 'aws', 'API', 'ListUsers, ListBuckets, DescribeInstances × 400', 360000, 'atk'],
        ['aws', 'soc', 'Finding', 'GuardDuty: anomalous discovery activity (high)', 1400, 'def'],
      ],
    },
    {
      title: 'Attempts to hide', sub: 'Watch the watchers',
      text: 'Next the intruder tries to stop CloudTrail logging. That call itself is logged, and a high-priority rule fires immediately. An organisation policy also denies stopping or deleting the trail, so the attempt fails.',
      fields: [['Call', 'StopLogging'], ['Result', 'Denied by organisation policy + alert']],
      packets: [
        ['atk', 'aws', 'API', 'cloudtrail:StopLogging', 600, 'atk'],
        ['aws', 'atk', 'API', 'AccessDenied (organisation policy)', 300, 'def'],
        ['aws', 'soc', 'Alert', 'CRITICAL: attempt to stop CloudTrail', 900, 'def'],
      ],
    },
    {
      title: 'Posture checks', sub: 'Finding risky settings before attackers do',
      text: 'Separately, a posture tool checks every account against a benchmark: root account without MFA, security groups open to the world on SSH, unencrypted volumes, buckets made public. Each failed check becomes a ticket with an owner.',
      fields: [['Failed checks', 'SSH open to 0.0.0.0/0; unencrypted volume'], ['Benchmark', 'CIS AWS Foundations']],
      packets: [
        ['aws', 'soc', 'CSPM', '2 failed controls in production', 3000, 'def'],
      ],
    },
    {
      title: 'Respond', sub: 'From finding to fix',
      text: 'The SOC disables the stolen key, checks CloudTrail for everything it did, and confirms nothing was changed. The posture issues are fixed through infrastructure code so they don\'t come back.',
      fields: [['Key', 'Deactivated'], ['Scope', 'Read-only reconnaissance, no changes'], ['Posture', 'Fixed in Terraform']],
      defend: 'Alert on the handful of events that almost always matter: root sign-in, logging changes, new admin keys, and MFA removed.',
      packets: [
        ['soc', 'aws', 'API', 'UpdateAccessKey → Inactive', 300, 'def'],
        ['soc', 'logs', 'Query', 'All events for the stolen key, last 7 days', 400, 'req'],
      ],
    },
  ],
});
