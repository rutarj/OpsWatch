# Who this is for, and how to pitch it

## Roles this project targets

| Role | What to lead with |
|---|---|
| **Junior AI Developer / AI Engineer** | MCP server design, forced structured output, fallback behavior, eval harness with held-out data, leakage guard, CI gate |
| **AI Consultant / Associate Consultant** | The business problem (triage backlog), human-in-the-loop design that a risk-averse client (a bank) will actually sign off on, OWASP mapping, the honest eval |
| **ServiceNow / ITSM roles with AI** | ITIL priority matrix, incident vs change, CAB-style approval, assignment groups, KB-driven resolution |
| **AI QA / Evaluation** | Selective accuracy vs coverage curve, injection detector precision/recall, confidently-wrong failure analysis, regression gate |
| **Cloud / DevOps** | SNS signature verification, CloudWatch alarm-to-incident automation, Docker, CI with container smoke test, the C1 bridge |

## Client scenarios (for consulting-style interviews)

**Campus IT service desk.** Semester start floods the queue with password, Wi-Fi and classroom AV tickets. OpsWatch pre-triages and attaches the right KB article; agents approve in one click; uncertain and security tickets go to a person.

**Bank IT operations.** Every change needs an approval trail. OpsWatch's proposals behave like change requests: separation of duties, senior sign-off for high risk, freeze windows, and an audit log that proves nobody edited history.

**Managed service provider running cloud workloads.** CloudWatch alarms from client environments become incidents with runbooks attached, deduplicated, and never auto-resolved when customer-facing.

## One-line pitches

- "An AI service desk assistant built the way a bank's change management works: the AI proposes, a human approves, and the audit log can't be quietly edited."
- "I measured it honestly: both cheap baselines score about 57% on unseen phrasing, which is exactly why the design only pays for the LLM on uncertain tickets."
