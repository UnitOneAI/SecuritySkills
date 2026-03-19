# Agent Security — Security Posture Evaluation Matrix

## Permission Model Evaluation

| Principle | What to Check | Finding If Absent |
|---|---|---|
| Least privilege | Each agent has only the tools it needs | High -- excessive agency |
| Separation of duties | Read agents cannot write; analysis agents cannot execute | High -- insufficient separation |
| Scoped credentials | Service identity permissions match tool requirements, no wildcards | High -- over-privileged identity |
| Per-task scoping | Tool set varies by task, not globally assigned | Medium -- static over-provisioning |
| Time-bounded access | Credentials and tool access expire, requiring renewal | Medium -- persistent access risk |
| Explicit deny | Actions not explicitly permitted are denied by default | High -- fail-open permission model |

## Least-Privilege Design Checklist

| Control Layer | Desired State | Common Violation |
|---|---|---|
| Tool access | Only task-relevant tools per invocation | Full tool registry always available |
| Data access | Only data needed for current task | Agent can query any table, any collection |
| Network egress | Allowlisted destinations only | Unrestricted outbound access |
| File system | Sandboxed to working directory | Host file system fully accessible |
| Secrets | No direct access; tools broker secret access | Agent can read all env vars including secrets |
| Compute | Hard limits on tokens, time, memory | No limits; agent runs until it decides to stop |
| Self-modification | Immutable config at runtime | Agent can modify its own tools or prompts |

## HITL Gate Design Principles

| Principle | Description | Anti-Pattern |
|---|---|---|
| Fail-closed | Agent halts if approval service is unavailable | Agent proceeds without approval on timeout |
| Full context | Approver sees the complete action with all parameters | Approver sees "Agent wants to run a tool" with no details |
| Cumulative tracking | System tracks aggregate session risk, not just per-action risk | Each action evaluated independently |
| Action classification | Actions categorized by risk level with different approval requirements | Binary approve/deny with no risk differentiation |
| Approval diversity | Critical actions require multiple approvers | Single click from one reviewer |
| Anti-fatigue | Rate-limited approval requests | Hundreds of identical-looking requests |
| Immutable gates | Approval logic in infrastructure, not modifiable by agent | Approval thresholds in agent-accessible storage |

## Multi-Agent Trust Boundary Evaluation

| Control | Secure State | Insecure State |
|---|---|---|
| Inter-agent auth | Signed messages with verified identity | Plain text messages, no sender verification |
| Authorization model | Explicit allowlist of permitted inter-agent requests | Any agent can request anything from any agent |
| Memory isolation | Per-agent memory; shared state mediated by trusted broker | All agents read/write shared memory directly |
| Delegation control | Maximum depth; no permission escalation; explicit policy | Unbounded delegation; delegated agents inherit full permissions |
| Output validation | Receiving agent validates incoming data against schema | Receiving agent trusts all incoming data as instructions |
| Trust documentation | Explicit trust model document defining boundaries | Implicit trust; no documentation |

## Architecture Security Posture Summary Template

| Review Area | Rating | Key Finding | Priority |
|---|---|---|---|
| Permission Model | [CRITICAL/HIGH/MEDIUM/LOW/PASS] | [one-line summary] | [P0/P1/P2/P3] |
| Least-Privilege Design | [rating] | [one-line summary] | [priority] |
| HITL Gate Placement | [rating] | [one-line summary] | [priority] |
| Blast Radius Containment | [rating] | [one-line summary] | [priority] |
| Audit Trail Completeness | [rating] | [one-line summary] | [priority] |
| Rollback Capability | [rating] | [one-line summary] | [priority] |
| Multi-Agent Trust Boundaries | [rating] | [one-line summary] | [priority] |
