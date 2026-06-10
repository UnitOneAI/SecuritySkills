---
name: tool-authorization-drift
description: >
  Reviews agentic systems for drift between declared tool permissions and
  effective runtime authorization. Covers preview/execute confusion, delegated
  tool calls, approval cache scope and TTL, tool alias mapping, indirect
  state-changing workflows, and audit evidence. Use when an LLM or agent can
  select tools, call functions, request approvals, or pass tool results to other
  executors.
tags: [ai-security, agents, authorization, tool-use, policy-drift]
role: [security-engineer, appsec-engineer, architect]
phase: [design, build, review, operate]
frameworks: [OWASP-Agentic-AI, OWASP-LLM06-2025, CWE-285]
difficulty: advanced
time_estimate: "45-90min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[agent-tool-policy-or-runtime-code]"
---

# Tool Authorization Drift Review

If a target is provided via arguments, focus the review on: $ARGUMENTS

> **This skill is strictly for defensive review.** It compares tool policy,
> approval, runtime enforcement, and audit evidence in systems you own or are
> authorized to assess. Do not execute tools, approve actions, transfer funds,
> change data, or call external services while reviewing.

## Security Outcome

Ensure an agent cannot perform an action that its declared policy, user approval,
tenant scope, or runtime authorization should deny.

## When to Use

Use this skill when reviewing:

- LLM tools, function calling, MCP connectors, plugin systems, or internal
  workflow tools;
- policy files that declare tool names, scopes, roles, tenants, or risk levels;
- approval flows for tool execution;
- preview/dry-run and execute tool pairs;
- delegated calls from one agent, workflow, or service to another;
- caches, queues, retries, or background workers that execute tool requests;
- audit logs that claim to prove who authorized and executed a tool call.

Pair it with `agent-security` for broader architecture reviews. Use this skill
when the central question is: "Does runtime enforcement exactly match the
declared tool authorization model?"

## Review Workflow

### 1. Build the Tool Authorization Matrix

Create a matrix from policy, code, and logs:

| Tool | Declared action | Runtime handler | Scope key | Approval required | Side effect |
|---|---|---|---|---|---|
| `invoice.preview` | read | preview handler | tenant, user | no | none |
| `invoice.send` | write | send handler | tenant, user, invoice | yes | sends invoice |

Every runtime handler must map to exactly one declared capability. If handlers
are invoked through aliases, queues, routers, or dynamic dispatch, include those
paths explicitly.

### 2. Compare Declared Policy to Runtime Enforcement

Check whether enforcement happens at the moment of execution, not only at prompt
construction or UI display.

Required evidence:

- declared tool name, action, resource type, tenant, and risk level;
- code that resolves the tool handler;
- code that checks actor, target resource, tenant, approval, and scope;
- tests or logs showing denied tools are denied at runtime;
- default behavior for missing, unknown, aliased, or renamed tools.

### 3. Review Preview/Execute Separation

Preview tools and execute tools must be separate capabilities. A preview result
must not be accepted as an execute instruction.

Look for:

- shared handler for preview and execute with a weak `mode` parameter;
- preview result object forwarded to a worker that performs the action;
- cached approval for `*.preview` reused for `*.execute`;
- UI text or model output converted into an execute payload;
- tool aliases that map a safe preview name to a state-changing handler.

### 4. Inspect Approval Tokens and Caches

Approval must be bound to the exact action that will execute.

Verify approval tokens include:

- actor and requester;
- target tenant and resource;
- tool name and action;
- risk level and allowed parameters;
- delegation chain, if any;
- expiry and single-use or replay controls;
- reason, ticket, or user confirmation evidence.

Cache keys must include the same fields. Any cache key that omits tool, action,
tenant, resource, actor, or approval version is a drift risk.

### 5. Trace Delegation and Background Execution

Tool authorization often drifts when an allowed tool hands work to another
system.

Review:

- queue payloads, background workers, retries, and schedulers;
- service-to-service calls made after the original agent request;
- delegated sub-agent policies and inherited scopes;
- webhook callbacks and async continuations;
- "safe" tools that return signed URLs, job IDs, or command payloads consumed by
  privileged workers.

Runtime workers must re-check authorization using durable context, not trust an
agent-supplied payload.

### 6. Validate Audit Evidence

Audit records must show both the declared authorization decision and the runtime
execution decision.

Each event should include:

- policy version and matched rule;
- requested tool and resolved handler;
- actor, tenant, target resource, and approval ID;
- delegation chain and background job ID;
- runtime decision, denial reason, or execution result;
- parameter digest or safe redacted parameter summary.

## High-Signal Findings

Report a finding when:

- a denied tool can be reached through alias, router, queue, or delegated call;
- preview approval or preview output can trigger execute behavior;
- approval cache keys omit tool, action, tenant, actor, resource, or policy
  version;
- runtime handlers trust model-generated or client-provided authorization
  fields;
- background workers execute tool payloads without re-checking scope;
- policy denies a capability but logs show the handler executes;
- audit logs record requested tool names but not resolved runtime handlers;
- missing policy entries default to allow.

## Remediation Guidance

- Treat each tool/action pair as a separate capability.
- Enforce authorization in the runtime handler and background worker.
- Bind approvals to exact tool, action, tenant, resource, actor, policy version,
  parameters, and expiry.
- Make preview outputs non-executable and structurally different from execute
  payloads.
- Resolve aliases before policy checks and log both alias and canonical handler.
- Fail closed for unknown tools, missing policy, stale approvals, and mismatched
  tenant/resource scope.
- Re-check delegated calls and queue workers using server-side context.
- Add tests that prove denied tools remain denied through aliases, retries, and
  delegation.

## Verification Checklist

- [ ] every runtime handler maps to a declared capability;
- [ ] unknown or missing policy entries fail closed;
- [ ] preview and execute capabilities have separate approval requirements;
- [ ] approval tokens include tool, action, tenant, resource, actor, policy
      version, and expiry;
- [ ] cache keys include the same fields as approval tokens;
- [ ] background workers re-check authorization before side effects;
- [ ] delegated calls preserve and constrain scope;
- [ ] audit records include requested tool, resolved handler, policy rule, and
      runtime decision;
- [ ] tests cover alias bypass, stale approval, preview/execute confusion, and
      cross-tenant delegation.

## Evidence to Request

- tool policy files and generated tool manifests;
- function-calling or MCP registration code;
- tool router and handler resolution logic;
- approval token generation and validation;
- cache keys for approvals and authorization decisions;
- queue payload schemas and worker code;
- audit event schema and logs;
- tests for denied tools, preview/execute separation, and delegated execution.

## Reporting Template

```markdown
### Finding: tool authorization drift in <tool/workflow>

Severity: High
Affected flow: <declared policy -> runtime handler -> side effect>
Evidence:
- <policy showing declared deny or scoped allow>
- <handler/router/cache/worker showing drift>
Impact: <action the agent can perform beyond policy>
Required fix:
- <runtime enforcement, approval binding, cache key, or delegation control>
Verification:
- <test proving the denied action fails through alias/delegation/retry>
```

## Common False Positives

- A preview tool returns text that a human must manually copy into a separate
  approved workflow.
- A background worker executes only after re-validating a server-side approval
  token bound to the exact action and resource.
- A broad tool name is safe because the handler dispatches to narrower
  server-side capabilities and logs the resolved handler.
- Test fixtures intentionally include denied tools but are not reachable in
  production routes.

## References

- OWASP Agentic AI security patterns for tool misuse and excessive agency
- OWASP LLM06:2025 Excessive Agency
- CWE-285 Improper Authorization
- CWE-863 Incorrect Authorization
- NIST AI RMF Map and Manage functions
