---
name: support-bot-action-approval-review
description: >
  Reviews support bots, customer-service copilots, and ticket automation that can
  trigger account, billing, entitlement, or security-sensitive actions. Focuses on
  approval boundaries, actor separation, step-up authentication, replay resistance,
  audit provenance, and safe fallback behavior. Produces findings mapped to OWASP
  ASVS, OWASP API Security, NIST SP 800-53, and CWE identifiers.
tags: [identity, auth, support-automation, approval, audit]
role: [security-engineer, appsec-engineer, vciso]
phase: [design, build, operate, review]
frameworks: [OWASP-ASVS, OWASP-API-Security-2023, NIST-SP-800-53, CWE]
difficulty: intermediate
time_estimate: "30-60min"
version: "1.0.0"
author: Ziliang-H
license: MIT
allowed-tools: [Read, Grep, Glob]
injection-hardened: true
argument-hint: "[support-bot-or-automation-source-directory]"
---

# Support Bot Action Approval Review

A structured review for support bots, helpdesk copilots, customer-service
automation, and ticket-driven workflows that can do more than answer questions.
The core question is: **can a bot, a support agent, or a customer-controlled
message trigger a privileged account, billing, entitlement, or security action
without the right approval and provenance?**

Use this skill for AI support assistants, ticket macros, workflow builders,
customer success automation, chat-to-action tools, refund bots, subscription
management assistants, and internal support consoles that call product APIs.

---

## Step 1: Map The Action Boundary

If a target is provided via arguments, focus the review on: $ARGUMENTS

Create an inventory of every action the bot or automation can initiate.

1. **Read-only answers** -- retrieval, summarization, article suggestions, status
   lookups, and internal knowledge-base search.
2. **Low-risk changes** -- adding notes, tagging tickets, sending canned replies,
   or updating non-sensitive preferences.
3. **Customer-impacting changes** -- changing plan, credits, shipping address,
   notification settings, feature flags, or account metadata.
4. **Billing actions** -- refunds, invoices, coupons, payment-method changes,
   cancellations, renewal changes, or usage adjustments.
5. **Identity/security actions** -- email changes, password resets, MFA resets,
   session revocation, role changes, account merges, bans, unbans, exports, or
   deletion.
6. **External actions** -- webhooks, CRM updates, marketplace actions, vendor API
   calls, or emails sent outside the support platform.

> **Gate:** Treat actions in categories 3-6 as privileged until the design proves
> the bot cannot perform them without explicit authorization, appropriate human
> approval, and auditable provenance.

---

## Step 2: Required Evidence

Collect evidence from code, workflow definitions, support-platform settings,
runbooks, audit logs, and product API authorization checks.

| Evidence | Why it matters |
|---|---|
| Action allowlist | Shows which operations the bot is permitted to call |
| Actor identity | Distinguishes customer, support agent, bot service, and approver |
| Approval workflow | Proves high-impact actions require the right human or policy gate |
| Step-up controls | Prevents stale support sessions from authorizing sensitive changes |
| Ticket binding | Ties the action to a specific customer request and ticket state |
| API authorization | Ensures backend APIs do not trust the bot alone |
| Idempotency/replay guard | Prevents repeated refunds, resets, or entitlement changes |
| Audit record | Preserves who requested, who approved, what changed, and why |
| Rollback/fallback path | Limits damage when the bot acts incorrectly or partially fails |

If evidence is missing, classify the result as a review gap before assuming the
implementation is safe.

---

## Step 3: Vulnerable Patterns

### 3.1 Bot Service Account Bypasses User Authorization

**Risk:** OWASP API1:2023 -- Broken Object Level Authorization,
CWE-862 -- Missing Authorization.

```typescript
// VULNERABLE: any authenticated support session can ask the bot to update any
// customer because the backend trusts the bot service account.
app.post("/support-bot/actions/change-plan", requireSupportLogin, async (req, res) => {
  await billing.changePlan({
    customerId: req.body.customerId,
    plan: req.body.plan,
    actor: "support-bot",
  });
  res.json({ ok: true });
});
```

Review questions:

- Does the product API authorize the human support agent, not only the bot token?
- Is the target customer bound to the open ticket or verified support context?
- Are tenant, organization, and reseller boundaries rechecked at the action API?
- Can the bot act on customer ids supplied by a prompt, chat message, or macro?

Safer pattern:

```typescript
const ticket = await tickets.requireOpenOwnedTicket(req.user.id, req.body.ticketId);
const plan = await billingPlans.requireAllowedPlan(req.body.plan);
await authz.requireSupportPermission(req.user.id, "billing.plan.change", ticket.customerId);
await billing.changePlan({ customerId: ticket.customerId, plan, actor: req.user.id });
```

### 3.2 High-Risk Actions Lack Human Approval

**Risk:** OWASP ASVS V4 -- Access Control,
NIST SP 800-53 AC-6 -- Least Privilege,
CWE-266 -- Incorrect Privilege Assignment.

```yaml
workflow:
  trigger: customer_message_contains("refund")
  action:
    type: issue_refund
    amount: "{{ invoice.balance }}"
    approval_required: false
```

Review questions:

- Which actions require approval, and who is allowed to approve them?
- Are approvals required for refunds, account merges, email changes, MFA resets,
  role changes, bans, unbans, exports, and deletion?
- Are approval rules based on amount, account risk, customer tier, data
  sensitivity, or regulatory impact?
- Does the system prevent the requester from approving their own action?

Safer pattern:

```yaml
approval:
  required_when:
    - action in ["refund", "mfa_reset", "email_change", "account_merge"]
    - refund_amount > 50
  approver_role: support_lead
  requester_cannot_approve: true
  expires_after: 30m
```

### 3.3 Prompt Or Ticket Text Can Choose The Action

**Risk:** OWASP LLM01 -- Prompt Injection,
OWASP API3:2023 -- Broken Object Property Level Authorization,
CWE-20 -- Improper Input Validation.

```python
# VULNERABLE: model output directly selects tool and arguments.
decision = llm.complete(ticket.body, tools=["refund", "reset_mfa", "change_email"])
tool_runner.run(decision.tool_name, decision.arguments)
```

Review questions:

- Is the model limited to recommending actions rather than executing them?
- Is tool selection constrained by a server-side allowlist for the ticket type?
- Are tool arguments validated against trusted system state?
- Are instructions inside customer messages, ticket notes, attachments, or CRM
  fields treated as untrusted content?

Safer pattern:

```python
recommendation = model.suggest_action(ticket_summary)
allowed = policy.allowed_actions(ticket.type, agent.role, customer.risk_level)
action = require_human_selection(recommendation, allowed)
validate_against_trusted_state(action, ticket, customer)
```

### 3.4 No Step-Up For Sensitive Support Actions

**Risk:** OWASP ASVS V2/V4 -- Authentication and Access Control,
NIST SP 800-53 IA-2 -- Identification and Authentication.

Review questions:

- Does the support agent need fresh MFA or reauthentication before sensitive
  actions?
- Are long-lived support sessions allowed to reset MFA, change emails, refund
  money, or export data?
- Are step-up requirements risk based, including unusual location, new device,
  high-value customer, or high-impact action?
- Are service-to-service calls scoped to the approved action and short-lived?

Finding trigger:

```
SUPPORT-BOT-STEPUP-01: Sensitive action uses only the support agent's existing
web session, with no recent-auth or MFA age check.
```

### 3.5 Approval Is Not Bound To The Final Action

**Risk:** CWE-367 -- Time-of-check Time-of-use Race Condition,
CWE-345 -- Insufficient Verification of Data Authenticity.

```json
{
  "approval_id": "apr_123",
  "approved_action": "refund",
  "approved_amount": 25,
  "executed_amount": 250
}
```

Review questions:

- Is the approval bound to action type, target customer, amount, currency, and
  expiration?
- Can the final request change arguments after approval?
- Are approvals single-use?
- Are approvals invalidated when the ticket, account state, or customer risk
  changes?

Safer pattern:

```text
approval_hash = H(action_type, customer_id, amount, currency, ticket_id, expires_at)
execute only if request hash exactly matches the approved hash.
```

### 3.6 Missing Audit Provenance

**Risk:** NIST SP 800-53 AU-2/AU-12 -- Audit Events and Audit Record Generation,
CWE-778 -- Insufficient Logging.

Review questions:

- Does the audit log record customer id, ticket id, requester, approver, bot
  version, action, before/after values, reason, and correlation id?
- Are model suggestions and final human decisions both recorded?
- Are logs immutable enough for dispute handling and incident response?
- Are denied or expired approvals logged, not only successful actions?

Minimum audit record:

```json
{
  "event": "support_action.executed",
  "action": "refund",
  "ticket_id": "TCK-491",
  "customer_id": "cus_123",
  "requested_by": "agent_7",
  "approved_by": "lead_2",
  "bot_run_id": "run_abc",
  "approval_id": "apr_123",
  "before": {"balance": 2500},
  "after": {"balance": 0}
}
```

---

## Step 4: Classification

Use the highest applicable severity.

| Severity | Finding pattern |
|---|---|
| Critical | Bot or support workflow can perform MFA reset, email change, account takeover, account deletion, or role elevation without backend authorization and approval |
| High | Bot can issue refunds, change billing, merge accounts, export sensitive data, or alter entitlements without approval binding, step-up, or audit provenance |
| Medium | Approval exists but is not single-use, not bound to exact action arguments, or lacks requester/approver separation |
| Low | Documentation, runbooks, or audit fields are incomplete, but backend authorization and approval controls are present |

Do not downgrade solely because the action is "internal-only" if the support
console is reachable by many agents, contractors, vendors, or outsourced support
teams.

---

## Step 5: False Positive Gates

Before reporting, check whether the design has compensating controls.

- **Recommendation-only bot:** The bot suggests text or actions, but a human must
  choose an action in a separate trusted UI and the backend enforces permission.
- **Read-only support assistant:** The bot cannot call mutating APIs or external
  webhooks.
- **Low-risk workflow:** Actions only tag tickets or add internal notes and cannot
  affect customer state.
- **Server-side policy engine:** A central policy engine evaluates action type,
  customer, requester, approver, amount, and risk before execution.
- **Strong approval binding:** Approval is single-use and cryptographically or
  transactionally bound to exact final arguments.
- **Complete audit trail:** Logs include requester, approver, bot run, ticket,
  before/after state, and denial/expiry events.

If a false-positive gate applies, record it as a control instead of a finding.

---

## Step 6: Output Format

Return findings in this structure:

```markdown
## Support Bot Action Approval Review

### Scope
- Bot/workflow reviewed:
- Mutating actions discovered:
- High-risk actions:

### Findings
| ID | Severity | Title | Evidence | Framework/CWE | Remediation |
|---|---|---|---|---|---|

### Approval Matrix
| Action | Required actor | Approval required | Step-up required | Audit fields |
|---|---|---|---|---|

### Positive Controls
- Control:
- Evidence:

### Open Questions
- Question:
```

Every finding must identify the specific action, actor, target, missing control,
and evidence source.

---

## Quick Grep Hints

Use these only as starting points; confirm findings manually.

```bash
rg -n "refund|credit|cancel|change.*email|reset.*mfa|reset.*password|merge.*account|ban|unban|delete.*account|export.*data"
rg -n "tool|function_call|workflow|macro|approval|approver|support.*bot|assistant|copilot"
rg -n "ticket_id|customer_id|actor|approved_by|requested_by|audit|provenance|idempotency"
rg -n "service_account|bot_token|impersonat|on_behalf|delegate|step_up|reauth|mfa"
```

