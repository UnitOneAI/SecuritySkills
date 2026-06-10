---
name: admin-impersonation-feature-review
description: >
  Reviews SaaS admin impersonation and support "login as user" features for
  approval, reason capture, session marking, action restrictions, actor/target
  audit trails, tenant boundaries, revocation, and timeout controls. Use when a
  product lets staff, support, success, or administrators act through a customer
  user's account or view their experience.
tags: [identity, impersonation, admin, audit, authorization]
role: [security-engineer, appsec-engineer, vciso]
phase: [design, build, operate, review]
frameworks: [OWASP-ASVS, NIST-SP-800-53-AC, NIST-SP-800-53-AU, CWE-285]
difficulty: intermediate
time_estimate: "30-60min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[admin-or-support-impersonation-code]"
---

# Admin Impersonation Feature Review

If a target is provided via arguments, focus the review on: $ARGUMENTS

> **This skill is strictly for defensive review.** It helps teams assess
> impersonation features they own or are authorized to test. Do not use this
> guidance to access accounts, change customer data, bypass consent, or perform
> live impersonation. Review code, configuration, logs, and documented behavior.

## Security Outcome

Ensure staff impersonation is explicit, approved, scoped, visible, auditable,
revocable, and unable to cross tenants or perform high-risk customer actions
without independent authorization.

## When to Use

Use this skill when reviewing:

- "login as user", "view as customer", support sessions, customer success
  sessions, or admin impersonation flows;
- staff dashboards that mint user sessions or switch actor context;
- debugging tools that proxy customer API calls;
- production support tooling that can see, edit, export, or approve customer
  data;
- audit trails for staff activity inside customer accounts.

Do not substitute this for a full PAM review. Pair it with `privileged-access`
when standing admin privilege, break-glass access, or credential vaulting is also
in scope.

## Review Workflow

### 1. Map Actor, Target, and Scope

For every impersonation entry point, record:

| Field | Evidence to collect |
|---|---|
| Actor | staff user, role, group, MFA state, support assignment |
| Target | customer user, tenant, environment, account status |
| Reason | ticket, incident, customer approval, business justification |
| Approval | approver, policy rule, expiration, dual-control requirement |
| Session scope | read-only, writable, billing, security, admin, export |
| Session identity | token claims, session marker, UI banner, API header |
| Exit path | manual stop, timeout, revocation, target password reset |

If actor and target cannot be reconstructed for a session, treat that as a high
confidence auditability gap.

### 2. Check Entry-Point Authorization

Confirm the system verifies all of the following before creating an
impersonation session:

- actor is authenticated with a staff account and recent MFA;
- actor has a role allowed to impersonate the target's tenant;
- actor is assigned to a valid case, ticket, incident, or approval;
- reason is captured and cannot be empty or generic;
- target account is eligible for impersonation;
- session scope is the narrowest needed for the support task;
- tenant and environment boundaries are enforced server-side.

High-risk targets, such as tenant owners, billing admins, security admins, and
regulated accounts, should require stronger approval or be excluded.

### 3. Verify Session Marking and User Visibility

Impersonation sessions must not look like normal customer sessions.

Review for:

- token/session claims that preserve both `actor_id` and `target_user_id`;
- visible staff banner or watermark in UI;
- API request context that carries impersonation state;
- inability to hide or downgrade the impersonation marker client-side;
- notifications or audit visibility when policy requires customer awareness;
- logs that never collapse actor and target into the same principal.

### 4. Restrict High-Risk Actions

During impersonation, the safest default is read-only unless the task requires a
specific write capability.

Block or require separate step-up approval for:

- password, MFA, SSO, recovery email, or passkey changes;
- payment method, payout, billing owner, invoice, or refund changes;
- security policy, role, SCIM, SAML, OAuth app, or API token changes;
- data export, bulk download, deletion, legal hold, or retention changes;
- actions that approve, sign, purchase, transfer funds, or accept contracts;
- actions that erase evidence of the impersonation session.

### 5. Confirm Audit Trail Integrity

Each event produced during impersonation should include:

- event ID and timestamp;
- actor staff ID and target user ID;
- tenant, workspace, and environment;
- reason/ticket/approval reference;
- session ID and impersonation scope;
- action name, resource, outcome, and request ID;
- source IP or device context when available.

Audit records must be immutable to support staff and inaccessible to the target
user for alteration. Logs must not be written only under the target user's ID.

### 6. Review Revocation, Timeout, and Lifecycle

Check whether sessions terminate predictably:

- short default timeout and absolute maximum lifetime;
- one-click staff exit;
- automatic end when ticket, approval, assignment, or employment state changes;
- revocation if target account is disabled or tenant status changes;
- re-authentication for new target users or elevated scopes;
- no reuse of normal customer refresh tokens.

## High-Signal Findings

Report a finding when:

- a staff user can create an impersonation session with only a target user ID;
- the target tenant is not checked against staff assignment or approval;
- reason or ticket capture is optional;
- token claims overwrite the principal with the target user and lose the actor;
- high-risk writes are allowed with normal customer permissions;
- audit events show only the target user or are editable by staff;
- sessions have no short timeout or survive approval revocation;
- customer-visible UI and API responses cannot tell the session is staff-driven.

## Remediation Guidance

- Require explicit reason, ticket, and approval before impersonation starts.
- Preserve both actor and target identity in server-side session claims.
- Scope impersonation sessions to read-only by default.
- Add deterministic deny rules for billing, security, export, destructive, and
  consent-like actions.
- Enforce tenant boundaries from server-side actor assignment and target tenant.
- Make impersonation visible in staff UI and logs.
- Emit immutable audit events for session start, every action, scope change, and
  session end.
- Expire sessions quickly and revoke them when approval, assignment, or target
  eligibility changes.

## Verification Checklist

- [ ] all entry points require staff authentication and recent MFA;
- [ ] target tenant and staff assignment are checked server-side;
- [ ] reason and approval references are required;
- [ ] session claims preserve actor, target, tenant, scope, and expiry;
- [ ] UI/API context marks impersonation visibly;
- [ ] high-risk actions are denied or require separate approval;
- [ ] audit events include actor and target for every impersonated action;
- [ ] sessions expire and revoke on approval, assignment, or target changes;
- [ ] tests cover cross-tenant target selection and write-action denial.

## Evidence to Request

- admin/support route handlers and controllers;
- session minting and token claim builders;
- middleware that resolves current user and tenant;
- policy engine or authorization rules;
- audit event emitters and log schema;
- UI banner or staff console components;
- approval/ticket integration code;
- tests for tenant boundaries, action gates, timeouts, and revocation.

## Reporting Template

```markdown
### Finding: unsafe admin impersonation in <flow>

Severity: High
Affected flow: <entry point -> session -> action>
Evidence:
- <file/function showing session creation>
- <file/function showing missing audit/action/tenant control>
Impact: <what staff or compromised staff account can do>
Required fix:
- <approval/session/audit/action-gate control>
Verification:
- <test that proves blocked cross-tenant or high-risk action>
```

## Common False Positives

- A read-only preview mode that never mints a target user session and cannot
  trigger customer actions.
- A support screen that displays customer data through staff-only APIs while
  preserving staff identity and full audit context.
- Local development impersonation disabled in production and covered by
  environment guard tests.
- Break-glass access handled by a separate PAM workflow with stronger controls.

## References

- OWASP ASVS: authentication, session management, access control, and logging
  verification requirements
- NIST SP 800-53 AC-6 Least Privilege
- NIST SP 800-53 AU-2, AU-3, AU-12 audit event generation and content
- CWE-285 Improper Authorization
- CWE-863 Incorrect Authorization
