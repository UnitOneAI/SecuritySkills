# Admin Impersonation Feature Review

This skill reviews SaaS admin impersonation and support "login as user" features
for approval, scope, tenant boundaries, action restrictions, session visibility,
auditability, revocation, and timeout behavior.

It is intended for defensive review of authorized systems. It does not require
or encourage live access to customer accounts.

## Included Fixtures

Vulnerable examples:

- `fixtures/vulnerable/typescript_unscoped_impersonation.js`
- `fixtures/vulnerable/python_actor_lost_audit.py`
- `fixtures/vulnerable/typescript_cross_tenant_target.js`

Benign examples:

- `fixtures/benign/python_approved_readonly_session.py`
- `fixtures/benign/typescript_action_gate.js`
- `fixtures/benign/python_revocation_timeout_audit.py`

## Review Targets

- admin/support impersonation route handlers;
- session and token claim builders;
- tenant and staff assignment checks;
- approval, ticket, and reason capture;
- action authorization during impersonation;
- audit event emitters;
- timeout and revocation workflows.

## Validation

Run syntax checks for the included fixtures:

```bash
python -m py_compile fixtures/vulnerable/python_actor_lost_audit.py \
  fixtures/benign/python_approved_readonly_session.py \
  fixtures/benign/python_revocation_timeout_audit.py

node --check fixtures/vulnerable/typescript_unscoped_impersonation.js
node --check fixtures/vulnerable/typescript_cross_tenant_target.js
node --check fixtures/benign/typescript_action_gate.js
```

Use `SKILL.md` for the review checklist and reporting template.
