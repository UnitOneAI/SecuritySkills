---
case: controlled-push-protection-bypass
expected: benign
skill: secrets-management
---

# Controlled Push Protection Bypass

## Input

```yaml
push_protection_bypass:
  detector: GitHub secret scanning push protection
  token_type: provider test token
  path: tests/fixtures/payment-provider-redacted.md
  reason: documented inert fixture for parser coverage
  requester: appsec-engineer
  reviewer: security-engineering
  expiry: 2026-07-01
  secret_state: confirmed revoked and non-production
  rotation_ticket: not required because token never had production access
```

## Expected Assessment

Treat as Low/Informational when the evidence proves the value is inert, scoped to a documented fixture, independently reviewed, and time-bound.

Still record the bypass in the assessment output so it can be revalidated before expiry. Do not print the token value.
