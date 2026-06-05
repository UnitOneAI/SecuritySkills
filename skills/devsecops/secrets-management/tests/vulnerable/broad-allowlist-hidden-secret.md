---
case: broad-allowlist-hidden-secret
expected: vulnerable
skill: secrets-management
---

# Broad Scanner Allowlist Hiding Real Secrets

## Input

```toml
[[allowlists]]
description = "ignore fixture tokens"
paths = ['''tests/fixtures/.*''']
regexes = ['''(?i)(api[_-]?key|token|secret).*''']
```

```text
push_protection_bypass:
  requester: build-maintainer
  reason: used_in_tests
  reviewer: missing
  expiry: missing
  rotation_ticket: missing
  secret_state: unknown
```

## Expected Assessment

Flag as High risk because the allowlist suppresses broad token-like values by path and regex without an owner, reviewer, expiry, exact fingerprint, or proof that matched values are inert or revoked.

Do not print the secret value. Report the detector, path scope, suppression scope, missing governance fields, and required rotation/revocation follow-up.
