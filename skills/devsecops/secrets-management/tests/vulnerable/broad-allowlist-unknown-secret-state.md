# Vulnerable Fixture: Broad Allowlist with Unknown Secret State

## Purpose

This fixture should be reported as a suppression-governance risk. The allowlist can hide real credentials, the bypass reason is generic, and there is no reviewer, expiry, rotation, revocation, or follow-up scan evidence.

## Pattern

```toml
[[allowlists]]
description = "ignore test and fixture secrets"
paths = ['''.*fixtures.*''']
regexes = ['''(?i)(api[_-]?key|token|secret|password).*''']
```

```yaml
push_protection_bypass:
  detector: github_secret_scanning
  token_type: unknown
  repository: example/service
  path: tests/fixtures/payment-provider.md
  reason: used_in_tests
  reviewer: null
  expiry: null
  secret_state: unknown
  rotation_ticket: null
  full_scan_after_bypass: not_run
```

## Expected Review Result

- Flag the broad allowlist because it suppresses generic credential terms across fixture paths.
- Require exact path/rule/fingerprint scope, owner, reviewer, expiry, and last audit evidence.
- Treat the bypassed value as High risk until secret state, revocation/rotation, alert recipients, and a full follow-up scan are documented.
