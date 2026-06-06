# Benign Fixture: Controlled Inert Push-Protection Bypass

## Purpose

This fixture should not be reported as a leaked production secret solely because a push-protection bypass exists. The value is redacted/inert, exact-scoped to a parser fixture, independently reviewed, and expiring.

## Evidence

```yaml
push_protection_bypass:
  detector: github_secret_scanning
  token_type: provider test token
  repository: example/security-fixtures
  path: tests/fixtures/provider-token-redacted.md
  fingerprint: fixture-provider-token-redacted-001
  reason: parser coverage fixture with non-production redacted value
  owner: appsec
  reviewer: security-engineering
  expiry: 2026-07-01
  secret_state: confirmed revoked and non-production
  alert_recipients:
    - appsec-oncall
  follow_up:
    rotation_ticket: not required for inert fixture
    full_scan_after_bypass: completed
```

```text
fixture_value: provider_token_REDACTED_FOR_TEST_ONLY
```

## Expected Review Result

- Record the bypass in the governance table.
- Do not classify the redacted fixture as a production secret leak.
- Keep residual risk Low/Informational because reviewer, expiry, exact scope, secret state, and follow-up scan evidence are present.
