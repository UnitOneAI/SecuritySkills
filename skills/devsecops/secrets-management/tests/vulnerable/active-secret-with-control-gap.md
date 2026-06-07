# Vulnerable: active secret exposure plus scanner control gaps

## Scenario

A production deploy token is present in an application configuration file. The value is redacted in the review evidence, but provider validation or security-team evidence confirms the token is active and unrotated.

Additional control evidence:

- No repo-visible scanner configuration.
- No platform-native scanner evidence is available.
- No pre-commit hook or push protection evidence is available.
- No git history scan evidence is available.

## Expected assessment

Create two separate records:

1. Critical Secret Exposure finding for the active production token. Do not display the token value.
2. High Secrets Control Gap for missing scanner and history-scan evidence in a production repository.

The control gap supports remediation priority, but it must not be counted as a second leaked-secret finding.
