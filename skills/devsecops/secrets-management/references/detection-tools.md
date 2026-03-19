# Secret Detection Tool Comparison

| Tool | Configuration File | CI Integration | Pre-commit | History Scan | Custom Rules |
|------|-------------------|----------------|------------|--------------|--------------|
| **Gitleaks** | `.gitleaks.toml` | GitHub Actions, GitLab CI | Yes (via pre-commit) | Yes (`--log-opts=all`) | Yes (TOML regex) |
| **TruffleHog** | Command-line or `.trufflehog.yml` | GitHub Actions, GitLab CI | Yes (via pre-commit) | Yes (`--since-commit` or full) | Yes (custom detectors) |
| **detect-secrets** | `.secrets.baseline` | GitHub Actions, any CI | Yes (native pre-commit hook) | No (current files only) | Yes (plugin system) |
| **git-secrets** | `.git/hooks/pre-commit` | Manual CI integration | Yes (native git hook) | Yes (`--scan-history`) | Yes (regex patterns) |

## Tool Selection Guidance

| Criterion | Recommendation |
|-----------|---------------|
| Best for GitHub-native teams | Gitleaks (direct GitHub Actions support, SARIF output) |
| Best for polyglot CI | TruffleHog (broad CI support, verified secrets feature) |
| Best for baseline management | detect-secrets (tracks known secrets, diff-based updates) |
| Best for git-hook-only | git-secrets (lightweight, AWS-pattern focused) |
| Maximum coverage | Gitleaks + detect-secrets (CI + pre-commit + baseline) |

## What to Verify

- Tool is configured in CI pipeline (runs on every PR/push).
- Tool is configured as a pre-commit hook (prevents secrets from entering history).
- Baseline file is maintained (for detect-secrets).
- Custom rules cover organization-specific secret formats.
- Allowlist entries are documented with justification (false positive suppression must not create blind spots).
