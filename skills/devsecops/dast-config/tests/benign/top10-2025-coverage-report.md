# Benign Fixture: OWASP Top 10:2025 DAST Coverage Report

## DAST Configuration Assessment Report

### Scope

- Target application: example app
- DAST tool(s): ZAP 2.x
- Configuration files analyzed: `af-plan.yaml`
- Date: 2026-06-03
- Frameworks applied: OWASP Top 10:2025, OWASP Testing Guide v4.2
- OWASP Top 10 source URL / retrieval date: https://owasp.org/Top10/2025/0x00_2025-Introduction/, 2026-06-03
- Legacy baseline: None
- DAST tool/version: `zaproxy/action-full-scan@v0.10.0`
- Scan environment: staging

### OWASP Top 10 DAST Coverage

| OWASP Category | DAST Coverage Status | DAST Evidence | Cross-Tool / Manual Evidence Required | Gap |
|---------------|----------------------|---------------|--------------------------------------|-----|
| A01:2025 Broken Access Control | Partially Covered | Authenticated path traversal and IDOR probes | Manual authorization review | Role matrix missing |
| A02:2025 Security Misconfiguration | DAST Covered | Passive header rules and directory listing checks | Config review for non-HTTP services | None |
| A03:2025 Software Supply Chain Failures | Partially Covered | Runtime component fingerprinting | SBOM, SCA, provenance | SCA evidence linked separately |
| A05:2025 Injection | DAST Covered | SQLi, XSS, command injection, SSTI rules enabled | Manual validation of high findings | None |
| A09:2025 Security Logging & Alerting Failures | Cross-Tool Evidence Required | Staged high DAST finding generated | SIEM alert evidence | Alert proof pending |
| A10:2025 Mishandling of Exceptional Conditions | Partially Covered | Malformed state and timeout tests in staging | Manual fail-open review | Retry boundary tests pending |

