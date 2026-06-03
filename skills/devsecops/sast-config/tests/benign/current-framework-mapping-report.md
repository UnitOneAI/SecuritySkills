# Benign Fixture: Current SAST Framework Mapping

## SAST Configuration Assessment Report

### Scope

- Repository: example-service
- SAST tool(s): Semgrep, CodeQL
- Configuration files analyzed: `.semgrep.yml`, `.github/codeql/codeql-config.yml`
- Date: 2026-06-03
- Frameworks applied: OWASP ASVS 5.0.0, CWE Top 25 2025
- ASVS source URL and retrieval date: https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release, 2026-06-03
- CWE source URL and retrieval date: https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html, 2026-06-03
- SAST rule-pack source/version/date: `p/cwe-top-25`, retrieved 2026-06-03
- Legacy framework exception: None

### Coverage Sample

| CWE Rank | CWE ID | Weakness | Language(s) | Rule(s) Active | Mapping Confidence | Severity | Gap |
|----------|--------|----------|-------------|----------------|--------------------|----------|-----|
| 1 | CWE-79 | XSS | JavaScript | 2 rules | High | ERROR | None |
| 4 | CWE-862 | Missing Authorization | JavaScript | 1 custom rule | Medium | WARNING | Partial - manual business logic review required |
| 22 | CWE-918 | SSRF | Python | 1 rule | High | WARNING | None |

