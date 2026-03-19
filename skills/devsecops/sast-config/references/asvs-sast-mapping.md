# OWASP ASVS 4.0.3 SAST-Relevant Chapter Mapping

| Chapter | Title | SAST Coverage |
|---------|-------|---------------|
| V2 | Authentication | Partial -- hardcoded credentials, weak password checks |
| V3 | Session Management | Limited -- configuration review only |
| V4 | Access Control | Partial -- missing authorization checks |
| V5 | Validation, Sanitization, Encoding | Strong -- injection, XSS, path traversal |
| V6 | Stored Cryptography | Moderate -- weak algorithms, hardcoded keys |
| V8 | Data Protection | Partial -- sensitive data in logs |
| V12 | File and Resources | Moderate -- upload validation, path traversal |
| V13 | API and Web Service | Partial -- mass assignment, SSRF patterns |

## Severity Mapping to OWASP ASVS

| ASVS Level | Risk Context | Semgrep Severity | CodeQL Severity | CI Action |
|------------|-------------|------------------|-----------------|-----------|
| L1 (Opportunistic) | Internet-facing, unauthenticated | ERROR | error, @security-severity >= 7.0 | Block merge |
| L2 (Standard) | Authenticated, business-critical | ERROR or WARNING | error or warning, >= 4.0 | Block or warn |
| L3 (Advanced) | High-value targets, regulated data | WARNING or INFO | All severities | Warn, review required |

Source: https://owasp.org/www-project-application-security-verification-standard/
