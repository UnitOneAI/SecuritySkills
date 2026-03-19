# Framework Mapping

## OWASP Top 10:2021 DAST Testability

| Category | Name | DAST Testability |
|----------|------|-----------------|
| A01 | Broken Access Control | Moderate -- path traversal, IDOR (with authenticated scanning) |
| A02 | Cryptographic Failures | Limited -- TLS config, cleartext transmission |
| A03 | Injection | Strong -- SQLi, XSS, Command Injection, SSTI, SSRF |
| A04 | Insecure Design | Minimal -- business logic flaws require manual testing |
| A05 | Security Misconfiguration | Strong -- headers, directory listing, default pages, error handling |
| A06 | Vulnerable Components | Moderate -- technology fingerprinting, Retire.js |
| A07 | Identification and Authentication Failures | Moderate -- session fixation, weak session IDs |
| A08 | Software and Data Integrity Failures | Minimal -- SRI checks, limited CSP analysis |
| A09 | Security Logging and Monitoring Failures | Not testable via DAST |
| A10 | Server-Side Request Forgery | Moderate -- SSRF active scanner |

## OWASP Testing Guide v4.2 (WSTG) -- DAST-Relevant Categories

| Category | ID Prefix | DAST Coverage |
|----------|-----------|--------------|
| Information Gathering | WSTG-INFO | Strong (passive fingerprinting) |
| Configuration and Deployment Management | WSTG-CONF | Strong (passive + active) |
| Identity Management | WSTG-IDNT | Limited |
| Authentication | WSTG-ATHN | Moderate (with auth scanning) |
| Authorization | WSTG-ATHZ | Moderate (IDOR, path traversal) |
| Session Management | WSTG-SESS | Moderate (passive cookie analysis, session fixation) |
| Input Validation | WSTG-INPV | Strong (injection scanners) |
| Error Handling | WSTG-ERRH | Strong (error message analysis) |
| Cryptography | WSTG-CRYP | Limited (TLS only) |
| Business Logic | WSTG-BUSL | Minimal (manual testing required) |
| Client-Side | WSTG-CLNT | Moderate (DOM XSS, clickjacking) |
