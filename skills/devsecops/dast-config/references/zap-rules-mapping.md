# ZAP Rules Mapping

## Passive Scan Rules

| ZAP Rule ID | Rule Name | OWASP Top 10 | WSTG Reference |
|-------------|-----------|-------------|----------------|
| 10010 | Cookie No HttpOnly Flag | A05:2021 | WSTG-SESS-02 |
| 10011 | Cookie Without Secure Flag | A05:2021 | WSTG-SESS-02 |
| 10015 | Incomplete or No Cache-control Header | A05:2021 | WSTG-CONF-06 |
| 10017 | Cross-Domain JavaScript Source | A05:2021 | WSTG-CLNT-01 |
| 10020 | X-Frame-Options Header | A05:2021 | WSTG-CLNT-09 |
| 10021 | X-Content-Type-Options Header | A05:2021 | WSTG-CONF-06 |
| 10023 | Information Disclosure - Debug Errors | A05:2021 | WSTG-ERRH-01 |
| 10035 | Strict-Transport-Security Header | A05:2021 | WSTG-CONF-07 |
| 10036 | Server Leaks Version Information | A05:2021 | WSTG-INFO-02 |
| 10038 | Content Security Policy Header | A05:2021 | WSTG-CONF-12 |
| 10063 | Permissions Policy Header | A05:2021 | WSTG-CONF-06 |
| 90004 | Insufficient Site Isolation Against Spectre | A05:2021 | N/A |

## Active Scan Rules

| OWASP Top 10 | ZAP Active Scanner | WSTG Reference |
|-------------|-------------------|----------------|
| A01:2021 Broken Access Control | Path Traversal (6), Remote File Inclusion (7) | WSTG-ATHZ-01 |
| A02:2021 Cryptographic Failures | Passive rules + TLS config check | WSTG-CRYP-01 |
| A03:2021 Injection | SQL Injection (40018, 40019, 40020, 40021, 40022), XSS Reflected (40012, 40014), XSS Persistent (40016, 40017), OS Command Injection (90020), SSTI (90035) | WSTG-INPV-05, WSTG-INPV-01 |
| A04:2021 Insecure Design | Limited DAST coverage -- manual testing required | WSTG-BUSL-* |
| A05:2021 Security Misconfiguration | Directory Browsing (0), Backup File Disclosure (10095) | WSTG-CONF-04, WSTG-CONF-03 |
| A06:2021 Vulnerable Components | Passive technology fingerprinting + Retire.js | WSTG-INFO-02 |
| A07:2021 Auth Failures | Brute Force (not default), Session Fixation (40013) | WSTG-ATHN-*, WSTG-SESS-* |
| A08:2021 Software/Data Integrity | Limited DAST coverage | N/A |
| A09:2021 Logging Failures | Not DAST-testable | N/A |
| A10:2021 SSRF | SSRF (40046) | WSTG-INPV-19 |
