# OWASP Top 10:2021 CWE Mappings

## A01:2021 -- Broken Access Control

| CWE | Name |
|-----|------|
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor |
| CWE-201 | Insertion of Sensitive Information Into Sent Data |
| CWE-352 | Cross-Site Request Forgery (CSRF) |
| CWE-284 | Improper Access Control |
| CWE-285 | Improper Authorization |
| CWE-639 | Authorization Bypass Through User-Controlled Key |
| CWE-862 | Missing Authorization |
| CWE-863 | Incorrect Authorization |
| CWE-22  | Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) |

## A02:2021 -- Cryptographic Failures

| CWE | Name |
|-----|------|
| CWE-259 | Use of Hard-coded Password |
| CWE-261 | Weak Encoding for Password |
| CWE-296 | Improper Following of a Certificate's Chain of Trust |
| CWE-310 | Cryptographic Issues |
| CWE-319 | Cleartext Transmission of Sensitive Information |
| CWE-321 | Use of Hard-coded Cryptographic Key |
| CWE-326 | Inadequate Encryption Strength |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm |
| CWE-328 | Use of Weak Hash |
| CWE-330 | Use of Insufficiently Random Values |
| CWE-331 | Insufficient Entropy |
| CWE-798 | Use of Hard-coded Credentials |

## A03:2021 -- Injection

| CWE | Name |
|-----|------|
| CWE-20  | Improper Input Validation |
| CWE-74  | Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection) |
| CWE-75  | Failure to Sanitize Special Elements into a Different Plane |
| CWE-77  | Improper Neutralization of Special Elements used in a Command (Command Injection) |
| CWE-78  | Improper Neutralization of Special Elements used in an OS Command (OS Command Injection) |
| CWE-79  | Improper Neutralization of Input During Web Page Generation (XSS) |
| CWE-80  | Improper Neutralization of Script-Related HTML Tags |
| CWE-89  | Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) |
| CWE-90  | Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection) |
| CWE-94  | Improper Control of Generation of Code (Code Injection) |
| CWE-643 | Improper Neutralization of Data within XPath Expressions (XPath Injection) |
| CWE-917 | Improper Neutralization of Special Elements used in an Expression Language Statement (EL Injection) |

## A04:2021 -- Insecure Design

| CWE | Name |
|-----|------|
| CWE-73  | External Control of File Name or Path |
| CWE-183 | Permissive List of Allowed Inputs |
| CWE-209 | Generation of Error Message Containing Sensitive Information |
| CWE-256 | Plaintext Storage of a Password |
| CWE-501 | Trust Boundary Violation |
| CWE-522 | Insufficiently Protected Credentials |
| CWE-602 | Client-Side Enforcement of Server-Side Security |
| CWE-656 | Reliance on Security Through Obscurity |
| CWE-799 | Improper Control of Interaction Frequency |
| CWE-840 | Business Logic Errors |

## A05:2021 -- Security Misconfiguration

| CWE | Name |
|-----|------|
| CWE-2   | Direct Use of Environment Configuration File |
| CWE-11  | ASP.NET Misconfiguration: Creating Debug Binary |
| CWE-13  | ASP.NET Misconfiguration: Password in Configuration File |
| CWE-15  | External Control of System or Configuration Setting |
| CWE-16  | Configuration |
| CWE-611 | Improper Restriction of XML External Entity Reference (XXE) |
| CWE-614 | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute |
| CWE-756 | Missing Custom Error Page |
| CWE-776 | Improper Restriction of Recursive Entity References in DTDs (XML Entity Expansion) |
| CWE-942 | Permissive Cross-domain Policy with Untrusted Domains |

## A06:2021 -- Vulnerable and Outdated Components

| CWE | Name |
|-----|------|
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere |
| CWE-1035 | OWASP Top Ten 2017 Category A9 -- Using Components with Known Vulnerabilities |
| CWE-1104 | Use of Unmaintained Third-Party Components |

## A07:2021 -- Identification and Authentication Failures

| CWE | Name |
|-----|------|
| CWE-255 | Credentials Management Errors |
| CWE-287 | Improper Authentication |
| CWE-288 | Authentication Bypass Using an Alternate Path or Channel |
| CWE-290 | Authentication Bypass by Spoofing |
| CWE-294 | Authentication Bypass by Capture-replay |
| CWE-295 | Improper Certificate Validation |
| CWE-297 | Improper Validation of Certificate with Host Mismatch |
| CWE-300 | Channel Accessible by Non-Endpoint |
| CWE-302 | Authentication Bypass by Assumed-Immutable Data |
| CWE-304 | Missing Critical Step in Authentication |
| CWE-306 | Missing Authentication for Critical Function |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts |
| CWE-384 | Session Fixation |
| CWE-521 | Weak Password Requirements |
| CWE-613 | Insufficient Session Expiration |

## A08:2021 -- Software and Data Integrity Failures

| CWE | Name |
|-----|------|
| CWE-345 | Insufficient Verification of Data Authenticity |
| CWE-353 | Missing Support for Integrity Check |
| CWE-426 | Untrusted Search Path |
| CWE-494 | Download of Code Without Integrity Check |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-565 | Reliance on Cookies without Validation and Integrity Checking |
| CWE-784 | Reliance on Cookies without Validation and Integrity Checking in a Security Decision |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere |

## A09:2021 -- Security Logging and Monitoring Failures

| CWE | Name |
|-----|------|
| CWE-117 | Improper Output Neutralization for Logs |
| CWE-223 | Omission of Security-relevant Information |
| CWE-532 | Insertion of Sensitive Information into Log File |
| CWE-778 | Insufficient Logging |
| CWE-779 | Logging of Excessive Data |

## A10:2021 -- Server-Side Request Forgery (SSRF)

| CWE | Name |
|-----|------|
| CWE-918 | Server-Side Request Forgery (SSRF) |
| CWE-441 | Unintended Proxy or Intermediary (Confused Deputy) |

## Summary Reference Table

| OWASP ID | Category | Key CWEs | Primary Risk |
|----------|----------|----------|-------------|
| A01:2021 | Broken Access Control | CWE-284, CWE-285, CWE-639, CWE-862, CWE-863 | Unauthorized data access or action |
| A02:2021 | Cryptographic Failures | CWE-259, CWE-327, CWE-328, CWE-330, CWE-798 | Sensitive data exposure |
| A03:2021 | Injection | CWE-77, CWE-78, CWE-79, CWE-89, CWE-94 | Arbitrary command/query execution |
| A04:2021 | Insecure Design | CWE-209, CWE-501, CWE-522, CWE-602, CWE-840 | Architectural security gaps |
| A05:2021 | Security Misconfiguration | CWE-16, CWE-611, CWE-614, CWE-756, CWE-942 | Exploitable default/weak settings |
| A06:2021 | Vulnerable and Outdated Components | CWE-829, CWE-1035, CWE-1104 | Known-CVE exploitation |
| A07:2021 | Identification and Authentication Failures | CWE-287, CWE-306, CWE-307, CWE-384, CWE-613 | Identity compromise |
| A08:2021 | Software and Data Integrity Failures | CWE-345, CWE-494, CWE-502, CWE-565 | Tampering and malicious updates |
| A09:2021 | Security Logging and Monitoring Failures | CWE-117, CWE-223, CWE-532, CWE-778 | Undetected breaches |
| A10:2021 | Server-Side Request Forgery (SSRF) | CWE-918, CWE-441 | Internal network/service access |
