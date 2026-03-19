# ASVS 4.0.3 Control Tables

## V5 -- Validation, Sanitization and Encoding

| ASVS Control | Description |
|---|---|
| V5.1.1 | Input validation is applied on a trusted service layer, not solely client-side |
| V5.1.3 | All input is validated against an allowlist of permitted characters or patterns |
| V5.2.1 | All HTML form output is properly encoded to prevent reflected XSS |
| V5.2.2 | Unstructured data is sanitized to enforce safety and allowed characters |
| V5.3.1 | Output encoding is relevant for the interpreter context (HTML, JS, URL, CSS, SQL) |
| V5.3.4 | Data selection or database queries use parameterized queries or ORM |
| V5.3.7 | The application protects against LDAP injection |
| V5.3.8 | The application protects against OS command injection |
| V5.5.1 | Serialized objects use integrity checks or encryption to prevent hostile object creation |

## V2 -- Authentication

| ASVS Control | Description |
|---|---|
| V2.1.1 | User-set passwords are at least 12 characters in length |
| V2.1.7 | Passwords are checked against a set of breached passwords (e.g., haveibeenpwned) |
| V2.2.1 | Anti-automation controls are effective against credential stuffing and brute-force |
| V2.5.1 | A system-generated initial activation or recovery secret is not sent in cleartext |
| V2.8.1 | Time-based OTP (TOTP) tokens have a defined validity period |
| V2.10.1 | No hard-coded credentials exist in the source code |
| V2.10.2 | No shared or default accounts are present |

## V3 -- Session Management

| ASVS Control | Description |
|---|---|
| V3.1.1 | Session tokens are generated using a cryptographically secure random number generator |
| V3.2.1 | Session tokens are invalidated on user logout |
| V3.3.1 | Session idle timeout is enforced |
| V3.4.1 | Cookie-based session tokens have the Secure attribute set |
| V3.4.2 | Cookie-based session tokens have the HttpOnly attribute set |
| V3.4.3 | Cookie-based session tokens have the SameSite attribute set |

## V4 -- Access Control

| ASVS Control | Description |
|---|---|
| V4.1.1 | Access control is enforced at a trusted service layer, not only at the UI |
| V4.1.2 | All user and data attributes used by access controls cannot be manipulated by end users |
| V4.1.3 | The principle of least privilege is applied -- users only access functions and data they need |
| V4.2.1 | Sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks |
| V4.2.2 | The application enforces a strong anti-CSRF mechanism |
| V4.3.1 | Administrative interfaces use appropriate multi-factor or role-based access control |

## V6 -- Stored Cryptography

| ASVS Control | Description |
|---|---|
| V6.1.1 | Regulated private data is stored encrypted at rest |
| V6.2.1 | All cryptographic modules fail in a secure manner and errors are handled properly |
| V6.2.2 | Industry-proven or government-approved cryptographic algorithms and modes are used |
| V6.2.3 | Encryption initialization vectors, cipher configurations, and block modes are configured securely |
| V6.2.5 | Known insecure block modes (ECB), padding modes, and weak algorithms (DES, RC4) are not used |
| V6.3.1 | All random numbers and strings are generated using a cryptographically secure PRNG |
| V6.4.1 | A key management solution is in place to create, distribute, rotate, and revoke keys |

## V7 -- Error Handling and Logging

| ASVS Control | Description |
|---|---|
| V7.1.1 | The application does not log credentials or payment details |
| V7.1.2 | The application does not log other sensitive data as defined by local privacy laws |
| V7.2.1 | All authentication decisions are logged |
| V7.2.2 | All access control decisions are logged |
| V7.3.1 | Logging mechanisms are protected from injection attacks |
| V7.4.1 | A generic error message is shown to users; detailed errors are only logged server-side |
| V7.4.3 | Error handling logic denies access by default |

## V8 -- Data Protection

| ASVS Control | Description |
|---|---|
| V8.1.1 | The application protects sensitive data from being cached in server components |
| V8.2.1 | The application sets sufficient anti-caching headers for sensitive responses |
| V8.3.1 | Sensitive data is sent to the server in the HTTP message body or headers, not via URL parameters |
| V8.3.4 | Sensitive information in autocomplete fields is disabled |
| V8.3.6 | Sensitive information in memory is overwritten as soon as it is no longer needed |

## V12 -- Files and Resources

| ASVS Control | Description |
|---|---|
| V12.1.1 | The application will not accept large files that could fill up storage or cause a denial of service |
| V12.1.2 | Compressed files are checked for decompression bombs |
| V12.3.1 | User-submitted filenames are validated and metadata from user uploads is not used directly by the system |
| V12.3.2 | User-submitted filenames are sanitized to prevent directory traversal |
| V12.4.1 | Files obtained from untrusted sources are stored outside the webroot |
| V12.4.2 | Files obtained from untrusted sources are scanned by antivirus or verified by content type |
| V12.6.1 | The web server only processes requests to specified and permitted file types |
