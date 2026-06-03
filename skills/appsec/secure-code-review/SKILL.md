# Secure Code Review

## Overview

Secure code review is the systematic examination of source code to identify security vulnerabilities, verify compliance with security requirements, and ensure adherence to secure coding practices. This skill covers the process of reviewing code for common security flaws, understanding attack vectors, and providing actionable remediation guidance.

## Key Areas

1. **Input Validation & Sanitization**
   - Validate all external inputs (user, API, file, network)
   - Check for injection flaws (SQL, NoSQL, OS command, LDAP, XPath)
   - Ensure proper encoding and escaping for output context
   - Verify use of parameterized queries or prepared statements

2. **Authentication & Session Management**
   - Review password storage (hashing with salt, not encryption)
   - Check session token generation, expiration, and rotation
   - Verify multi-factor authentication implementation
   - Ensure secure password reset flows

3. **Access Control**
   - Verify authorization checks on every protected resource
   - Check for privilege escalation paths
   - Review role-based access control (RBAC) implementation
   - Ensure least privilege principle is followed

4. **Cryptography**
   - Use strong, modern algorithms (AES-256, RSA-2048+, SHA-256+)
   - Proper key management (no hardcoded keys, secure storage)
   - Correct use of TLS/SSL for data in transit
   - Avoid custom cryptographic implementations

5. **Error Handling & Logging**
   - Don't expose sensitive information in error messages
   - Log security-relevant events (auth failures, access denials)
   - Ensure logs are tamper-proof and monitored
   - Implement proper exception handling

6. **Data Protection**
   - Classify data sensitivity and apply appropriate controls
   - Encrypt sensitive data at rest and in transit
   - Implement data masking for display purposes
   - Ensure secure data disposal

7. **Archive Extraction Security**
   - **Classify the archive source** before reviewing extraction logic:
     - User uploads / untrusted external sources → **High severity**
     - CI/CD artifacts from trusted pipelines → Medium severity
     - Package dependencies (npm, PyPI, NuGet) → Medium severity
     - Third-party exports (vendor data dumps) → Medium severity
     - Trusted application fixtures (packaged at build time) → Low severity
   - **Path traversal prevention** (not just `../` checks):
     - Resolve the destination path using `Path.resolve()` or equivalent
     - Check that the resolved target path starts with the intended extraction root
     - Block absolute paths, Windows drive letters (e.g., `C:\`), UNC paths (e.g., `\\server\share`), and mixed separators
     - Reject entries with null bytes, device names (CON, NUL, etc.), or symlinks that escape the root
   - **Resource exhaustion (zip bombs / decompression bombs):**
     - Enforce limits on total uncompressed size, entry count, compression ratio, and individual file size
     - Set a timeout for extraction operations
     - Monitor memory and disk usage during extraction
   - **Symbolic link safety:**
     - If symlinks are extracted, verify they do not point outside the extraction directory
     - Consider extracting without following symlinks, or rejecting symlinks entirely for untrusted archives
   - **Archive integrity:**
     - Validate archive signatures or checksums if available
     - Reject corrupted or truncated archives

8. **Dependency & Supply Chain**
   - Review third-party libraries for known vulnerabilities
   - Check for outdated or unmaintained dependencies
   - Verify integrity of downloaded packages (checksums, signatures)
   - Assess license compliance

9. **Configuration & Deployment**
   - Review default configurations for security
   - Check for hardcoded secrets, API keys, or credentials
   - Verify secure defaults (HTTPS, secure cookies, etc.)
   - Ensure environment-specific configurations are not exposed

10. **Concurrency & State**
    - Check for race conditions in file operations, database writes
    - Review locking mechanisms and transaction isolation
    - Verify atomicity of security-critical operations
    - Prevent time-of-check time-of-use (TOCTOU) vulnerabilities

## Review Process

1. **Preparation**
   - Understand the application architecture and threat model
   - Identify critical components and data flows
   - Gather relevant security requirements and standards

2. **Automated Scanning**
   - Run SAST tools (Semgrep, CodeQL, SonarQube)
   - Review dependency vulnerability reports
   - Analyze results and triage false positives

3. **Manual Review**
   - Focus on high-risk areas (authentication, authorization, data handling)
   - Trace data flows from input to output
   - Verify security controls are correctly implemented
   - Check for business logic flaws

4. **Reporting**
   - Document findings with severity, impact, and exploitability
   - Provide clear, actionable remediation steps
   - Include code snippets demonstrating the vulnerability and fix
   - Prioritize findings based on risk

## Common Vulnerabilities

- **Injection Flaws**: SQL, NoSQL, OS command, LDAP, XPath injection
- **Broken Authentication**: Weak passwords, session fixation, missing MFA
- **Sensitive Data Exposure**: Unencrypted data, weak cryptography
- **XML External Entities (XXE)**: XML parser misconfiguration
- **Broken Access Control**: Missing authorization checks, IDOR
- **Security Misconfiguration**: Default credentials, verbose errors
- **Cross-Site Scripting (XSS)**: Reflected, stored, DOM-based
- **Insecure Deserialization**: Arbitrary code execution via serialized objects
- **Using Components with Known Vulnerabilities**: Outdated libraries
- **Insufficient Logging & Monitoring**: Missing audit trails

## Tools & Resources

- **SAST Tools**: Semgrep, CodeQL, SonarQube, Checkmarx, Fortify
- **Dependency Scanners**: Dependabot, Snyk, OWASP Dependency-Check
- **Manual Review Aids**: OWASP ASVS, CWE Top 25, OWASP Testing Guide
- **Language-Specific**: Bandit (Python), Brakeman (Ruby), Security Code Scan (.NET)

## References

- OWASP Code Review Guide
- OWASP ASVS (Application Security Verification Standard)
- CWE Top 25 Most Dangerous Software Weaknesses
- SEI CERT Coding Standards