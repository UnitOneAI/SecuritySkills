# Security Code Review Report Template

```
## Security Code Review Report

**Scope:** [list of files reviewed]
**Languages:** [detected languages and frameworks]
**Date:** [review date]
**Reviewer:** AI Agent -- secure-code-review skill v1.1.0

### Summary
- Critical: [count]
- High: [count]
- Medium: [count]
- Low: [count]
- Informational: [count]

### Findings

#### SCR-001: [Title]
- **Severity:** [Critical|High|Medium|Low|Informational]
- **CWE:** CWE-[number] -- [name]
- **ASVS Control:** V[x.y.z]
- **Location:** [file:line]
- **Description:** [explanation]
- **Evidence:**
  ```[language]
  [code snippet]
  ```
- **Remediation:** [specific fix with code example]
- **Status:** Open

[Repeat for each finding]

### ASVS Coverage Matrix
| ASVS Section | Applicable | Findings | Pass/Fail |
|---|---|---|---|
| V2 Authentication | Yes/No | [count] | [result] |
| V3 Session Management | Yes/No | [count] | [result] |
| V4 Access Control | Yes/No | [count] | [result] |
| V5 Validation, Sanitization and Encoding | Yes/No | [count] | [result] |
| V6 Stored Cryptography | Yes/No | [count] | [result] |
| V7 Error Handling and Logging | Yes/No | [count] | [result] |
| V8 Data Protection | Yes/No | [count] | [result] |
| V12 Files and Resources | Yes/No | [count] | [result] |
```
