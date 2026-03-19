# False Positive Record Template

```
False Positive Record:
- Scanner:             [Scanner name]
- Plugin/Check ID:     [ID]
- CVE ID:              [CVE-YYYY-NNNNN or N/A]
- CWE:                 [CWE-NNN or N/A]
- Affected Asset:      [hostname/IP]
- Scanner Severity:    [Critical/High/Medium/Low/Info]
- FP Pattern:          [Version-based | Banner | Protocol | OS Misidentification | Container | Informational | Compensated]
- Evidence:            [Specific evidence proving false positive]
- Verification Method: [Package manager check | Authenticated re-scan | Manual testing | Configuration review]
- Disposition:         [Confirmed FP -- suppress | Accepted Risk -- document | True Positive -- remediate]
```
