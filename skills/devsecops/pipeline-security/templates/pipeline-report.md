## Pipeline Security Assessment Report

### Repository
- Name: <repository name>
- Date: <assessment date>
- Configurations reviewed: <list of files>

### SLSA Build Level Determination
- **Current Level:** SLSA Build L<1|2|3>
- **Evidence:**
  - L1: <met/not met> -- <evidence>
  - L2: <met/not met> -- <evidence>
  - L3: <met/not met> -- <evidence>
- **Gap to next level:** <what is needed to reach the next SLSA level>

### OWASP CICD-SEC Findings

| Control ID | Risk Name | Severity | Status | Finding Summary |
|------------|-----------|----------|--------|-----------------|
| CICD-SEC-1 | Insufficient Flow Control | High/Med/Low | Pass/Fail/Partial | <summary> |
| CICD-SEC-2 | Inadequate IAM | ... | ... | ... |
| ... | ... | ... | ... | ... |

### Detailed Findings

#### [CICD-SEC-X] <Risk Name>
- **Status:** Pass / Fail / Partial
- **Severity:** Critical / High / Medium / Low
- **File:** <path to relevant config>
- **Line(s):** <line numbers if applicable>
- **Description:** <what was found>
- **Remediation:** <specific fix>

### Prioritized Remediation Plan

1. **[Critical]** <CICD-SEC-X> -- <action item>
2. **[High]** <CICD-SEC-X> -- <action item>
3. ...

### Summary
- Total controls evaluated: 10
- Passed: X
- Partial: X
- Failed: X
- Current SLSA Level: L<X>
- Target SLSA Level: L<X+1>
