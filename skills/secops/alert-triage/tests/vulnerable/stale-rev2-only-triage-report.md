# Alert Triage Fixture: Stale Rev. 2-Only Report

## Alert Triage Report
**Date:** 2026-06-03 10:00 UTC
**Skill:** alert-triage v1.0.0
**Frameworks:** MITRE ATT&CK v16, NIST SP 800-61 Rev 2
**Analyst:** AI-assisted

### Alert Summary
| Field | Value |
|-------|-------|
| Alert ID | SIEM-123 |
| Rule Name | Suspicious PowerShell |
| Source System | SIEM |
| Timestamp | 2026-06-03 09:45:00 UTC |
| ATT&CK Technique | T1059.001 -- PowerShell |
| ATT&CK Tactic | Execution |

### Triage Decision
| Field | Value |
|-------|-------|
| Disposition | True Positive |
| Priority | P2 High |
| Confidence | Medium |
| Escalation Required | Yes -- to IR team |

### Why This Fixture Should Be Flagged

The report uses only NIST SP 800-61 Rev. 2 without a legacy-mode reason, NIST source date, CSF 2.0 mapping, incident declaration criteria, communication trigger, recovery trigger, evidence confidence basis, or not-evaluable reason.
