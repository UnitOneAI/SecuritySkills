# Patch Prioritization Report Template

Extracted from the patch-prioritization SKILL.md.

```markdown
## Patch Prioritization Report
**Date:** [YYYY-MM-DD]
**Skill:** patch-prioritization v1.0.2
**Frameworks:** SSVC 2.1, EPSS v3, CISA KEV
**Reviewer:** AI-assisted (human review required for P0/P1 actions and risk acceptances)

### Executive Summary
[3-5 sentences. State the total number of pending findings, breakdown by SLA tier,
count of SLA breaches, and overall patch posture classification. Highlight any P0/P1
findings requiring immediate action.]

### SLA Compliance Dashboard

| SLA Tier | Total Findings | Within SLA | At Risk (< 7 days) | Breached | Exception Granted |
|---|---|---|---|---|---|
| P0 - Emergency | [N] | [N] | [N] | [N] | [N] |
| P1 - Critical | [N] | [N] | [N] | [N] | [N] |
| P2 - High | [N] | [N] | [N] | [N] | [N] |
| P3 - Medium | [N] | [N] | [N] | [N] | [N] |
| P4 - Low | [N] | [N] | [N] | [N] | [N] |
| **Total** | **[N]** | **[N]** | **[N]** | **[N]** | **[N]** |

**Patch Posture:** [Critical Backlog | Elevated Risk | On Track | Healthy]

### EPSS Trend Alerts

| CVE ID | Current EPSS | 30-day Prior | Trend | Recommended Action |
|---|---|---|---|---|
| [CVE-ID] | [score] | [score] | [Surging/Rising] | [Action] |

### Prioritized Patch Schedule

| Priority | CVE ID(s) | Target System | Patch | Scheduled Window | SLA Deadline | Status |
|---|---|---|---|---|---|---|
| P0 | [CVE-ID] | [system] | [version] | [date/time] | [date] | [Scheduled/Pending/Complete] |

### Compensating Controls in Effect

| CVE ID | Control Type | Effectiveness | SLA Extension | Expiration |
|---|---|---|---|---|
| [CVE-ID] | [type] | [Full/Partial] | [+N days] | [date] |

### Risk Exceptions

| Exception ID | CVE ID(s) | Original SLA | New Deadline | Approver | Status |
|---|---|---|---|---|---|
| [EXC-ID] | [CVE-IDs] | [tier] | [date] | [name] | [Approved/Pending] |

### Recommendations
1. [Highest-priority actionable recommendation]
2. [Second priority recommendation]
3. [Process improvement recommendation if applicable]
```
