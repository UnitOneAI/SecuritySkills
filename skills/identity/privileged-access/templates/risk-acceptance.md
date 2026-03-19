# PAM Exception / Risk Acceptance Template

> Extracted from `privileged-access/SKILL.md`. Use when documenting exceptions to PAM policies.

## Risk Acceptance Form

```
## PAM Exception Request

### Requestor
- Name: [Requestor name]
- Role: [Job title]
- Date: [YYYY-MM-DD]

### Exception Details
- Finding ID: [e.g., PAM-JIT-01]
- System/Account: [Affected system or account name]
- Exception Type: [Standing access / Rotation bypass / Session recording waiver / Other]
- Current State: [Description of current non-compliant state]
- Requested Duration: [Time-bounded: max 90 days, must be renewed]

### Business Justification
[Why this exception is operationally necessary]

### Risk Assessment
- Likelihood of exploit: [Low / Medium / High]
- Impact if exploited: [Low / Medium / High / Critical]
- Residual risk level: [Low / Medium / High / Critical]

### Compensating Controls
1. [Control 1 — e.g., enhanced monitoring, additional logging]
2. [Control 2 — e.g., network restriction, IP allowlisting]
3. [Control 3 — e.g., manual review cadence]

### Approval Chain
- [ ] Security team lead: [Name] — Date: [YYYY-MM-DD]
- [ ] Risk owner (business): [Name] — Date: [YYYY-MM-DD]
- [ ] CISO / delegate: [Name] — Date: [YYYY-MM-DD]

### Review Schedule
- Next review date: [Max 90 days from approval]
- Auto-expiry: [Yes — exception reverts to non-compliant finding if not renewed]

### Evidence of Compensating Controls
[Link to monitoring dashboard, audit log configuration, etc.]
```

## Exception Severity Escalation

| Residual Risk | Required Approver | Max Duration | Review Cadence |
|---|---|---|---|
| Low | Security team lead | 180 days | Semi-annual |
| Medium | Security manager + risk owner | 90 days | Quarterly |
| High | CISO | 30 days | Monthly |
| Critical | CISO + CTO/CIO | 14 days | Bi-weekly |
