# Risk Exception Request Template

Extracted from the patch-prioritization SKILL.md.

```
Risk Exception Request:
- Exception ID:        [EXC-YYYY-NNNN]
- Date Requested:      [YYYY-MM-DD]
- CVE ID(s):           [List]
- Affected System(s):  [List]
- Original SLA Tier:   [P0-P5]
- Original Deadline:   [YYYY-MM-DD]
- Requested Extension: [N days, new deadline YYYY-MM-DD]
- Business Justification: [Specific reason patch cannot be applied]
- Compensating Controls:  [Reference compensating control assessment]
- Residual Risk:          [Impact description and likelihood]
- Review Date:            [YYYY-MM-DD, within maximum exception duration]
- Approver:               [Name, title]
- Approval Date:          [YYYY-MM-DD]
- Status:                 [Pending | Approved | Denied | Expired]
```

## Risk Acceptance Criteria

A risk acceptance is only valid when ALL of the following conditions are met:

1. **Business justification documented:** A specific, verifiable reason why the patch cannot be applied within the SLA
2. **Compensating controls in place:** At least one compensating control assessed as "Full" or "Partial" effectiveness
3. **Residual risk quantified:** The remaining risk after compensating controls is documented with potential business impact
4. **Expiration date set:** Every risk acceptance has a mandatory review/expiration date (maximum 90 days for P1-P2, 180 days for P3-P4)
5. **Appropriate authority approval:** Risk acceptance is signed by the appropriate level based on severity tier
