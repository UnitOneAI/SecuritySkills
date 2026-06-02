# Vulnerable: subcategory score treated as an organizational tier

```text
ID.AM-01 current score: 3 / Tier 3
Evidence: asset inventory spreadsheet
Missing: update cadence, authoritative source, coverage percentage, lifecycle
owner, reconciliation signal, organizational risk-management integration
```

Expected assessment: flag the tier calibration error. CSF tiers describe the
organization's overall risk management posture, not an individual subcategory.
The asset inventory can support an ID.AM-01 profile score, but it cannot by
itself prove a Tier 3 organizational posture.
