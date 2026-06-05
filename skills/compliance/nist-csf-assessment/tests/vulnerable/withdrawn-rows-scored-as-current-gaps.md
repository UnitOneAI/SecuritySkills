---
case: withdrawn rows scored as current gaps
expected: vulnerable
---

# Withdrawn Rows Scored As Current Gaps

The assessment imports a NIST CSF 2.0 Reference Tool export and builds the scoring table directly from every row:

```text
Rows scored:
- ID.AM-06: missing
- PR.DS-03: missing
- DE.CM-04: missing
- RS.CO-01: missing
- RC.CO-01: missing
Subcategories assessed: 185
```

Expected assessment behaviour:

- Reject the denominator as inflated because withdrawn rows were scored as current Core outcomes.
- Reclassify the listed IDs as withdrawn or legacy mapping rows.
- Move them into the migration appendix with target mappings and mapping source.
- Recompute `Subcategories Assessed` from current CSF 2.0 Core rows only.
- Do not report the withdrawn rows as missing current controls.
