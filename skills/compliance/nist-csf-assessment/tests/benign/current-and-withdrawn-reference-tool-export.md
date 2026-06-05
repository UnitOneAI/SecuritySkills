---
case: current and withdrawn reference tool export normalized
expected: benign
---

# Current And Withdrawn Reference Tool Export

Source artifact: NIST CSF 2.0 Reference Tool export.
Source checked at: 2026-06-05.

Rows imported:

| ID | Row Status | Current Target(s) | Score In Current Profile | Mapping Source |
|----|------------|-------------------|--------------------------|----------------|
| GV.RR-02 | current | GV.RR-02 | true | CSF 2.0 Core |
| GV.SC-02 | current | GV.SC-02 | true | CSF 2.0 Core |
| ID.AM-06 | withdrawn | GV.RR-02, GV.SC-02 | false | NIST CSF Reference Tool |
| PR.DS-03 | withdrawn | ID.AM-08, PR.PS-03 | false | NIST CSF Reference Tool |

Expected assessment behaviour:

- Score only the current CSF 2.0 Core rows in the main Current Profile vs Target Profile table.
- Preserve ID.AM-06 and PR.DS-03 in the migration appendix as lineage only.
- Use a current CSF 2.0 Core denominator of 2 for this scoped sample.
- Do not mark the withdrawn rows as missing current controls.
