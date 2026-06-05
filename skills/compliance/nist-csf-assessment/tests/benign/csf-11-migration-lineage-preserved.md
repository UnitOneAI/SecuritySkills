---
case: csf 1.1 migration lineage preserved
expected: benign
---

# CSF 1.1 Migration Lineage Preserved

Client evidence arrives from a CSF 1.1 transition workbook:

```yaml
client_evidence:
  ID.GV-03: "Legal and regulatory requirements are documented"
normalization:
  row_status: legacy_mapped
  mapped_to: GV.OC-03
  mapping_source: "NIST CSF 1.1 to 2.0 migration workbook"
  evidence_revalidated_against_current_outcome: partial
  score_in_current_profile: false
```

Expected assessment behaviour:

- Keep ID.GV-03 in the CSF 1.1 / withdrawn row migration appendix.
- Do not score the legacy ID directly in the current CSF 2.0 Core denominator.
- Require revalidation before evidence is assigned to GV.OC-03.
- Avoid copying legacy evidence into multiple targets unless each target is supported.
