# Vulnerable: deidentified analytics export remains linkable

## Scenario

A healthcare analytics dataset is labeled `deidentified`, then exported to a feature store and marketing dashboard. The owner has no Expert Determination report, no Safe Harbor checklist, no quasi-identifier review, and no downstream lineage showing whether logs or derived features can recreate ePHI context.

```yaml
warehouse_dataset: patient_outcomes_analytics
claimed_status: deidentified
deidentification_method: missing
safe_harbor_checklist: missing
expert_determination:
  expert_name: missing
  determination_date: missing
  methods_and_results: missing
fields:
  - birth_year
  - zip3
  - diagnosis_group
  - visit_month
  - device_id_hash
derived_identifiers:
  device_id_hash:
    salt_or_key_custody: unknown
    linkage_possible_with_mobile_events: true
exports:
  - destination: ml_feature_store
    row_key: patient_feature_hash
  - destination: marketing_attribution_dashboard
    cohort_min_size: 4
logs:
  prompt_debug: full_query_and_results
scope_decision:
  excluded_from_ephi_inventory: true
  rationale: dataset label says deidentified
```

## Expected Findings

- `HIPAA-DEID-01`: De-identification method evidence is missing.
- `HIPAA-DEID-03`: Safe Harbor removal/generalization evidence is missing.
- `HIPAA-DEID-04`: Quasi-identifiers such as ZIP3, dates, diagnosis group, and small cohorts need review.
- `HIPAA-DEID-05`: Hashed device IDs and feature keys need linkage and salt/key custody evidence.
- `HIPAA-DEID-06`: Downstream feature store, dashboard, and prompt/debug logs need lineage review.
- `HIPAA-DEID-08`: Scope decision should be `not_evaluable_treat_as_ephi` until evidence is complete.

## Expected Assessment

Do not exclude this dataset or its downstream systems from HIPAA Security Rule scoping based only on the `deidentified` label. Treat as ePHI for security review until privacy/legal review documents the de-identification basis and residual re-identification risk.
