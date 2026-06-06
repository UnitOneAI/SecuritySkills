# Benign: expert-determined low-risk analytics export

## Scenario

The organization documents the de-identification basis, recipient context, quasi-identifier handling, downstream lineage, logging controls, and residual risk before excluding an analytics export from ePHI scope.

```yaml
warehouse_dataset: patient_outcomes_trends_public
claimed_status: deidentified
deidentification_method: expert_determination
expert_determination:
  expert_name: privacy-statistician@example.org
  determination_date: 2026-06-01
  anticipated_recipient: internal_population_health_team
  methods_and_results_document: DEID-2026-14
  residual_risk_conclusion: very_small
  next_review_date: 2027-06-01
quasi_identifier_controls:
  geography: state_only
  dates: year_only
  age: five_year_bands_with_90_plus_aggregation
  rare_diagnosis_groups: suppressed_when_cohort_under_20
derived_identifier_controls:
  row_ids: random_non_reversible_per_export
  linkage_code_custody: privacy_team_only
downstream_lineage:
  approved_destinations:
    - population_health_dashboard
  prohibited_destinations:
    - marketing_attribution_dashboard
    - prompt_debug_logs
logging_controls:
  query_logs: aggregate_only
  prompt_debug: disabled
scope_decision:
  excluded_from_ephi_inventory: true
  rationale: expert determination documented and downstream linkage controlled
```

## Expected Assessment

Do not flag `HIPAA-DEID-01` through `HIPAA-DEID-08` when the review records method evidence, qualified expert review, quasi-identifier controls, derived identifier custody, downstream lineage, logging controls, residual risk, and a documented scope decision.
