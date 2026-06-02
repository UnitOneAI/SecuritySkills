# Vulnerable: TRA evidence is conflated with customized approach evidence

```yaml
requirement_frequency:
  requirement: 10.4.2
  selected_frequency: monthly
  rationale: low transaction volume
  targeted_risk_analysis_12_3_1: missing
customized_control:
  requirement: 8.4.2
  approach: customized
  objective_mapping: missing
  control_matrix: missing
  targeted_risk_analysis_12_3_2: missing
  assessor_derived_testing: missing
compensating_control:
  requirement: 11.6.1
  worksheet: generic risk acceptance note
```

Expected assessment: flag separate evidence gaps. Flexible-frequency TRA,
customized approach validation, and compensating controls are different PCI DSS
paths and cannot be satisfied by one generic risk acceptance statement.
