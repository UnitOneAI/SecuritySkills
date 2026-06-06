# Organizational Tier Evidence Edge Cases

Use these cases to validate that `nist-csf-assessment` does not convert average subcategory scores directly into an organizational CSF Tier.

## Case 1: High technical average with weak GOVERN evidence

**Input**

```yaml
subcategory_scores:
  average: 3.2
  protect_average: 3.8
  detect_average: 3.4
govern_evidence:
  risk_appetite: missing
  board_oversight: ad_hoc
  erm_integration: missing
  roles_and_authorities: partial
  supply_chain_risk_management: partial
reported_tier: Tier 3
```

**Expected result**

Do not accept Tier 3. The organization should be capped at Tier 2 or lower until risk appetite, ERM integration, oversight cadence, roles, and supply chain risk management evidence support repeatable organization-wide risk management.

## Case 2: Claimed Tier 4 without adaptive feedback loops

**Input**

```yaml
current_tier_claim: Tier 4
technical_controls:
  vulnerability_management: mature
  siem_monitoring: mature
adaptive_evidence:
  predictive_indicators: missing
  lessons_learned_to_strategy_updates: missing
  external_intelligence_to_control_changes: missing
  real_time_risk_adjustment: missing
```

**Expected result**

Cap below Tier 4. Strong controls do not prove Adaptive Tier unless there is evidence that lessons learned, predictive indicators, external intelligence, and real-time risk data drive program changes.

## Case 3: Management-approved but inconsistent implementation

**Input**

```yaml
risk_management:
  methodology: approved
  risk_register: maintained
  business_units_covered: 3 of 9
  board_reporting: quarterly
  policy_enforcement: inconsistent
  supplier_monitoring: critical suppliers only
subcategory_scores:
  average: 2.7
```

**Expected result**

Tier 2 is appropriate. Risk practices are approved and partially implemented but not yet organization-wide or consistently enforced.

## Case 4: Complete Tier 3 evidence

**Input**

```yaml
risk_management_process:
  risk_appetite: board_approved
  methodology: standardized
  risk_register: maintained_quarterly
  risk_response_options: documented
integrated_program:
  erm_linkage: established
  budget_linkage: risk_based
  roles_authorities: documented_and_enforced
  oversight_reporting: monthly_to_executives_quarterly_to_board
external_participation:
  supplier_tiering: complete
  supplier_monitoring: active
  incident_coordination: tested_with_critical_suppliers
adaptive_feedback:
  lessons_learned: used_for_policy_updates
  predictive_indicators: limited
```

**Expected result**

Tier 3 is supportable if subcategory evidence is consistent. The organization has repeatable, policy-driven, organization-wide risk management, but limited predictive indicators may prevent Tier 4.
