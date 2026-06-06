# ISO 27001 Climate, AI Asset, and Destructive Recovery Fixtures

These fixtures calibrate the supplemental evidence gates in `SKILL.md`.

```yaml
case: climate_context_missing
scope:
  locations:
    - coastal_datacenter
  critical_services:
    - customer_portal
evidence:
  clause_4_1_context_review: present
  climate_relevance_determination: missing
  supplier_disruption_review: missing
  rationale_if_not_relevant: missing
expected_decision: Gap
expected_findings:
  - check: ISO27001-AMD-01
    classification: Minor Nonconformity
    reason: Clause 4.1 context evidence does not determine whether climate change is relevant to the ISMS.
```

```yaml
case: climate_not_relevant_with_traceability
scope:
  service_model: remote_saas
  facilities_dependency: none_for_in_scope_processing
evidence:
  clause_4_1_context_review: present
  climate_relevance_determination: not_relevant
  rationale_if_not_relevant: documented
  interested_party_review: documented
  review_cadence: annual
expected_decision: Pass
expected_findings: []
```

```yaml
case: qualitative_risk_false_positive
risk_methodology:
  scoring: qualitative
  likelihood_levels: documented
  impact_levels: documented
  acceptance_thresholds: documented
  reassessment_triggers: documented
  owner_approval: documented
expected_decision: Pass
expected_findings: []
```

```yaml
case: qualitative_risk_not_repeatable
risk_methodology:
  scoring: qualitative
  likelihood_levels: missing
  impact_levels: missing
  acceptance_thresholds: missing
  reassessment_triggers: informal
  owner_approval: missing
expected_decision: Gap
expected_findings:
  - check: ISO27001-RISK-01
    classification: Minor Nonconformity
    reason: Qualitative ratings lack criteria and approval evidence required for repeatable Clause 6.1.2 results.
```

```yaml
case: shadow_ai_missing_from_asset_inventory
assets:
  approved_saas:
    - crm
    - ticketing
  ai_integrated_saas: missing
  prompt_stores: missing
  shadow_ai_discovery: missing
evidence:
  procurement_export: present
  idp_app_inventory: present
  dlp_ai_destination_review: missing
expected_decision: Gap
expected_findings:
  - check: ISO27001-AI-01
    classification: Minor Nonconformity
    reason: A.5.9 inventory excludes AI-integrated SaaS, prompt stores, and shadow AI discovery evidence.
```

```yaml
case: destructive_recovery_cloud_replication_only
continuity_scope:
  destructive_malware: in_scope
  critical_service: order_processing
recovery_evidence:
  cloud_replication: enabled
  immutable_backup: missing
  deletion_protection: missing
  separate_admin_plane: missing
  last_known_good_selection: missing
  malware_scan_before_restore: missing
  restore_test_result: missing
expected_decision: Not Evaluable
expected_findings:
  - check: ISO27001-BC-01
    classification: Major Nonconformity
    reason: Destructive-event continuity scope lacks recoverability evidence for critical services.
  - check: ISO27001-BC-02
    classification: Minor Nonconformity
    reason: Standard cloud replication is treated as sufficient without immutability, deletion protection, admin separation, or restore testing.
```

```yaml
case: complete_amendment_ai_resilience_package
evidence:
  climate:
    clause_4_1_relevance: documented
    clause_4_2_interested_parties: documented
    owners_and_review_cadence: documented
  risk_methodology:
    scoring: semi_quantitative
    criteria: documented
    acceptance_thresholds: documented
    owner_approval: documented
  ai_assets:
    approved_gen_ai_services: inventoried
    ai_integrated_saas: inventoried
    shadow_ai_discovery: performed
    data_classification: linked
  continuity:
    destructive_malware: in_scope
    immutable_backup: verified
    deletion_protection: enabled
    separate_admin_plane: verified
    last_known_good_selection: documented
    malware_scan_before_restore: passed
    restore_test_result: passed
  transition:
    from_2013: true
    new_2022_controls_evaluated: true
expected_decision: Pass
expected_findings: []
```
