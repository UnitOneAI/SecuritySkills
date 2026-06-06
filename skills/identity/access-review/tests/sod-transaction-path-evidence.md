# SoD Transaction Path Evidence Fixtures

These fixtures calibrate the supplemental `AR-SOD-08` through `AR-SOD-14` evidence gates in `access-review`. They separate confirmed toxic access from role-name false positives, mitigated risk, and not-evaluable access review packages.

```yaml
case: production_vendor_to_payment_release_confirmed
identity: finance_ops_042
systems:
  procurement_saas:
    entitlement: vendor_admin
    environment: production
    legal_entity: us_operating_company
    effective_capability: create_or_modify_vendor
  erp_finance:
    entitlement: payment_batch_creator
    environment: production
    legal_entity: us_operating_company
    effective_capability: create_payment_batch
  bank_portal:
    entitlement: payment_releaser
    environment: production
    legal_entity: us_operating_company
    effective_capability: release_payment
conflict_rule:
  id: SOD-FIN-004
  owner: controllership
  version: "2026.2"
  approved_date: "2026-04-15"
  last_reviewed: "2026-05-30"
  applicable_environments:
    - production
transaction_path:
  initiating_step: create_vendor
  approval_step: create_payment_batch
  release_step: release_payment
  workflow_breakpoints: none
compensating_controls:
  independent_review: missing
  monitoring_alert: missing
expected_decision: Fail
expected_findings:
  - check: AR-SOD-02
    severity: Critical
    reason: The same identity can create vendors, create payment batches, and release payments in the same production entity.
```

```yaml
case: sandbox_submitter_and_prod_zero_limit_approver_false_positive
identity: analyst_042
systems:
  invoice_sandbox:
    entitlement: invoice_submitter_sandbox
    environment: sandbox
    production_transaction_creation: disabled
  erp_finance:
    entitlement: payment_approver_prod
    environment: production
    approval_limit: 0
    workflow_state: approval_disabled
conflict_rule:
  id: SOD-FIN-001
  owner: controllership
  version: "2026.1"
  approved_date: "2026-01-10"
  last_reviewed: "2026-05-01"
transaction_path:
  initiating_step: sandbox_only
  approval_step: approval_limit_zero
  release_step: none
  effective_capability_proof: exported_entitlement_and_workflow_config
expected_decision: Pass
expected_findings: []
```

```yaml
case: conflict_rule_missing_provenance
identity: procurement_admin_118
systems:
  procurement_saas:
    entitlement: vendor_admin
  erp_finance:
    entitlement: payment_approver
conflict_rule:
  id: missing
  owner: missing
  version: missing
  approved_date: missing
  last_reviewed: missing
  mapped_systems:
    - procurement_saas
    - erp_finance
transaction_path:
  evidence: partial
expected_decision: Not Evaluable
expected_findings:
  - check: AR-SOD-08
    severity: Medium
    reason: The conflict rule has no owner, version, approval date, review date, or applicable scope evidence.
```

```yaml
case: cross_system_chain_not_mapped
identity: release_engineer_021
systems:
  git:
    entitlement: code_committer
  ci_cd:
    entitlement: deployment_approver
  cloud:
    entitlement: production_change_executor
conflict_rule:
  id: SOD-ENG-003
  owner: engineering_governance
  version: "2026.3"
transaction_path:
  initiating_step: code_commit
  approval_step: missing
  release_step: missing
  workflow_breakpoints: unknown
  effective_capability_proof: missing
expected_decision: Not Evaluable
expected_findings:
  - check: AR-SOD-09
    severity: Medium
    reason: The role combination is flagged, but the review lacks proof that the identity can complete the same deployment transaction path.
  - check: AR-SOD-10
    severity: Medium
    reason: Cross-system access across source control, CI/CD, and cloud execution was not mapped end to end.
```

```yaml
case: compensating_control_documented_but_not_operating
identity: small_team_admin_007
systems:
  erp_finance:
    entitlements:
      - invoice_creator
      - invoice_approver
conflict_rule:
  id: SOD-FIN-002
  owner: controllership
  version: "2026.2"
transaction_path:
  status: confirmed_same_system
compensating_controls:
  description: weekly_manager_review
  independent_reviewer: missing
  sample_results: missing
  alert_on_self_approval: missing
  review_cadence: weekly
  exception_expiry: missing
expected_decision: Fail
expected_findings:
  - check: AR-SOD-12
    severity: High
    reason: The compensating control is documented but lacks independent reviewer, sampled results, alerting, and expiry evidence.
```

```yaml
case: jit_emergency_exception_with_complete_activation_evidence
identity: incident_lead_204
systems:
  siem:
    eligible_roles:
      - security_log_admin
      - security_log_reviewer
assignment_type: eligible_jit
activation:
  ticket: INC-2026-441
  approved_by: soc_manager
  duration_hours: 2
  activated_at: "2026-06-01T13:00:00Z"
  deactivated_at: "2026-06-01T15:00:00Z"
  actions_taken:
    - adjusted_parser_for_active_incident
  post_use_review: completed
  revocation_evidence: privileged_identity_management_log
certifier_independence:
  reviewer: soc_manager
  self_review: false
expected_decision: Pass
expected_findings: []
```

```yaml
case: self_certified_sod_exception
identity: security_admin_313
systems:
  siem:
    entitlements:
      - security_log_admin
      - security_log_reviewer
conflict_rule:
  id: SOD-SEC-001
  owner: security_governance
  version: "2026.1"
exception:
  approved: true
  approved_by: security_admin_313
  certifier: security_admin_313
  independent_reviewer: missing
  expiry: "2026-12-31"
expected_decision: Fail
expected_findings:
  - check: AR-SOD-14
    severity: High
    reason: The identity with the conflicting access approved and certified its own SoD exception.
```
