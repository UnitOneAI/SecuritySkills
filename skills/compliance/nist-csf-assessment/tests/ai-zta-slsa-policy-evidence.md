# AI, Zero Trust, SLSA, and Policy Evidence Fixtures

These fixtures calibrate supplemental evidence overlays for the NIST CSF 2.0 assessment skill.

```yaml
case: ai_governance_missing_ai_rmf
organization:
  uses_ai_for:
    - credit_decision_support
    - security_alert_triage
csf_claim:
  govern_score: 4
evidence:
  ai_inventory: missing
  ai_risk_tiers: missing
  model_data_provenance: missing
  transparency_notice: partial
  model_monitoring: missing
expected_decision: Gap
expected_findings:
  - check: CSF-SUPP-01
    severity: High
    reason: Material AI systems lack AI RMF-aligned governance and risk evidence.
  - check: CSF-SUPP-02
    severity: Medium
    reason: AI transparency, provenance, monitoring, and escalation evidence are incomplete.
```

```yaml
case: zero_trust_tool_purchase_only
csf_claim:
  organizational_tier: 4
zero_trust_evidence:
  purchased_sase_tool: true
  identity_continuous_verification: missing
  device_posture: missing
  application_workload_policy: missing
  data_pillar_policy: missing
  telemetry_policy_feedback: missing
expected_decision: Gap
expected_findings:
  - check: CSF-SUPP-03
    severity: Medium
    reason: Zero Trust maturity is claimed without pillar-specific CISA ZTMM evidence.
  - check: CSF-SUPP-04
    severity: Medium
    reason: Adaptive maturity lacks continuous verification and policy adjustment evidence.
```

```yaml
case: supply_chain_contracts_without_slsa
csf_mapping:
  - GV.SC
  - ID.RA-09
  - PR.PS-06
evidence:
  supplier_contracts: present
  artifact_provenance: missing
  isolated_builds: missing
  artifact_signing: missing
  dependency_policy: partial
  release_attestation: missing
expected_decision: Gap
expected_findings:
  - check: CSF-SUPP-05
    severity: Medium
    reason: Critical software integrity evidence lacks SLSA-style provenance and release controls.
```

```yaml
case: tier2_platform_encryption_false_positive
subcategory: PR.DS-01
target_tier: 2
data_context:
  sensitivity: internal_business
  regulatory_cmek_requirement: false
evidence:
  platform_managed_encryption: enabled
  monitoring: present
  key_rotation_by_provider: documented
  risk_acceptance: approved
  cmek: absent
expected_decision: Pass
expected_findings: []
```

```yaml
case: adaptive_claim_without_policy_as_code
csf_claim:
  organizational_tier: 4
evidence:
  policies_documented: present
  policy_as_code: missing
  automated_control_tests: missing
  drift_detection: missing
  exception_workflow: manual_untracked
expected_decision: Gap
expected_findings:
  - check: CSF-SUPP-04
    severity: Medium
    reason: Tier 4 claim lacks policy-as-code, drift detection, and telemetry-driven adjustment evidence.
```

```yaml
case: complete_supplemental_overlay_package
organization:
  target_tier: 3
evidence:
  ai_rmf:
    inventory: present
    risk_mapping: present
    model_monitoring: present
    incident_escalation: present
  zero_trust:
    identity: advanced
    device: advanced
    network: initial
    application_workload: advanced
    data: advanced
    continuous_verification: present
  slsa:
    provenance: present
    build_isolation: present
    artifact_signing: present
    dependency_policy: present
  policy_as_code:
    opa_or_equivalent: present
    tests: present
    drift_monitoring: present
expected_decision: Pass
expected_findings: []
```
