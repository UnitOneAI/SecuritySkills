# SoA Risk Traceability Edge Cases

Use these cases to validate that `iso27001-gap` treats the Statement of Applicability as a risk-driven artifact, not a checklist of Annex A controls.

## Case 1: Blanket inclusion without risk linkage

**Input**

```yaml
soa:
  scope: enterprise
  controls_applicable: 93
  controls_excluded: 0
  rationale: all controls are included for certification
sample_record:
  control: A.8.11
  title: Data masking
  applicable: true
  linked_risk: missing
  legal_or_contractual_driver: missing
  treatment_option: missing
  owner: missing
  evidence_location: missing
```

**Expected result**

Classify as a major nonconformity if this pattern is systemic. Including all controls does not satisfy Clause 6.1.3 unless control selection traces to risks, obligations, treatment decisions, owners, and evidence.

## Case 2: Generic exclusion for a cloud control

**Input**

```yaml
soa_record:
  control: A.5.23
  title: Information security for use of cloud services
  applicable: false
  exclusion_justification: not relevant
  scope:
    systems: customer SaaS platform
    hosting: AWS
  linked_risk: missing
  evidence_location: missing
```

**Expected result**

Reject the exclusion. The organization uses cloud services, so a generic "not relevant" justification is not auditor-defensible and should be classified as at least a minor nonconformity, or major if repeated.

## Case 3: Residual risk accepted by wrong owner

**Input**

```yaml
soa_record:
  control: A.8.16
  title: Monitoring activities
  applicable: true
  driver: risk
  linked_risk: RISK-044
  treatment_option: accept
  residual_risk: limited monitoring in legacy environment
  residual_risk_acceptance:
    approver: security analyst
    date: 2026-06-01
  risk_owner: business system owner
```

**Expected result**

Mark traceability as partial or failing. Residual risk should be accepted by the accountable risk owner, not only by the control implementer or analyst.

## Case 4: Complete traceable SoA record

**Input**

```yaml
soa_record:
  control: A.5.7
  title: Threat intelligence
  applicable: true
  decision_driver: risk
  linked_risk_requirement_id: RISK-017
  applicability_rationale: ransomware and supply chain threats affect in-scope SaaS operations
  risk_treatment_option: mitigate
  treatment_plan_link: GRC-PLAN-017
  control_owner: security-operations
  evidence_location: grc://iso27001/soa/a.5.7
  implementation_status: measured
  residual_risk: medium after mitigations
  residual_risk_acceptance: CISO 2026-06-30
  last_reviewed: 2026-06-30
```

**Expected result**

Pass the SoA traceability gate. The record ties applicability to a risk driver, treatment plan, owner, evidence, residual risk, and review date.
