# SOC 2 Subservice Organization and CUEC Evidence Fixtures

These fixtures calibrate CC9.2 and system-description readiness for subservice organization and complementary-control evidence.

```yaml
case: vendor_reports_collected_without_subservice_mapping
audit_period: 2026-01-01_to_2026-12-31
vendors:
  - name: AWS
    supports_system_objectives:
      - infrastructure_availability
      - physical_security
      - environmental_controls
    soc2_report_collected: true
    reporting_method: not_documented
    report_period: 2025-01-01_to_2025-12-31
    bridge_letter: missing
    cuecs_extracted: false
    internal_control_mapping: []
expected_decision: Provisional
expected_findings:
  - check: SOC2-SUBSERVICE-01
    severity: High
    reason: Critical provider role is not classified as vendor, carved-out, or included subservice organization.
  - check: SOC2-SUBSERVICE-03
    severity: Medium
    reason: Vendor report period does not cover the audit period and bridge evidence is missing.
  - check: SOC2-SUBSERVICE-04
    severity: High
    reason: Complementary controls were not extracted from the vendor report.
```

```yaml
case: cuecs_extracted_but_unmapped
provider: cloud_provider
reporting_method: carved_out
cuecs_from_report:
  - Customer configures logical access to cloud consoles.
  - Customer enables logging for in-scope workloads.
  - Customer reviews privileged users periodically.
mapped_internal_controls: []
expected_decision: Gap
expected_findings:
  - check: SOC2-SUBSERVICE-05
    severity: High
    reason: CUECs are not mapped to owners, control IDs, frequencies, and evidence artifacts.
```

```yaml
case: bridge_letter_closes_period_gap
audit_period: 2026-01-01_to_2026-12-31
provider: payment_processor
reporting_method: carved_out
report_period: 2025-10-01_to_2026-09-30
bridge_letter:
  covers_period: 2026-10-01_to_2026-12-31
  reviewed_by: compliance_owner
  review_date: "2026-12-15"
cuecs_extracted: true
internal_control_mapping:
  - cuec: Customer reviews dashboard users quarterly.
    owner: finance_ops
    control_id: CC6.1-QAR
    frequency: quarterly
    evidence: access_review_q4
expected_decision: Pass
expected_findings: []
```

```yaml
case: nda_limited_vendor_report_without_alternative_assurance
provider: support_platform
report_access: nda_required_not_obtained
security_summary: received
reviewer: missing
review_date: missing
exceptions_reviewed: false
alternative_assurance:
  questionnaire: missing
  iso_certificate: missing
  pen_test_summary: missing
  contract_controls: partial
expected_decision: Not Evaluable
expected_findings:
  - check: SOC2-SUBSERVICE-07
    severity: Medium
    reason: SOC report is unavailable and no qualified alternative assurance package is documented.
```

```yaml
case: nested_subservice_not_evaluated
provider: identity_provider
reporting_method: carved_out
soc2_report_collected: true
nested_subservice_providers:
  - cloud_hosting_provider
report_carves_out_nested_subservices: true
nested_subservice_review: missing
cuecs_extracted: true
internal_control_mapping:
  - cuec: Customer maintains MFA and SSO configuration.
    owner: identity_team
    control_id: CC6.1-MFA
    frequency: continuous
    evidence: conditional_access_policy
expected_decision: Partial
expected_findings:
  - check: SOC2-SUBSERVICE-06
    severity: Medium
    reason: Nested subservice providers carved out of the vendor report were not evaluated for residual risk.
```

```yaml
case: complete_subservice_and_cuec_mapping
audit_period: 2026-01-01_to_2026-12-31
provider: aws
role: carved_out_subservice_organization
system_dependency: hosting_and_infrastructure_availability
data_touched:
  - encrypted_customer_data
reporting_method: carved_out
report_period: 2026-01-01_to_2026-09-30
bridge_letter:
  covers_period: 2026-10-01_to_2026-12-31
  reviewed_by: compliance_owner
  review_date: "2026-12-20"
report_opinion: unqualified
exceptions: none_relevant
nested_subservice_review: completed
cuecs_extracted: true
internal_control_mapping:
  - cuec: Customer configures logical access to cloud consoles.
    owner: cloud_security
    control_id: CC6.1-IAM
    frequency: continuous
    evidence: iam_policy_and_access_review
  - cuec: Customer enables logging for in-scope workloads.
    owner: security_operations
    control_id: CC7.2-LOG
    frequency: continuous
    evidence: cloudtrail_and_siem_exports
expected_decision: Pass
expected_findings: []
```
