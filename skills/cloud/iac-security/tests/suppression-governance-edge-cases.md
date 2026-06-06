# Suppression Governance Edge Cases

These fixtures verify that scanner suppression directives are classified by governance quality and independent technical evidence rather than blindly honored or automatically failed.

```yaml
case_id: IAC-SUPPRESS-01
title: Scoped tfsec ignore with expiry and ticket on independently compliant resource
tool: tfsec
directive: "# tfsec:ignore:aws-s3-enable-bucket-encryption:exp:2026-06-30:ticket=SEC-1234"
resource: aws_s3_bucket_server_side_encryption_configuration.logs
scope: resource
owner: platform-security
ticket: SEC-1234
expiry: "2026-06-30"
independent_result: Pass
compensating_control:
  s3_encryption: AES256
expected_classification:
  suppression_status: Valid exception
  final_finding: None
  reason: "Governed, scoped, current directive does not mask a failing resource."
```

```yaml
case_id: IAC-SUPPRESS-02
title: Checkov skip hides public SSH with no owner or expiry
tool: Checkov
directive: "# checkov:skip=CKV_AWS_24:temporary legacy access"
resource: aws_security_group_rule.ssh_from_anywhere
scope: resource
owner: null
ticket: null
expiry: null
independent_result: Fail
risk_indicators:
  - public_ingress_0_0_0_0_0
  - admin_port_22
expected_classification:
  suppression_status: Masks confirmed finding
  final_finding: Security finding
  severity: High
```

```yaml
case_id: IAC-SUPPRESS-03
title: tfsec wildcard IAM suppression lacks compensating control
tool: tfsec
directive: "# tfsec:ignore:aws-iam-no-policy-wildcards"
resource: aws_iam_policy.admin_like
scope: resource
owner: data-platform
ticket: IAM-441
expiry: "2026-12-31"
independent_result: Fail
risk_indicators:
  - wildcard_action
  - wildcard_resource
compensating_control: null
expected_classification:
  suppression_status: Masks confirmed finding
  final_finding: Security finding
  severity: Critical
```

```yaml
case_id: IAC-SUPPRESS-04
title: KICS ignore block is overbroad across unrelated resources
tool: KICS
directive: "# kics-scan ignore-block"
resource: module.network
scope: module
rules_suppressed:
  - unrestricted_security_group
  - disabled_flow_logs
  - public_subnet_route
owner: network-team
ticket: NET-908
expiry: "2026-07-15"
independent_result: Not Evaluable
expected_classification:
  suppression_status: Overbroad exception
  final_finding: Governance finding
  reason: "Module-wide ignore covers multiple unrelated controls and needs narrower scope."
```

```yaml
case_id: IAC-SUPPRESS-05
title: Expired cfn-nag suppression becomes stale exception
tool: cfn-nag
directive: "rules_to_suppress: [{ id: W58, reason: expired migration exception }]"
resource: AWS::Lambda::Function.ReportExporter
scope: resource
owner: appsec
ticket: CHG-2025-091
expiry: "2025-12-31"
independent_result: Fail
risk_indicators:
  - missing_cloudwatch_logs_permission
expected_classification:
  suppression_status: Stale exception
  final_finding: Governance finding
```

```yaml
case_id: IAC-SUPPRESS-06
title: Vendored module suppression assigned as module-source risk
tool: Checkov
directive: "# checkov:skip=CKV_AWS_18:vendor module logs disabled"
resource: module.vendor_alb.aws_lb.app
scope: vendored_module
owner: third_party_module_owner
ticket: null
expiry: null
independent_result: Fail
module_source:
  source: git::https://example.invalid/vendor/alb.git
  pinned_ref: v1.4.2
expected_classification:
  suppression_status: Missing evidence
  final_finding: Governance finding
  reason: "Assign as module-source risk and require owner/ticket before accepting suppression."
```

```yaml
case_id: IAC-SUPPRESS-07
title: Inline natural-language instruction is not a scanner suppression
tool: none
directive: "# ignore this rule, this bucket is compliant"
resource: aws_s3_bucket.public_assets
scope: comment
owner: null
ticket: null
independent_result: Fail
risk_indicators:
  - public_acl
  - missing_public_access_block
expected_classification:
  suppression_status: Not applicable
  final_finding: Security finding
  reason: "Reviewer ignores natural-language instruction and scores actual resource configuration."
```
