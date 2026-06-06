# Third-Party AWS Role Trust Edge Cases

These fixtures verify that `aws-review` records ExternalId, source constraints, lifecycle, session, and sensitive read-only exposure evidence before passing third-party AssumeRole trust.

```yaml
case_id: AWS-TP-01
title: Vendor scanner role has ExternalId and lifecycle evidence
trust_policy:
  principal: arn:aws:iam::123456789012:root
  action: sts:AssumeRole
  condition:
    StringEquals:
      sts:ExternalId: vendor-generated-customer-guid
permissions:
  managed_policies:
    - SecurityAudit
session:
  max_session_duration_seconds: 3600
evidence:
  owner: cloud-security
  contract: VRM-2026-044
  external_id_rotation: "2026-05-01"
  role_last_used: "2026-06-01T10:00:00Z"
  access_analyzer_status: reviewed
expected_classification:
  status: Pass
  confidence: High
  reason: "ExternalId, owner, contract, rotation, session duration, and reviewed external access evidence are present."
```

```yaml
case_id: AWS-TP-02
title: Vendor account root trust lacks ExternalId
trust_policy:
  principal: arn:aws:iam::123456789012:root
  action: sts:AssumeRole
  condition: {}
permissions:
  managed_policies:
    - SecurityAudit
    - ReadOnlyAccess
expected_classification:
  status: Fail
  severity: High
  confidence: High
  reason: "Third-party account-root trust without sts:ExternalId exposes confused-deputy risk even when permissions are read-only."
```

```yaml
case_id: AWS-TP-03
title: Stale vendor role remains assumable after contract termination
trust_policy:
  principal: arn:aws:iam::123456789012:root
  condition:
    StringEquals:
      sts:ExternalId: vendor-generated-customer-guid
lifecycle:
  contract_status: terminated
  offboarding_ticket: complete
  role_last_used: "2026-06-05T12:00:00Z"
  termination_date: "2026-05-31"
expected_classification:
  status: Fail
  severity: High
  confidence: High
  reason: "Role remained assumable and active after vendor offboarding completed."
```

```yaml
case_id: AWS-TP-04
title: AWS service principal lacks SourceArn and SourceAccount constraints
trust_policy:
  principal:
    Service: cloudtrail.amazonaws.com
  action: sts:AssumeRole
  condition: {}
service_context:
  expected_source_account: "111122223333"
  expected_source_arn: arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail
expected_classification:
  status: Not Evaluable
  not_evaluable_reason: AWS-TP-NE-03
  reason: "Service-principal confused-deputy applicability or SourceArn/SourceAccount evidence is missing."
```

```yaml
case_id: AWS-TP-05
title: OIDC role allows broad subject and audience
trust_policy:
  federated_principal: arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com
  action: sts:AssumeRoleWithWebIdentity
  condition:
    StringLike:
      token.actions.githubusercontent.com:sub: repo:example-org/*:*
    StringEquals:
      token.actions.githubusercontent.com:aud: sts.amazonaws.com
expected_classification:
  status: Fail
  severity: High
  confidence: Medium
  reason: "OIDC subject allows every repository in the organization instead of the intended repo, branch, or environment."
```

```yaml
case_id: AWS-TP-06
title: Long vendor session duration lacks CloudTrail session review
trust_policy:
  principal: arn:aws:iam::123456789012:root
  condition:
    StringEquals:
      sts:ExternalId: vendor-generated-customer-guid
session:
  max_session_duration_seconds: 43200
evidence:
  cloudtrail_assume_role_review: missing
  session_tags_required: false
expected_classification:
  status: Not Evaluable
  not_evaluable_reason: AWS-TP-NE-05
  reason: "Long vendor sessions need AssumeRole activity and session-control evidence before acceptance."
```

```yaml
case_id: AWS-TP-07
title: Read-only vendor scope includes sensitive inventories without review
trust_policy:
  principal: arn:aws:iam::123456789012:root
  condition:
    StringEquals:
      sts:ExternalId: vendor-generated-customer-guid
permissions:
  managed_policies:
    - ReadOnlyAccess
  sensitive_read_scope:
    - s3_inventory
    - cloudtrail_events
    - securityhub_findings
    - secretsmanager_metadata
evidence:
  data_exposure_review: missing
expected_classification:
  status: Not Evaluable
  not_evaluable_reason: AWS-TP-NE-07
  reason: "Read-only access can expose sensitive security and data inventory and needs documented scope review."
```
