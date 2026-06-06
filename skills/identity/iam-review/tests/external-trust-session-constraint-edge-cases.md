# External Trust and Session Constraint Edge Cases

These fixtures calibrate the `iam-review` external trust gate. A review should evaluate the permission policy, trust/resource policy, provider configuration, session controls, and analyzer evidence together before passing cross-account, service-principal, or federated access as least privilege.

## Vulnerable: External AWS Account Without Confused-Deputy Control

```yaml
case: external-account-missing-external-id
platform: aws
trust_policy:
  Principal:
    AWS: arn:aws:iam::222222222222:root
  Action: sts:AssumeRole
  Condition: {}
permission_policy:
  Action:
    - s3:GetObject
  Resource: arn:aws:s3:::customer-export/prod/*
analyzer_evidence:
  access_analyzer_finding: external_access
expected_result:
  finding_codes:
    - IAM-TRUST-01
    - IAM-TRUST-02
  decision: Fail
  severity: High
  reason: Narrow permissions do not compensate for a broad external assume-role path without a unique external ID or principal/org scoping.
```

## Vulnerable: Caller-Supplied Session Tags Drive ABAC

```yaml
case: self-asserted-admin-session-tag
platform: aws
trust_policy:
  Action:
    - sts:AssumeRole
    - sts:TagSession
  Condition: {}
authorization_policy:
  allow_when: aws:PrincipalTag/Admin == "true"
session_controls:
  aws_RequestTag_Admin: unrestricted
  aws_TagKeys: unrestricted
  sts_TransitiveTagKeys: unrestricted
expected_result:
  finding_codes:
    - IAM-TRUST-04
    - IAM-TRUST-05
  decision: Fail
  severity: High
  reason: Callers can self-assert privileged tags that ABAC policies treat as authorization facts.
```

## Vulnerable: Shared Admin Role Missing Source Identity

```yaml
case: shared-admin-no-source-identity
platform: aws
role: OrganizationAdmin
trusted_principals:
  - arn:aws:iam::111111111111:role/AdminFederation
  - arn:aws:iam::111111111111:role/AutomationDeploy
session_controls:
  sts_SourceIdentity: not_required
  role_session_name_pattern: not_constrained
  mfa: optional
  max_session_duration: 12h
log_evidence:
  cloudtrail_assume_role_source_identity: missing
expected_result:
  finding_codes:
    - IAM-TRUST-06
    - IAM-TRUST-07
  decision: Fail
  severity: High
  reason: Shared privileged sessions cannot be reliably attributed to an initiating human or workload.
```

## Vulnerable: Federated Trust Missing Issuer/Audience/Subject Restrictions

```yaml
case: federated-claim-drift
platform: azure
federation:
  issuer: https://token.actions.githubusercontent.com
  audience: missing
  subject: repo:example/*:*
  tenant_or_application_scope: broad
provider_evidence: partial
permission_policy:
  scope: production-deploy
expected_result:
  finding_codes:
    - IAM-TRUST-03
  decision: Fail
  severity: High
  reason: The deployment role has least-privilege permissions, but unintended federated principals can obtain the session because claims are not bounded.
```

## Vulnerable: Service Principal Without Source Conditions

```yaml
case: service-principal-no-source-conditions
platform: aws
resource_policy:
  Principal:
    Service: events.amazonaws.com
  Action: sts:AssumeRole
  Condition: {}
supported_controls_not_reviewed:
  - aws:SourceArn
  - aws:SourceAccount
  - aws:SourceOrgID
expected_result:
  finding_codes:
    - IAM-TRUST-02
  decision: Partial
  severity: Medium
  reason: Managed service access may be legitimate, but the review lacks service-specific source constraints needed to prevent confused-deputy access.
```

## Vulnerable: Permission Policy Only

```yaml
case: permission-policy-only
platform: aws
available_evidence:
  identity_permission_policy: present
  trust_policy: missing
  resource_policy: missing
  provider_configuration: missing
  analyzer_evidence: missing
expected_result:
  finding_codes:
    - IAM-TRUST-09
  decision: Not Evaluable
  severity: Medium
  reason: The reviewer cannot determine who can obtain the role session from permission policy evidence alone.
```

## Benign: Complete Bounded Trust and Session Evidence

```yaml
case: complete-bounded-trust-session
platform: aws
trust_policy:
  Principal:
    AWS: arn:aws:iam::222222222222:role/vendor-collector
  Action: sts:AssumeRole
  Condition:
    StringEquals:
      sts:ExternalId: vendor-customer-unique-id
      aws:PrincipalOrgID: o-a1b2c3d4e5
    StringLike:
      sts:RoleSessionName: vendor-collector-*
    Bool:
      aws:MultiFactorAuthPresent: "true"
session_controls:
  sts_SourceIdentity: required
  max_session_duration: 1h
  sts_TagSession: disabled
analyzer_evidence:
  access_analyzer_finding: none_active
permission_policy:
  actions:
    - logs:FilterLogEvents
  resource_scope: account-specific-log-groups
expected_result:
  finding_codes: []
  decision: Pass
  severity: Informational
  reason: Permission, trust, session attribution, confused-deputy controls, and analyzer evidence are all bounded.
```
