# Benign: federated trust with session guardrails

## Scenario

A production AWS role is available to a named partner automation role through a
federated access workflow. The trust policy narrows the principal, requires the
external ID, requires source identity and session tags, and stores evidence from
Access Analyzer plus CloudTrail.

```yaml
role_name: prod-billing-reconciliation
provider: aws
trust_policy:
  Statement:
    - Effect: Allow
      Principal:
        AWS: arn:aws:iam::222222222222:role/vendor-billing-runner
      Action:
        - sts:AssumeRole
        - sts:TagSession
      Condition:
        StringEquals:
          sts:ExternalId: billing-prod-2026
          aws:PrincipalOrgID: o-abc123
        StringLike:
          sts:SourceIdentity: vendor-billing-*
        ForAllValues:StringEquals:
          aws:TagKeys:
            - workload
            - environment
            - ticket
session_controls:
  max_session_duration_minutes: 60
  required_session_tags:
    workload: billing-reconciliation
    environment: production
    ticket: required
  transitive_tag_keys:
    - workload
    - environment
  mfa_required: service-to-service exception documented
observability:
  access_analyzer_finding:
    status: reviewed
    trusted_principal: arn:aws:iam::222222222222:role/vendor-billing-runner
    condition_keys:
      - sts:ExternalId
      - sts:SourceIdentity
      - aws:PrincipalOrgID
      - aws:TagKeys
  cloudtrail_assume_role_query:
    window: last_30_days
    source_identity_present: true
    required_tags_present: true
    unexpected_principals: 0
review_decision:
  disposition: acceptable
  review_expiry: 2026-07-06
  evidence_owner: identity-security@example.com
```

## Expected Assessment

Do not flag `IAM-TRUST-01` through `IAM-TRUST-08` when the review proves the exact
trusted principal, enforced external ID, source identity, session tags, bounded
duration, Access Analyzer review, CloudTrail assumption evidence, and an expiry
date for re-review.
