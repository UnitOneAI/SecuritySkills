# Vulnerable: cross-account trust without session evidence

## Scenario

A production AWS role can be assumed from a partner account. The trust policy allows
the partner root principal and mentions an external ID in a tag, but the trust policy
does not enforce that external ID, session tags, source identity, or bounded session
duration. The review closes the role as acceptable because the partner account is
known.

```yaml
role_name: prod-billing-reconciliation
provider: aws
trust_policy:
  Statement:
    - Effect: Allow
      Principal:
        AWS: arn:aws:iam::222222222222:root
      Action: sts:AssumeRole
      Condition:
        StringEquals:
          aws:PrincipalOrgID: o-abc123
role_tags:
  external_id_expected: billing-prod-2026
session_controls:
  max_session_duration_hours: 12
  require_source_identity: false
  require_session_tags: false
  transitive_tag_keys: []
  mfa_required: unknown
observability:
  cloudtrail_assume_role_query: missing
  access_analyzer_finding: archived_as_intended
  last_assumed_by: unknown
review_decision:
  disposition: acceptable
  reason: partner account is known and belongs to our organization
```

## Expected Findings

- `IAM-TRUST-01`: External principal is broad and lacks a required `sts:ExternalId` condition.
- `IAM-TRUST-02`: Trust is accepted from metadata instead of an enforceable trust-policy condition.
- `IAM-TRUST-03`: Role assumption does not require `sts:SourceIdentity` or equivalent attribution.
- `IAM-TRUST-04`: Required session tags and transitive tag keys are missing.
- `IAM-TRUST-05`: Session duration exceeds the bounded duration expected for partner access.
- `IAM-TRUST-06`: Access Analyzer evidence is archived without showing the exact trusted principal and condition set.
- `IAM-TRUST-07`: CloudTrail evidence for recent `AssumeRole` use is missing.

## Expected Assessment

Do not close the role as acceptable until the trust policy enforces the partner
principal, external ID, source identity, required session tags, bounded duration,
and CloudTrail / Access Analyzer evidence that proves actual assumption behavior.
