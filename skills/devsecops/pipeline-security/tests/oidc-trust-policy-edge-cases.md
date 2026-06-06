# OIDC Trust-Policy Claim Edge Cases

These fixtures calibrate the `pipeline-security` OIDC/workload identity trust-policy gate. The expected behavior is to evaluate workflow-side token issuance and cloud-side trust conditions together before treating short-lived credentials as safe.

## Vulnerable: AWS Role Trusts Any Ref in the Repository

```yaml
case: aws-broad-repo-subject
workflow:
  permissions:
    id-token: write
    contents: read
  job: deploy
  ref: refs/pull/44/merge
cloud_trust_policy:
  provider: aws
  issuer: https://token.actions.githubusercontent.com
  conditions:
    StringEquals:
      token.actions.githubusercontent.com:aud: sts.amazonaws.com
    StringLike:
      token.actions.githubusercontent.com:sub: repo:acme/payments:*
expected_result:
  decision: Fail
  reason: Production role accepts every branch, tag, pull request, and environment from the repository.
  required_evidence: Narrow sub to a protected branch/environment, such as repo:acme/payments:environment:production, and document fork/PR reachability.
```

## Vulnerable: AWS Trust Policy Missing Audience Check

```yaml
case: aws-missing-audience
workflow:
  permissions:
    id-token: write
  requested_audience: sts.amazonaws.com
cloud_trust_policy:
  provider: aws
  issuer: https://token.actions.githubusercontent.com
  conditions:
    StringEquals:
      token.actions.githubusercontent.com:sub: repo:acme/payments:ref:refs/heads/main
expected_result:
  decision: Fail
  reason: Trust policy constrains subject but does not verify the intended audience.
  required_evidence: Add and verify token.actions.githubusercontent.com:aud equals sts.amazonaws.com.
```

## Vulnerable: Azure Federated Credential Mismatched Subject and Audience

```yaml
case: azure-subject-audience-mismatch
workflow:
  permissions:
    id-token: write
  requested_audience: api://AzureADTokenExchange
  expected_subject: repo:acme/payments:environment:production
cloud_trust_policy:
  provider: azure
  issuer: https://token.actions.githubusercontent.com
  federated_credential:
    subject: repo:acme/payments:ref:refs/heads/main
    audiences:
      - api://WrongAudience
expected_result:
  decision: Fail
  reason: Microsoft Entra federated credential subject and audience do not match the external token expected by the workflow.
  required_evidence: Align issuer, subject, and audience exactly, then bind production credentials to the protected environment or intended ref.
```

## Vulnerable: Google WIF Provider Without Organization Attribute Conditions

```yaml
case: gcp-wif-missing-organization-condition
workflow:
  permissions:
    id-token: write
  repository: acme/payments
cloud_trust_policy:
  provider: gcp
  issuer: https://token.actions.githubusercontent.com
  attribute_mapping:
    google.subject: assertion.sub
    attribute.repository: assertion.repository
    attribute.ref: assertion.ref
  attribute_condition: attribute.repository == "acme/payments"
expected_result:
  decision: Partial
  reason: Repository is constrained, but shared GitHub issuer risk is not reduced with organization/owner and deployment ref/environment conditions.
  required_evidence: Add organization/owner, repository, ref/environment, and workflow-context conditions before production service account impersonation.
```

## Vulnerable: Reusable Workflow Without job_workflow_ref Restriction

```yaml
case: reusable-workflow-no-job-workflow-ref
workflow:
  caller: acme/app/.github/workflows/release.yml@refs/heads/main
  reusable_workflow: acme/deploy/.github/workflows/prod.yml@refs/tags/v1
  permissions:
    id-token: write
cloud_trust_policy:
  provider: aws
  conditions:
    StringEquals:
      token.actions.githubusercontent.com:aud: sts.amazonaws.com
    StringLike:
      token.actions.githubusercontent.com:sub: repo:acme/*:*
  job_workflow_ref_condition: missing
expected_result:
  decision: Fail
  reason: Any matching caller repository can use the reusable workflow path to mint cloud credentials because job_workflow_ref is not constrained.
  required_evidence: Restrict job_workflow_ref or equivalent provider-side claim to the approved reusable workflow and immutable ref.
```

## Benign: Complete Least-Privilege OIDC Configuration

```yaml
case: complete-least-privilege-oidc
workflow:
  file: .github/workflows/deploy.yml
  job: deploy-production
  permissions:
    contents: read
    id-token: write
  environment: production
  ref: refs/heads/main
cloud_trust_policy:
  provider: aws
  issuer: https://token.actions.githubusercontent.com
  conditions:
    StringEquals:
      token.actions.githubusercontent.com:aud: sts.amazonaws.com
      token.actions.githubusercontent.com:sub: repo:acme/payments:environment:production
    StringLike:
      token.actions.githubusercontent.com:job_workflow_ref: acme/payments/.github/workflows/deploy.yml@refs/heads/main
controls:
  branch_protection: required_reviews_and_status_checks
  environment_protection: required_reviewers
  fork_pull_request_access: blocked_from_environment
expected_result:
  decision: Pass
  reason: Token issuance, audience, subject, workflow ref, branch, environment, and fork/PR reachability are all bounded for production credentials.
  required_evidence: Record issuer, aud, sub, job_workflow_ref, protected environment, branch protection, and cloud role policy in the OIDC evidence table.
```
