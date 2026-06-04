---
name: workload-federation-broad-trust
expected: vulnerable
---

# Workload Federation Broad Trust

## Context

A cloud security review states that the organization has removed long-lived service account keys for CI/CD deployments. The review evidence includes federated workload identity configuration for GitHub Actions and shared deployment identities.

## Evidence

### AWS OIDC Role Trust

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    }
  }
}
```

The AWS deployment role grants `AdministratorAccess` and does not constrain the `sub` claim by repository, branch, or protected environment.

### Azure Federated Credential

```json
{
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:example-org/*",
  "audiences": ["api://AzureADTokenExchange"]
}
```

The corresponding service principal has Contributor at subscription scope.

### GCP Workload Identity Provider

```yaml
allowed_audiences: []
attribute_mapping:
  google.subject: assertion.sub
attribute_condition: ""
iam_member: principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/deployers/*
role: roles/editor
scope: project
```

## Expected Assessment

Flag this as `IAM-SVC-10` and `IAM-SVC-11`: keyless access exists, but the trust policy does not pin issuer, audience, subject, and mapped attributes tightly enough, and the downstream role binding grants broad high-privilege access.
