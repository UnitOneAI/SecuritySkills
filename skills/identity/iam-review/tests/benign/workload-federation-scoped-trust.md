---
name: workload-federation-scoped-trust
expected: benign
---

# Workload Federation Scoped Trust

## Context

A deployment pipeline uses workload identity federation for production releases. The review packet includes trust policy evidence, downstream role scope, and environment protection records.

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
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:example-org/payments-api:environment:production"
    }
  }
}
```

The AWS role can deploy only the `payments-api` service and has a permission boundary that excludes IAM administration.

### Azure Federated Credential

```json
{
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:example-org/payments-api:environment:production",
  "audiences": ["api://AzureADTokenExchange"]
}
```

The managed identity has a resource-group role assignment limited to the production app resource group, and the GitHub production environment requires approval.

### GCP Workload Identity Provider

```yaml
allowed_audiences:
  - https://github.com/example-org/payments-api
attribute_mapping:
  google.subject: assertion.sub
  attribute.repository: assertion.repository
  attribute.environment: assertion.environment
attribute_condition: attribute.repository == "example-org/payments-api" && attribute.environment == "production"
iam_member: principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/deployers/attribute.repository/example-org/payments-api
role: roles/clouddeploy.releaser
scope: service
```

## Expected Assessment

Treat this as scoped federation when the issuer, audience, subject or mapped attributes, downstream principal selector, and role scope all match the intended production workload.
