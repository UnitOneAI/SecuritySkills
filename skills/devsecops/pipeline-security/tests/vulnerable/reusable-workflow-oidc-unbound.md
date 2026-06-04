# Vulnerable: Reusable Workflow Can Mint OIDC Credentials Without Caller Binding

This fixture should trigger a CICD-SEC-5/CICD-SEC-6 finding because deployment credentials are exposed through a reusable workflow without a `job_workflow_ref` or equivalent caller restriction.

```yaml
name: reusable-deploy

on:
  workflow_call:
    inputs:
      environment:
        required: true
        type: string

permissions:
  contents: read
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: ${{ inputs.environment }}
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/prod-deploy
          aws-region: us-east-1
```

Cloud role trust policy:

```json
{
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:repository_owner": "acme"
    },
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:acme/payments-api:*"
    }
  }
}
```

Expected result: fail. The reusable workflow can be called for arbitrary environments and the trust policy does not require the expected protected environment subject or a specific caller workflow reference.
