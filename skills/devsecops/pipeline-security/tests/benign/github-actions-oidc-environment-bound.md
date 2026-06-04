# Benign: OIDC Role Bound to Protected Production Environment

This fixture should be treated as controlled OIDC federation, not as a credential-hygiene finding.

```yaml
name: deploy

on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/payments-prod-deploy
          aws-region: us-east-1
```

Matching trust-policy evidence:

```json
{
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:repository_owner": "acme",
      "token.actions.githubusercontent.com:sub": "repo:acme/payments-api:environment:production",
      "token.actions.githubusercontent.com:job_workflow_ref": "acme/payments-api/.github/workflows/deploy.yml@refs/heads/main"
    }
  }
}
```

Expected result: pass or informational only. The workflow uses a protected environment and the role trust policy binds the token to the expected audience, owner, repository, environment, and workflow source.
