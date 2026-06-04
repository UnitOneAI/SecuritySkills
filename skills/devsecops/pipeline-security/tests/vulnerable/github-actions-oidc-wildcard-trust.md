# Vulnerable: OIDC Trust Policy Accepts Organization Wildcards

This fixture should trigger a CICD-SEC-2/CICD-SEC-6 finding because the workflow can request cloud credentials while the role trust policy accepts broad repository subjects.

```yaml
name: deploy

on:
  pull_request:
  push:
    branches: ["*"]

permissions:
  contents: read
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
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
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:acme/*"
    }
  }
}
```

Expected result: fail. The policy does not bind audience, repository owner, exact repository, branch, environment, or caller workflow, so unrelated repositories or unsafe triggers can attempt the same role exchange.
