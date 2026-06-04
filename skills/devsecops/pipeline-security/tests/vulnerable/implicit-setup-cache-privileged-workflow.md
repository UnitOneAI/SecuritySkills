# Vulnerable: Privileged Workflow Uses Implicit Setup Cache Without Trust Boundary Evidence

This fixture should fail closed because implicit package-manager caching is enabled in a privileged workflow without enough evidence that restored content is scoped and revalidated.

```yaml
name: deploy

on:
  workflow_run:
    workflows: ["test"]
    types: [completed]

permissions:
  contents: write
  packages: write
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
          cache: npm
      - run: npm install
      - run: npm run deploy
```

Review evidence to collect:

```text
implicit cache action: actions/setup-node package-manager cache
event scope: workflow_run with write token and OIDC
cache key evidence: not documented in the workflow review record
restore consumer: deployment job
integrity revalidation: npm install can update dependency state instead of enforcing the lockfile
privileged impact: package and deployment publishing paths
```

Expected result: fail or require escalation until evidence proves the cache is scoped to trusted refs and lockfiles, followed by a locked reinstall or equivalent integrity check before deployment.
