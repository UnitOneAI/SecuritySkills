# Benign: Pull Request Cache Scoped to Lockfile and Merge Ref

This fixture should be treated as a low-risk dependency cache pattern because the restored content is scoped and revalidated before use.

```yaml
name: test

on:
  pull_request:

permissions:
  contents: read

jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: npm-${{ runner.os }}-${{ github.event.pull_request.head.sha }}-${{ hashFiles('package-lock.json') }}
          restore-keys: |
            npm-${{ runner.os }}-${{ github.event.pull_request.head.sha }}-
      - run: npm ci --ignore-scripts
      - run: npm test
```

Review evidence:

```text
cache writer: pull_request job with read-only token
restore consumer: same unprivileged test job
cached path: package manager download cache only, not node_modules or build output
key boundary: PR head SHA plus package-lock hash
revalidation: npm ci recreates dependencies from the lockfile before tests
privileged follow-on consumers: none
```

Expected result: pass or informational only. The cache does not cross into a privileged job, the key is bounded by ref and lockfile evidence, and restored content is revalidated before execution.
