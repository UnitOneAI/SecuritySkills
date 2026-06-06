# Benign Fixture: Read-Only Fork PR Workflow

```yaml
name: pr-check
on:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: npm ci --ignore-scripts
      - run: npm test
```

Expected decision:

- Do not flag `SCA-ATTACK-09`; untrusted PR code runs under the normal `pull_request` event with read-only permissions.
- Review whether `--ignore-scripts` is compatible with the project before treating lifecycle-script risk as resolved.
