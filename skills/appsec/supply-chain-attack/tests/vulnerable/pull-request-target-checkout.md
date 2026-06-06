# Vulnerable Fixture: Unsafe `pull_request_target`

```yaml
name: pr-check
on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install
      - run: npm test
```

Expected findings:

- `SCA-ATTACK-09` Critical: untrusted fork code is checked out and executed in a `pull_request_target` workflow with write permissions.
- `SCA-ATTACK-06` High if install scripts are not disabled or reviewed before `npm install`.

Benign contrast: use `pull_request` with read-only permissions for untrusted code, or keep `pull_request_target` limited to metadata-only operations.
