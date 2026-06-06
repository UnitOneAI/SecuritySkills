# Benign Fixture: Pinned Release Workflow

```yaml
name: release
on:
  push:
    tags:
      - "v*"

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: some-org/publish-action@0123456789abcdef0123456789abcdef01234567
      - run: slsa-generate-provenance --artifact dist/example.tgz
```

Expected decision:

- Do not flag mutable action usage; third-party actions are pinned to full-length commit SHAs.
- Review provenance generation evidence before deciding whether `SCA-ATTACK-10` is satisfied.
