# Vulnerable Fixture: Mutable Release Action

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
      contents: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: some-org/publish-action@main
      - run: npm publish
```

Expected findings:

- `SCA-ATTACK-08` High: secret-bearing release workflow uses a mutable third-party action reference.
- `SCA-ATTACK-10` Medium: release path has no visible artifact provenance or signature validation.

Benign contrast: pin third-party actions to full commit SHAs and generate signed SLSA/in-toto provenance for release artifacts.
