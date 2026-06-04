# Vulnerable: Release Job Restores Broad Build Cache Prefix

This fixture should fail because a privileged release job can restore build-influencing content from a broad prefix that is not scoped to a trusted ref or lockfile.

```yaml
name: release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write
  id-token: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: |
            build/
            node_modules/
          key: build-${{ runner.os }}-${{ github.sha }}
          restore-keys: |
            build-${{ runner.os }}-
      - run: npm test -- --cache-hit-ok
      - run: ./scripts/publish-release.sh
```

Review evidence to collect:

```text
cache writer scope: unknown from this workflow; broad prefix can match earlier branch caches
restore consumer: tag release job with write token and OIDC
cached path: build output and executable dependency tree
restore exactness: partial restore allowed by build-${{ runner.os }}-
revalidation: no clean rebuild, exact cache-hit requirement, checksum, or provenance check before release
```

Expected result: fail. Treat this as high severity when a secret-bearing, release, or OIDC-capable job can consume executable or build output restored from a broad untrusted prefix without revalidation.
