# Supply Chain Attack Review Fixtures

These fixtures are safe review examples. They must be inspected as static text
only; do not install packages, execute scripts, or fetch remote artifacts.

## Fixture 1: Dependency Confusion Risk

```ini
# .npmrc
registry=https://registry.npmjs.org/
```

```json
{
  "dependencies": {
    "company-auth-lib": "^3.2.0"
  }
}
```

Expected decision: `Vulnerable`.

Why: the internal-looking unscoped package has no `@company:registry=` binding
and can resolve from the public npm registry.

Expected finding: `SCA-DC-01`.

## Fixture 2: Dependency Confusion Controlled

```ini
# .npmrc
@company:registry=https://npm.internal.example/
registry=https://registry.npmjs.org/
always-auth=true
```

```json
{
  "dependencies": {
    "@company/auth-lib": "3.2.4"
  }
}
```

Expected decision: `Secure` if the lockfile also resolves
`@company/auth-lib` to the private registry and includes integrity data.

Why: the private namespace is bound to the private registry.

## Fixture 3: PyPI Extra Index Confusion

```txt
--extra-index-url https://pypi.internal.example/simple/
company-auth-lib==1.2.0
```

Expected decision: `Vulnerable` unless an internal proxy or source priority rule
proves public registry fallback cannot win.

Expected finding: `SCA-DC-01`.

## Fixture 4: Typosquat With Supporting Signals

```json
{
  "dependencies": {
    "reqeusts": "1.0.1"
  }
}
```

Supporting evidence:

- Package name is one edit away from `requests`.
- Package was created recently.
- Publisher is unrelated to the trusted project.
- Package includes an install script.

Expected decision: `Vulnerable`.

Expected finding: `SCA-TYPO-02`.

## Fixture 5: Legitimate Similar Name

```json
{
  "dependencies": {
    "python-dateutil": "2.9.0"
  }
}
```

Expected decision: `Secure` when publisher identity and project documentation
show this is the canonical package.

Why: name similarity alone is not enough for a finding.

## Fixture 6: Malicious Maintainer Takeover Indicator

```json
{
  "scripts": {
    "postinstall": "node scripts/download-prebuilt.js"
  },
  "dependencies": {
    "left-pad-compatible": "99.0.0"
  }
}
```

Review evidence:

- New maintainer for an established package.
- Sudden major version jump.
- Install script downloads a binary without a pinned digest.

Expected decision: `Partial` or `Vulnerable` depending on registry metadata.

Expected finding: `SCA-MT-03`.

## Fixture 7: Lockfile Drift

```gitignore
package-lock.json
```

```yaml
# .github/workflows/release.yml
jobs:
  release:
    steps:
      - uses: actions/checkout@v4
      - run: npm install
      - run: npm publish
```

Expected decision: `Vulnerable`.

Why: the lockfile is ignored and release uses mutable dependency resolution.

Expected findings: `SCA-LF-04`, `SCA-PIPE-05`.

## Fixture 8: Frozen Install Controlled

```yaml
# .github/workflows/release.yml
permissions:
  contents: read
  id-token: write
jobs:
  release:
    steps:
      - uses: actions/checkout@3df4ab11eba7bda6032a0b82a6bb43b11571feac
      - run: npm ci
      - uses: actions/attest-build-provenance@1c608171e939e0b5d43c74d3e5b96572d0c9964a
```

Expected decision: `Secure` for lockfile and action pinning when the referenced
SHAs are reviewed and the release artifact digest is attested.

## Fixture 9: Pull Request Target Poisoning

```yaml
on:
  pull_request_target:
jobs:
  test:
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install
      - run: npm test
```

Expected decision: `Vulnerable`.

Why: privileged `pull_request_target` executes untrusted pull-request code with
write permissions.

Expected finding: `SCA-PIPE-05`.

## Fixture 10: Not Evaluable Registry Metadata

```toml
[tool.poetry.dependencies]
company-auth-lib = "1.2.0"
```

Expected decision: `Not Evaluable` if the reviewer cannot access source priority
rules, lockfile metadata, registry configuration, or package ownership data.

Why: the repository alone does not prove whether the package can resolve from a
public registry.
