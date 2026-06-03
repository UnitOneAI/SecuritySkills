# Dependency Scanning Review Skill

## Overview

This skill guides security engineers in reviewing dependency trees and lockfiles for supply-chain risks. It covers:

- Lockfile integrity and registry signature evidence
- Identifying missing integrity hashes, unexpected tarball hosts, and unsigned packages
- Detecting git dependencies without immutable commits
- Spotting registry drift and lockfile/manifest disagreements
- Distinguishing normal lockfile metadata from genuine tampering indicators

## Review Steps

### 1. Collect Lockfile and Manifest Evidence

Obtain the following files from the repository:

- `package-lock.json` (npm)
- `yarn.lock` (Yarn)
- `pnpm-lock.yaml` (pnpm)
- `Gemfile.lock` (Ruby)
- `go.sum` (Go)
- `Cargo.lock` (Rust)
- `composer.lock` (PHP)
- `poetry.lock` (Python)
- `requirements.txt` with hashes (Python)
- `nuget.lock.json` (.NET)
- `gradle.lockfile` (Gradle)
- `pom.xml` or `build.gradle` (Java)

### 2. Verify Lockfile Integrity

For each entry in the lockfile, check:

- **Integrity hash presence**: The `integrity` field (npm) or equivalent must exist. Missing integrity means the artifact cannot be verified.
- **Resolved URL origin**: The `resolved` URL should point to the official registry (e.g., `https://registry.npmjs.org/`). Unexpected third-party hosts (e.g., `https://example-cdn.invalid/`) are suspicious.
- **Signature evidence**: If the package ecosystem supports signatures (e.g., npm packages with `signatures` field), verify that signatures are present and valid.

**Example of a benign entry (normal lockfile metadata):**

```json
{
  "packages": {
    "node_modules/example": {
      "version": "1.2.3",
      "resolved": "https://registry.npmjs.org/example/-/example-1.2.3.tgz",
      "integrity": "sha512-<redacted-sri>",
      "license": "MIT"
    }
  }
}
```

**Example of a risky entry (missing integrity, unexpected host):**

```json
{
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://example-cdn.invalid/lodash-4.17.21.tgz"
    }
  }
}
```

**Why the risky entry is a concern:**
- The `integrity` field is absent, so the downloaded artifact cannot be verified against a known hash.
- The `resolved` URL points to a non-official host (`example-cdn.invalid`), which could serve a tampered package.

### 3. Check Git Dependencies for Immutable Commits

Git dependencies (e.g., in `package.json` or `Gemfile`) should reference immutable commits (full SHA) rather than mutable references like branches or tags.

**Risky example:**

```json
{
  "dependencies": {
    "my-lib": "git+https://github.com/user/repo.git#main"
  }
}
```

**Safe example:**

```json
{
  "dependencies": {
    "my-lib": "git+https://github.com/user/repo.git#a1b2c3d4e5f6..."
  }
}
```

### 4. Detect Registry Drift

Compare the lockfile's resolved URLs against the expected registry for each package. If a package from `registry.npmjs.org` suddenly resolves to a different registry (e.g., `https://other-registry.example.com/`), this may indicate a man-in-the-middle attack or compromised registry.

### 5. Verify Lockfile/Manifest Agreement

Ensure that the version and dependencies declared in the manifest (e.g., `package.json`) match the lockfile. Discrepancies can indicate tampering or incomplete dependency resolution.

**Checklist:**
- [ ] All lockfile entries have integrity hashes (where supported).
- [ ] Resolved URLs point to official registries.
- [ ] Git dependencies use immutable commit SHAs.
- [ ] No unexpected third-party hosts in resolved URLs.
- [ ] Signatures are present and valid for signed packages.
- [ ] Lockfile and manifest versions agree.
- [ ] No duplicate entries with different integrity hashes.

## Output Template

When reporting findings, use the following template to record evidence:

```markdown
## Dependency Scanning Review

### Lockfile Integrity Evidence

| Package | Version | Resolved URL | Integrity Present | Signature Present | Notes |
|---------|---------|--------------|-------------------|-------------------|-------|
| example | 1.2.3   | https://registry.npmjs.org/... | Yes | Yes | Normal |
| lodash  | 4.17.21 | https://example-cdn.invalid/... | No | No | Risky: missing integrity, unexpected host |

### Git Dependencies

| Dependency | Reference | Immutable Commit | Notes |
|------------|-----------|------------------|-------|
| my-lib     | main      | No               | Risky: uses branch instead of SHA |

### Registry Drift

- Package `foo` resolved from `https://registry.npmjs.org/` in lockfile but expected from `https://other-registry.example.com/` in manifest.

### Lockfile/Manifest Agreement

- Version for `bar` in lockfile (2.0.0) does not match manifest (1.0.0).

### Overall Risk Assessment

- [ ] Low: All entries have integrity, official hosts, and immutable commits.
- [ ] Medium: Some entries missing integrity or using mutable references.
- [ ] High: Missing integrity, unexpected hosts, or registry drift detected.
```

## References

- [npm package-lock.json documentation](https://docs.npmjs.com/cli/v9/configuring-npm/package-lock-json)
- [Subresource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
- [npm registry signatures](https://docs.npmjs.com/about-registry-signatures)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)