# Dependency Scanning Supply Chain Risk Examples

These examples support the lockfile bisectability, provenance propagation, and contextual dependency-confusion checks added to the dependency-scanning skill.

## Vulnerable or Higher-Risk Examples

### 1. Private Python package with public fallback

```txt
--extra-index-url https://pypi.internal.example/simple/
company-auth-lib==1.2.0
```

Risk: pip can search both the public and private indexes. If `company-auth-lib` appears on the public registry with a higher version, dependency confusion is possible unless an internal proxy or hash-pinning control prevents fallback.

Expected classification: `dependency_confusion_context = HIGH_RISK_PUBLIC_FALLBACK`

### 2. Deep dependency tree with weak transitive provenance

```yaml
direct_dependency:
  name: "@scope/pkg-a"
  publisher: verified
  provenance: sigstore_attested
transitive_dependency:
  name: "pkg-c"
  depth: 6
  publisher: unknown
  maintainer_count: 1
  last_release_age_months: 39
  provenance: missing
```

Risk: the direct dependency has strong evidence, but trust degrades in a reachable transitive package.

Expected classification: `provenance_chain_propagation = DEGRADED_TRANSITIVE_TRUST`

### 3. Lockfile exists but cannot support incident bisecting

```yaml
lockfile:
  file: package-lock.json
  committed: false
  integrity_hash_coverage: complete
build:
  artifact_attestation: missing
  release_notes_reference_lockfile_digest: false
```

Risk: the lockfile can make a local install reproducible today, but it cannot prove which dependency graph shipped with an older artifact.

Expected classification: `bisectability_score = WEAK`

## Benign or Lower-Risk Examples

### 1. Scoped npm package with explicit private registry routing

```ini
@company:registry=https://npm.internal.example/
registry=https://registry.npmjs.org/
```

```json
{
  "packages": {
    "node_modules/@company/core": {
      "resolved": "https://npm.internal.example/@company/core/-/core-1.2.0.tgz",
      "integrity": "sha512-..."
    }
  }
}
```

Risk context: the internal scope resolves only through the private registry and the lockfile confirms the source host.

Expected classification: `dependency_confusion_context = PATTERN_PRESENT_MITIGATED_BY_ROUTING`

### 2. Deep but well-provenanced dependency tree

```yaml
dependency_tree:
  max_depth: 9
  all_versions_pinned: true
  all_lock_entries_have_integrity_hashes: true
  publisher_verification_coverage: high
  known_cve_count: 0
  stale_or_single_maintainer_high_risk_count: 0
```

Risk context: depth alone should not be treated as high risk when lockfile, provenance, and maintainer evidence are strong.

Expected classification: `supply_chain_risk_score = LOW_TO_MEDIUM_CONTEXTUAL`

### 3. Strong lockfile bisectability

```yaml
lockfile:
  file: pnpm-lock.yaml
  committed: true
  integrity_hash_coverage: complete
build:
  provenance: slsa_l2
  artifact_attestation_references_lockfile_digest: true
```

Risk context: the deployed artifact can be traced back to the exact dependency set used at build time.

Expected classification: `bisectability_score = STRONG`
