# SBOM Analysis Quality Examples

Use these examples to calibrate `sbom-analysis` findings for graph completeness, VEX credibility, and SBOM freshness/trustworthiness.

## Vulnerable or Higher-Risk Cases

### 1. Flat-listed transitive dependencies

```yaml
sbom:
  format: CycloneDX 1.5
  components:
    direct: 12
    transitive: 30
  dependencies:
    graph_depth: 1
    transitive_parent_linkage: missing
assessment:
  ntia_fields_present: true
  graph_completeness_rating: Flat List
  risk: transitive CVE remediation cannot be traced to the consuming direct component
```

Expected handling: do not mark the SBOM as fully useful just because NTIA fields are present. Report `NTIA fields present, graph incomplete`.

### 2. Vendor-attested VEX without consumer verification

```yaml
vex:
  cve: CVE-2024-3094
  component: xz-utils
  status: Not Affected
  justification: vulnerable_code_not_in_execute_path
  verification_status: vendor_attested
  consumer_runtime_trace: missing
assessment:
  vex_credibility: Medium
  action: verify reachability before closing risk for critical systems
```

Expected handling: preserve the VEX status, but do not treat the justification as equally strong as consumer-verified evidence.

### 3. Stale SBOM for old release

```yaml
sbom_metadata:
  sbom_timestamp: "2025-06-01T10:00:00Z"
  sbom_software_version: "4.2.0"
  latest_release_version: "5.1.0"
  latest_release_date: "2026-03-15"
  cve_scan_date: "2025-06-01"
assessment:
  sbom_age_category: Stale
  trustworthiness: Low
```

Expected handling: downgrade usefulness even if component fields look complete.

### 4. Stale Under Investigation VEX

```yaml
vex:
  cve: CVE-2026-1000
  status: Under Investigation
  first_seen: "2026-01-01"
  vendor_sla_days: 30
  current_age_days: 75
assessment:
  stale_vex: true
  action: escalate; do not leave risk unresolved indefinitely
```

## Benign or Lower-Risk Cases

### 1. Complete dependency graph

```yaml
sbom:
  components:
    direct: 10
    transitive: 65
  dependency_graph:
    traceable_depth_max: 7
    orphan_component_relationships: 0
    transitive_parent_linkage: complete
assessment:
  graph_completeness_rating: Complete Graph
```

Expected handling: deep graph alone is not a completeness failure when parent-child paths are traceable.

### 2. Consumer-verified Not Affected VEX

```yaml
vex:
  cve: CVE-2024-21626
  component: runc
  status: Not Affected
  justification: vulnerable_code_not_present
  verification_status: consumer_verified
  verification_evidence: SBOM version match plus source review
assessment:
  vex_credibility: High
```

Expected handling: record high credibility because the consumer verified the justification, not only the vendor.

### 3. Fresh and signed SBOM

```yaml
sbom_metadata:
  timestamp: "2026-06-06T18:20:00Z"
  software_version: "5.1.0"
  release_version: "5.1.0"
  build_provenance: Sigstore signed attestation
  generation_tool: cyclonedx-cli 0.27.2
assessment:
  sbom_age_category: Fresh
  trustworthiness: High
```

Expected handling: freshness and provenance strengthen trust in the SBOM's current decision value.
