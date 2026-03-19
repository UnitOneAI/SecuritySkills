# NTIA Minimum Elements Mapping

Extracted from the sbom-analysis SKILL.md.

| # | NTIA Minimum Element | CycloneDX 1.5 Field | SPDX 2.3 Field | Required |
|---|---|---|---|---|
| 1 | **Supplier Name** | `component.supplier.name` or `component.publisher` | `Package: PackageSupplier` | Yes |
| 2 | **Component Name** | `component.name` | `Package: PackageName` | Yes |
| 3 | **Version of the Component** | `component.version` | `Package: PackageVersion` | Yes |
| 4 | **Unique Identifier** | `component.bom-ref`, `component.cpe`, `component.purl` | `Package: SPDXID`, `Package: ExternalRef (purl)` | Yes |
| 5 | **Dependency Relationship** | `dependencies[]` array with `dependsOn` | `Relationship: DEPENDS_ON`, `DEPENDENCY_OF` | Yes |
| 6 | **Author of SBOM Data** | `metadata.authors[]` or `metadata.manufacture` | `CreationInfo: Creator` | Yes |
| 7 | **Timestamp** | `metadata.timestamp` | `CreationInfo: Created` | Yes |

## Completeness Thresholds

| Rating | Criteria |
|---|---|
| **Complete** | All 7 NTIA elements present for 100% of components |
| **Substantially Complete** | All 7 elements present for >= 90% of components; gaps documented |
| **Partial** | 5-6 elements present for majority of components; significant gaps in supplier or dependency data |
| **Incomplete** | Fewer than 5 elements consistently present; SBOM not suitable for compliance or risk assessment |

## References

- NTIA Minimum Elements: https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report_0.pdf
