---
name: pci-cde-stale-source-gap
expected: vulnerable
---

# PCI CDE Segmentation Evidence - Stale Source Gap

This fixture should not be marked PCI DSS compliant. It has a successful sample network test, but the source mapping is stale and the service-provider cadence is missing.

## Source Gate

```yaml
pci_dss_version: v4.0
pci_dss_source_document: docs-prv.pcisecuritystandards.org/PCI-DSS-v4_0.pdf
pci_dss_source_review_date: missing
pci_requirement_mapping_checked: false
segmentation_test_frequency_source: 11.4.5
entity_type: service_provider
```

## CDE Boundary

```yaml
cde_boundary: "PCI subnet"
connected_to_systems: missing
segmentation_controls:
  - "Firewall blocks users from CDE"
```

## Test Evidence

| Requirement | Test Date | Origin | Destination | Port | Expected | Observed |
|---|---|---|---|---|---|---|
| 11.4.5 | 2025-04-01 | 10.20.15.12 | 10.40.10.34 | tcp/5432 | blocked | blocked |

## Expected Finding

The review should mark PCI-specific status as `Not Evaluable for PCI DSS` until the source version, current requirement mapping, CDE boundary, connected-to systems, and service-provider 11.4.6 cadence are recorded. The stale v4.0 PDF reference and missing review date should not be accepted as current v4.0.1 evidence.

