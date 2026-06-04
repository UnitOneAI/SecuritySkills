# Vulnerable: PCI Finding Uses Stale Source Metadata

This fixture should fail because a segmentation result is treated as PCI-complete even though the PCI source gate is missing or stale.

```text
pci_dss_version: v4.0
pci_source_document: docs-prv.pcisecuritystandards.org/PCI-DSS-v4_0.pdf
pci_source_review_date: missing
requirement_mapping_checked: false
entity_type: merchant
cde_boundary: PCI subnet
segmentation_test:
  date: 2025-04-01
  origin: jump-host
  destination: database-subnet
  observed: blocked
claim: CDE segmentation compliant
```

Expected result: fail or Not Evaluable for PCI DSS. A successful network test does not prove current PCI DSS mapping when the source version, official document, review date, and requirement mapping are stale or missing.
