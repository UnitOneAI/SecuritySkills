---
name: pci-cde-current-source-evidence
expected: benign
---

# PCI CDE Segmentation Evidence - Current Source

This fixture should be treated as acceptable PCI segmentation evidence because it records both the source mapping and the tested boundary evidence.

## Source Gate

```yaml
pci_dss_version: v4.0.1
pci_dss_source_document: PCI SSC Document Library - PCI DSS v4.0.1
pci_dss_source_review_date: 2026-06-04
pci_requirement_mapping_checked: true
segmentation_test_frequency_source: 11.4.5 and 11.4.6
entity_type: service_provider
```

## CDE Boundary

```yaml
cde_boundary:
  cde_subnets:
    - 10.40.10.0/24
  connected_to_systems:
    - bastion-prod-01
    - siem-forwarder-02
  out_of_scope_sources:
    - 10.20.0.0/16
    - 10.30.0.0/16
segmentation_controls:
  - firewall_policy: fw-cde-east-west-v17
  - route_table: rt-cde-deny-local-bypass
  - security_group: sg-cde-db-ingress
```

## Test Evidence

| Requirement | Test Date | Origin | Destination | Port | Expected | Observed |
|---|---|---|---|---|---|---|
| 11.4.5 | 2026-05-15 | 10.20.15.12 | 10.40.10.34 | tcp/5432 | blocked | blocked |
| 11.4.5 | 2026-05-15 | 10.30.2.9 | 10.40.10.34 | tcp/443 | blocked | blocked |
| 11.4.6 | 2026-05-15 | 10.20.15.12 | 10.40.10.34 | tcp/22 | blocked | blocked |

## Change Retest

Change `CHG-2026-0412` modified the CDE firewall policy on 2026-04-12. Retest `SEG-2026-0413` covered the changed inbound and outbound rules before the environment relied on the updated segmentation.

