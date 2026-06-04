# Vulnerable: Service Provider Uses Merchant-Only Cadence Evidence

This fixture should fail because service-provider segmentation cadence is not separated from merchant annual testing evidence.

```text
pci_dss_version: v4.0.1
pci_source_review_date: 2026-06-05
requirement_mapping_checked: true
entity_type: service_provider
segmentation_test_frequency_source: 11.4.5 only
service_provider_11_4_6_cadence: missing
last_test_date: 2025-04-01
significant_change_retest: not recorded
connected_to_systems: missing
result: pass
```

Expected result: fail or Not Evaluable. Service-provider evidence must explicitly address the 11.4.6 cadence, retained evidence, connected-to systems, and significant-change retesting instead of relying only on generic merchant cadence.
