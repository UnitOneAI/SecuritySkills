# Vulnerable: partial compensating control extends every affected asset

```yaml
cve: CVE-2025-22222
control: WAF virtual patch
control_tested_against_poc: true
protected_assets: 2
affected_assets: 9
scanner_rescan_after_control: missing
owner_attestation: present
sla_extension: +7 days
```

Expected assessment: flag as insufficient for broad SLA extension. The control
coverage must be mapped asset by asset, with validation or rescan evidence, and
the extension should apply only to assets inside the verified control boundary.
