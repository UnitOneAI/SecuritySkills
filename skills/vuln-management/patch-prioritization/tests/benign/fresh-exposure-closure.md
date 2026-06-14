# Benign: fresh exposure closure prevents false escalation

This sample should not be escalated solely from a stale historical exposure label. Current external scan evidence and a change ticket prove the temporary exposure closed within the configured TTL.

```text
CVE: CVE-2026-45678
asset: checkout-preview-blue
historical_exposure: internet-facing at 2026-06-01T10:00:00Z
closed_change: CHG-2044 at 2026-06-01T11:00:00Z
current_external_scan.observed_at: 2026-06-14T08:30:00Z
current_external_scan.state: closed
exposure_ttl: 24h
business_criticality.observed_at: 2026-06-10T09:00:00Z
recommended_action: maintain internal-only SLA unless new exposure appears
```

Expected result:

- Context status: Fresh.
- No finding for stale internet exposure escalation.
- Reviewer should still use CVSS, EPSS, SSVC, and KEV signals for the final SLA.
