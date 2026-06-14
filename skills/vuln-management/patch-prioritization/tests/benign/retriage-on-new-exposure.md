# Benign: new internet exposure triggers SLA recalculation

This sample should be treated as good process. The finding was originally internal-only, but a fresh attack-surface scan detected a new public listener and the SLA was recalculated immediately.

```text
CVE: CVE-2026-56789
asset: reports-api
original_exposure: internal-only
original_sla: P3
attack_surface_scan.observed_at: 2026-06-14T09:15:00Z
attack_surface_scan.state: internet-facing
scan_confidence: high
retriage_trigger: exposure_changed
new_sla: P1
new_deadline: 2026-06-17T09:15:00Z
owner_notified: true
```

Expected result:

- Context status: Fresh.
- No finding for missed retiering.
- Reviewer should verify the new deadline aligns with the organization's SLA matrix.
