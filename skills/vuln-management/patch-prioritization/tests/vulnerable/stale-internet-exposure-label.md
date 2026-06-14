# Vulnerable: stale internet-exposure label drives SLA escalation

This sample should be reported because the patch priority is escalated using a historical exposure label even though current scan evidence shows the exposure was closed.

```text
CVE: CVE-2026-12345
asset: blue-web-legacy
cmdb.exposure: internet-facing
cmdb.exposure_observed_at: 2026-05-01T00:00:00Z
current_external_scan.observed_at: 2026-06-14T08:00:00Z
current_external_scan.state: closed
change_ticket: CHG-1821 closed public listener after blue/green cutover
assigned_sla: P1 because cmdb.exposure=internet-facing
```

Expected finding:

- Context status: Contradictory or stale.
- Evidence gap: exposure TTL exceeded and current scan conflicts with historical label.
- Remediation: refresh exposure evidence and recalculate SLA from current external reachability.
