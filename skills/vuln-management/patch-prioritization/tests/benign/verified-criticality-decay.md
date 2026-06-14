# Benign: verified criticality decay after service migration

```yaml
finding_id: benign-2026-002
cve: CVE-2026-20002
asset: legacy-reporting-ui
asset_criticality: Low
criticality_source: service-catalog
criticality_last_verified: 2026-06-13T12:00:00Z
decommission_ticket: CHG-48291
traffic_absence_evidence: "30 days zero production traffic in telemetry"
dns_removed_at: 2026-06-12T18:00:00Z
scanner_absence_evidence: "No reachable endpoint in 2026-06-14 external scan"
owner_confirmation: "Data migration complete; read-only archive retained internally"
```

Expected review result: do not escalate solely based on an old Critical tag. The downgrade is supportable because decommission/migration evidence is current and source-backed.
