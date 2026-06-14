# Vulnerable: old criticality tag retained after claimed decommission

```yaml
finding_id: vuln-2026-002
cve: CVE-2026-10002
asset: billing-legacy-worker
asset_criticality: Critical
criticality_source: cmdb-import
criticality_last_verified: 2025-12-01T00:00:00Z
owner_note: "This service is retired, close the patch item."
decommission_ticket: null
traffic_absence_evidence: null
scanner_absence_evidence: null
```

Expected review result: mark context not evaluable. Do not close or downgrade based on a claimed retirement until decommission ticket, traffic/log absence, DNS removal or owner confirmation, and scanner absence are fresh enough to satisfy the 7-day decommission/migration TTL.
