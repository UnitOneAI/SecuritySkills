# Benign: KEV deadline is bound to affected asset and source freshness

```yaml
cve: CVE-2026-10001
asset: vpn-gateway-prod-2
scanner_source: Tenable plugin 123456
affected_version_evidence: vendor advisory confirms 4.2.1 vulnerable
runtime_exposure: internet-facing VPN service listening on 443
kev_catalog_date: 2026-06-01
kev_due_date: 2026-06-21
known_ransomware_campaign_use: false
organization_scope: federal civilian executive branch
sla_start_source: first_seen 2026-06-02 from Tenable
exception_status: none
```

Expected assessment: KEV status can drive the required remediation deadline
when the entry is current, the organization is in BOD 22-01 scope, and the CVE
is bound to an actually affected runtime asset.
