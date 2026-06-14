# Vulnerable: stale exposure evidence used to downgrade SLA

```yaml
finding_id: vuln-2026-001
cve: CVE-2026-10001
asset: checkout-api-prod
original_sla: P1
proposed_sla: P3
reason: "No longer internet exposed"
exposure_source: external-asm
exposure_observed_value: closed
exposure_observed_at: 2026-05-20T10:00:00Z
current_date: 2026-06-14T00:00:00Z
kev_status: false
epss: 0.42
```

Expected review result: block the downgrade because the internet-exposure evidence is older than the 24-hour TTL for P1/P2 decisions. Require a fresh external scan or network-path proof before relaxing the SLA.
