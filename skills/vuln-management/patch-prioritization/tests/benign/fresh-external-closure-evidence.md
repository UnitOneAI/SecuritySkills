# Benign: fresh external exposure closure supports lower urgency

```yaml
finding_id: benign-2026-001
cve: CVE-2026-20001
asset: blue-api-preview
original_sla: P1
proposed_sla: P2
reason: "Temporary public preview listener removed"
exposure_source: external-asm-and-cloud-lb-inventory
exposure_observed_value: closed
exposure_observed_at: 2026-06-14T05:30:00Z
current_date: 2026-06-14T06:00:00Z
network_path_proof: "No public DNS, no public load balancer listener, external scan closed"
kev_status: false
epss: 0.08
```

Expected review result: allow the lower urgency if SSVC and change evidence also support it because exposure evidence is fresh, source-named, and within the P1/P2 24-hour TTL.
