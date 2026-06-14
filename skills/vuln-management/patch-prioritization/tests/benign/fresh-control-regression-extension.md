# Benign: fresh compensating control regression evidence supports short extension

```yaml
finding_id: benign-2026-003
cve: CVE-2026-20003
asset: customer-portal
sla_tier: P2
requested_extension_days: 7
compensating_control: waf-virtual-patch
control_rule_hash: sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000
control_tested_at: 2026-06-13T20:00:00Z
control_test_result: "Known PoC blocked; bypass regression passed"
coverage: "All affected public routes"
expiration: 2026-06-21
```

Expected review result: allow the short extension if business approval exists because P2 compensating-control evidence is within the 14-day TTL, scoped to all affected routes, and has regression proof.
