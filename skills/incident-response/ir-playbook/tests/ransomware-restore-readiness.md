# Ransomware Restore Readiness Fixtures

## Vulnerable / Not Evaluable

This scenario should not be marked ransomware-recovery ready.

```text
incident: ransomware encryption detected on production file shares
backup_status: nightly jobs succeeded
last_restore_drill: none recorded
restore_target: production network only
key_escrow: backup encryption keys stored in the same production IAM tenant
immutability: retention lock enabled, but backup admins can shorten retention
database_validation: storage snapshot restore only; no application transaction test
reconnect_plan: reconnect all restored systems after antivirus scan
```

Expected assessment:

- Restore readiness: Not Evaluable
- Key escrow: Missing
- Immutability: Partial
- Reconnect criteria: Blocked until clean-room restore, key recovery, and application validation are proven

## Benign / Recovery-Ready Evidence

This scenario can be marked ready if no other incident facts contradict it.

```text
incident: ransomware encryption detected on one application tier
backup_status: immutable object storage with separate backup-admin identity
last_restore_drill: 2026-05-15, clean-room restore of payments-api and database
rto_rpo: RTO 4h achieved, RPO 15m achieved
key_escrow: dual-control escrow tested during last drill
immutability: retention lock cannot be shortened without separate approval
database_validation: point-in-time restore plus application transaction checks passed
reconnect_plan: phased reconnection with IOC monitoring and rollback window
owner_signoff: application owner and backup platform owner approved
```

Expected assessment:

- Restore readiness: Complete
- Key escrow: Complete
- Immutability: Complete
- Reconnect criteria: Approved after credential rotation, clean-room scan, and phased monitoring
