# Vulnerable calibration: sparse low-and-slow aggregate pattern

```text
Metric: failed logons against privileged accounts
PerEntityCounts:
  admin-a: 1
  admin-b: 1
  admin-c: 1
  admin-d: 1
  admin-e: 1
SourceIPs:
  - 198.51.100.10
  - 198.51.100.11
  - 198.51.100.12
  - 198.51.100.13
TimeWindow: 25 minutes
MaintenanceWindow: none
```

Expected assessment: escalate the aggregate pattern even if each single entity count is small. Peer-group and population-level analysis should catch low-and-slow password spraying that per-user mean/stddev thresholds may miss.
