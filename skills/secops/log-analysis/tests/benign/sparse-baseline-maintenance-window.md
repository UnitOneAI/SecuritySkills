# Benign calibration: sparse baseline with approved maintenance

```text
Metric: daily NewCredentials events for admin workstation aw-17
History: 0,0,0,1,0,0,0,0,0,1,0,0,0,0,0,2,0,0,0,0,0,1,0,0,0,0,0,0,0,0
CurrentCount: 1
Context: quarterly maintenance window
Owner: infrastructure operations
Ticket: CHG-2026-0605
```

Expected assessment: do not alert only because the mean is near zero. Use owner/ticket evidence, event context, and peer/admin-workstation baseline before scoring severity.
