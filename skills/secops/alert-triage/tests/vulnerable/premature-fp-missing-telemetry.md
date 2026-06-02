# Vulnerable: Premature FP With Missing Telemetry

```text
Alert: Suspicious PowerShell child process
Host: ENG-LAPTOP-014
Observed event: powershell.exe -EncodedCommand <redacted>
EDR heartbeat: last event 11 minutes after the alert, then offline
Proxy logs: ingestion delay currently 45 minutes
DNS logs: unavailable for this subnet
Correlation result: no related alerts in +/- 30 minutes
Incorrect disposition: False Positive, low confidence
```

Expected handling:

- Evidence quality is `Insufficient`.
- Missing and delayed telemetry can materially change classification.
- Disposition should be `NE` until EDR, proxy, and DNS evidence is recovered or
  the case is escalated for manual evidence collection.

