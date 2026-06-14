# Vulnerable: SIEM conversion lacks regression fixtures

This sample should be reported because the converted rule changes normalized field names but does not include positive or benign fixture events proving equivalent behavior.

```kql
// Original rule used Account and Computer from Windows SecurityEvent.
SecurityEvent
| where EventID == 4688
| where Process has "rundll32.exe"
| project TimeGenerated, Account, Computer, Process

// Converted rule uses MDE fields, but no fixture proves this still alerts.
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| project Timestamp, InitiatingProcessAccountName, DeviceName, ProcessCommandLine
```

Expected finding:

- Severity: P3 unless the rule covers an active high-priority threat.
- Evidence: field mapping changed and no should-alert or should-not-alert event is supplied.
- Remediation: add fixtures for the old and new field names and verify the converted rule alerts on the same malicious event.
