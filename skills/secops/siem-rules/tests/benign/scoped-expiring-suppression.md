# Benign: scoped suppression with owner, ticket, and expiry

This sample should not be reported as a permanent blind spot. The suppression is tied to one build host, one signed process, one ticket, and an expiry date. Events outside that scope still alert.

```kql
let suppression_ticket = "SEC-1428";
let suppression_owner = "detection-eng";
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "powershell.exe"
| where not(
    DeviceName == "build-01"
    and InitiatingProcessFileName == "signed-builder.exe"
    and ProcessCommandLine has "-File build.ps1"
    and Timestamp < datetime(2026-07-01)
)
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, suppression_ticket, suppression_owner
```

Expected result:

- No finding for broad or permanent suppression.
- Reviewer should still confirm an expired-suppression monitor exists for dates after `2026-07-01`.
