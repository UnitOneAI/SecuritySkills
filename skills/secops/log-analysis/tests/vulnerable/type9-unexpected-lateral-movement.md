# Vulnerable calibration: unexpected NewCredentials lateral movement

```text
EventID: 4624
LogonType: 9
LogonProcessName: seclogo
AuthenticationPackageName: Negotiate
SubjectUserName: helpdesk-temp
TargetUserName: helpdesk-temp
NetworkAccountName: domain-admin
ProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -EncodedCommand <redacted>
SourceHostRole: ordinary workstation
RelatedEvent: 4648 missing
FollowOnEvents:
  - SMB connection to dc-01
  - WinRM connection to app-07
  - EventID 4672 special privileges assigned
```

Expected assessment: high priority investigation because Type 9 is paired with unexpected privileged network credentials, suspicious process evidence, non-admin source host role, and follow-on lateral-movement protocols.
