# Benign calibration: approved NewCredentials admin workflow

```text
EventID: 4624
LogonType: 9
LogonProcessName: seclogo
AuthenticationPackageName: Negotiate
SubjectUserName: analyst01
TargetUserName: analyst01
NetworkAccountName: domain-admin-readonly
ProcessName: C:\Windows\System32\runas.exe
CommandLine: runas /netonly /user:DOMAIN\domain-admin-readonly mmc.exe
SourceHostRole: admin workstation
OutboundTarget: management console subnet
RelatedEvent: 4648 explicit credentials present
ChangeTicket: CHG-2026-0605
```

Expected assessment: informational or benign true positive when the account, process, source host, target, and change ticket match approved administration. Do not mark as lateral movement solely because `LogonType` is `9`.
