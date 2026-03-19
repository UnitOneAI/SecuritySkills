# Windows Security Event ID Reference

Extracted from the log-analysis SKILL.md.

## Authentication Events

| Event ID | Description | Security Relevance | ATT&CK Mapping |
|----------|-------------|-------------------|-----------------|
| **4624** | Successful logon | Tracks who logged into what system and how (logon type) | T1078 |
| **4625** | Failed logon | Brute force attempts, password spraying, credential guessing | T1110 |
| **4648** | Logon using explicit credentials (runas) | Lateral movement and privilege escalation | T1078 |
| **4672** | Special privileges assigned to new logon | Privileged logon (admin, backup operator) | T1078 |

## Windows Logon Types

| LogonType | Name | Description | Security Context |
|-----------|------|-------------|------------------|
| 2 | Interactive | Physical console logon | Normal for workstations; unusual for servers |
| 3 | Network | Access to shared resource (SMB) | Expected for file servers; lateral movement on workstations |
| 4 | Batch | Scheduled task execution | Expected for automation; unexpected batch logons warrant investigation |
| 5 | Service | Service start under a service account | Expected for known services; new service logons suspicious |
| 7 | Unlock | Workstation unlock | Normal for workstations |
| 8 | NetworkCleartext | Logon with plaintext credentials | Security concern -- credentials exposed |
| 9 | NewCredentials | Caller cloned token (runas /netonly) | Lateral movement technique; always investigate |
| 10 | RemoteInteractive | RDP logon | Expected for jump servers; suspicious on workstations |
| 11 | CachedInteractive | Cached domain credentials | Normal when DC unreachable; suspicious if DC available |

## Process and Service Events

| Event ID | Description | Security Relevance | ATT&CK Mapping |
|----------|-------------|-------------------|-----------------|
| **4688** | New process created | Tracks every process execution including command line | T1059 |
| **4698** | Scheduled task created | Persistence and execution mechanism | T1053.005 |
| **7045** | Service installed (System log) | Persistence and privilege escalation | T1543.003 |

## Account Management Events

| Event ID | Description | Security Relevance | ATT&CK Mapping |
|----------|-------------|-------------------|-----------------|
| **4720** | User account created | Persistence via new account creation | T1136.001 |
| **4728** | Member added to global group | Privilege escalation via group membership | T1098 |
| **4732** | Member added to local group | Monitor additions to local Administrators | T1098 |
| **4756** | Member added to universal group | Monitor high-privilege universal groups | T1098 |

## Defense Evasion Events

| Event ID | Description | Security Relevance | ATT&CK Mapping |
|----------|-------------|-------------------|-----------------|
| **1102** | Audit log cleared | Almost always malicious on production systems | T1070.001 |
| **4657** | Registry value modified | Persistence, defense evasion, configuration changes | T1112 |
