# MITRE ATT&CK TTP Mappings for STRIDE

## STRIDE to ATT&CK Technique Mapping

Map each identified threat to the corresponding MITRE ATT&CK Enterprise technique to enable standardized tracking and correlation with threat intelligence.

| STRIDE Category | Common ATT&CK Techniques |
|----------------|--------------------------|
| **Spoofing** | T1078 — Valid Accounts, T1134 — Access Token Manipulation, T1556 — Modify Authentication Process, T1528 — Steal Application Access Token, T1539 — Steal Web Session Cookie |
| **Tampering** | T1565 — Data Manipulation, T1195 — Supply Chain Compromise, T1059 — Command and Scripting Interpreter, T1190 — Exploit Public-Facing Application, T1210 — Exploitation of Remote Services |
| **Repudiation** | T1070 — Indicator Removal, T1070.001 — Clear Windows Event Logs, T1070.002 — Clear Linux or Mac System Logs, T1562 — Impair Defenses, T1562.001 — Disable or Modify Tools |
| **Information Disclosure** | T1530 — Data from Cloud Storage, T1552 — Unsecured Credentials, T1552.001 — Credentials In Files, T1040 — Network Sniffing, T1557 — Adversary-in-the-Middle, T1119 — Automated Collection |
| **Denial of Service** | T1498 — Network Denial of Service, T1499 — Endpoint Denial of Service, T1499.003 — Application Exhaustion Flood, T1499.004 — Application or System Exploitation, T1489 — Service Stop |
| **Elevation of Privilege** | T1068 — Exploitation for Privilege Escalation, T1548 — Abuse Elevation Control Mechanism, T1611 — Escape to Host, T1053 — Scheduled Task/Job, T1055 — Process Injection |

## MITRE ATT&CK Framework Reference

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally recognized knowledge base of adversary behavior based on real-world observations. It organizes techniques under tactical categories representing the adversary's objectives during an attack lifecycle:

- **Initial Access** (TA0001) — Techniques for gaining a foothold (T1190 Exploit Public-Facing Application, T1195 Supply Chain Compromise)
- **Persistence** (TA0003) — Techniques for maintaining access (T1053 Scheduled Task/Job, T1556 Modify Authentication Process)
- **Privilege Escalation** (TA0004) — Techniques for gaining higher-level permissions (T1068 Exploitation for Privilege Escalation, T1548 Abuse Elevation Control Mechanism)
- **Defense Evasion** (TA0005) — Techniques for avoiding detection (T1070 Indicator Removal, T1562 Impair Defenses)
- **Credential Access** (TA0006) — Techniques for stealing credentials (T1528 Steal Application Access Token, T1539 Steal Web Session Cookie, T1552 Unsecured Credentials)
- **Collection** (TA0009) — Techniques for gathering data (T1119 Automated Collection, T1530 Data from Cloud Storage)
- **Impact** (TA0040) — Techniques for disruption or destruction (T1489 Service Stop, T1498 Network Denial of Service, T1499 Endpoint Denial of Service, T1565 Data Manipulation)

Use the ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/) to visualize coverage of identified threats against the ATT&CK matrix.
