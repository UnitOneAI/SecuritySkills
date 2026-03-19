# ATT&CK Technique-to-Containment Mapping

Extracted from the containment SKILL.md.

## Initial Access Containment

| ATT&CK Technique | Containment Action |
|---|---|
| T1566 -- Phishing | Block sender domain/IP at email gateway; quarantine delivered messages; reset credentials |
| T1190 -- Exploit Public-Facing Application | Deploy WAF rule; take vulnerable app offline or restrict to VPN-only; apply emergency patch |
| T1078 -- Valid Accounts | Disable compromised accounts; force MFA re-enrollment; revoke sessions; audit activity |
| T1195 -- Supply Chain Compromise | Isolate systems running compromised software; block network to compromised vendor; roll back |
| T1133 -- External Remote Services | Disable compromised VPN/RDP accounts; restrict to allowlisted IPs; require MFA |

## Lateral Movement Containment

| ATT&CK Technique | Containment Action |
|---|---|
| T1021 -- Remote Services (RDP, SSH, SMB) | Block lateral protocols between workstations; restrict to jump servers; disable unused services |
| T1550 -- Use Alternate Auth Material | Reset credentials; clear Kerberos ticket caches; enable Credential Guard; restrict NTLM |
| T1210 -- Exploitation of Remote Services | Isolate vulnerable systems; apply emergency patches; restrict network access |
| T1570 -- Lateral Tool Transfer | Block SMB/admin shares between endpoints; restrict PowerShell remoting; deploy app whitelisting |

## Command and Control Containment

| ATT&CK Technique | Containment Action |
|---|---|
| T1071 -- Application Layer Protocol | Block C2 IPs/domains at firewall and proxy; implement SSL inspection; deploy DNS sinkhole |
| T1572 -- Protocol Tunneling | Inspect and restrict non-standard protocol usage; block unauthorized tunnel endpoints; deploy DPI |
| T1573 -- Encrypted Channel | Block C2 IPs at network layer; deploy JA3/JA3S fingerprinting |
| T1568 -- Dynamic Resolution (DGA) | Deploy DNS analytics for DGA; restrict DNS to internal resolvers; implement RPZ |

## Persistence Containment

| ATT&CK Technique | Containment Action |
|---|---|
| T1053 -- Scheduled Task/Job | Audit and remove unauthorized tasks; restrict creation permissions; monitor task scheduler |
| T1547 -- Boot or Logon Autostart Execution | Audit startup entries; restrict write access to autostart locations |
| T1505.003 -- Web Shell | Scan web directories for unauthorized files; deploy FIM; restrict write permissions |
| T1136 -- Create Account | Audit and disable unauthorized accounts; restrict creation permissions; alert on new accounts |
