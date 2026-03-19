# SIEM Reference Tables

Extracted from the siem-rules SKILL.md.

## Common Sentinel Tables

| Table | Data Source | Key Fields |
|-------|------------|------------|
| SigninLogs | Azure AD interactive sign-ins | UserPrincipalName, ResultType, IPAddress, Location |
| AADNonInteractiveUserSignInLogs | Azure AD non-interactive sign-ins | Same as SigninLogs |
| SecurityEvent | Windows Security Event Log | EventID, Account, Computer, Activity |
| Syslog | Linux syslog | SyslogMessage, ProcessName, Facility, SeverityLevel |
| DeviceProcessEvents | Microsoft Defender for Endpoint | FileName, ProcessCommandLine, InitiatingProcessFileName |
| DeviceNetworkEvents | MDE network events | RemoteIP, RemotePort, RemoteUrl |
| AzureActivity | Azure control plane | OperationNameValue, Caller, ResourceGroup |
| CommonSecurityLog | CEF-format logs | DeviceAction, SourceIP, DestinationIP |
| ThreatIntelligenceIndicator | Threat intel feeds | NetworkIP, DomainName, Url, ExpirationDateTime |
| OfficeActivity | Microsoft 365 audit logs | Operation, UserId, ClientIP |

## Common Splunk Sourcetypes

| Sourcetype | Data Source | Key Fields |
|------------|------------|------------|
| WinEventLog:Security | Windows Security Event Log | EventCode, Account_Name, ComputerName |
| WinEventLog:System | Windows System Event Log | EventCode, SourceName |
| XmlWinEventLog:Microsoft-Windows-Sysmon/Operational | Sysmon | EventCode, Image, CommandLine, ParentImage |
| linux_secure | /var/log/secure | action, user, src_ip |
| linux_audit | auditd logs | type, uid, exe, key |
| pan:traffic | Palo Alto firewall | src_ip, dest_ip, dest_port, action |
| aws:cloudtrail | AWS CloudTrail | eventName, sourceIPAddress, userIdentity.arn |
| o365:management:activity | Microsoft 365 | Operation, UserId, ClientIP |

## KQL Operator Reference

| Operator | Purpose | Example |
|----------|---------|---------|
| where | Filter rows | where EventID == 4625 |
| summarize | Aggregate | summarize count() by UserName |
| extend | Add columns | extend Hour = hourofday(TimeGenerated) |
| project | Select columns | project TimeGenerated, User, IP |
| join | Combine tables | T1 \| join kind=inner (T2) on Key |
| let | Define variables | let threshold = 10; |
| ago() | Time relative | where TimeGenerated > ago(1h) |
| bin() | Time bucketing | bin(TimeGenerated, 5m) |
| dcount() | Distinct count | dcount(UserPrincipalName) |
| make_set() | Collect unique | make_set(IPAddress, 100) |

## SPL Command Reference

| Command | Purpose | Example |
|---------|---------|---------|
| search | Filter events | index=main EventCode=4625 |
| stats | Aggregate | stats count by src_ip |
| eval | Compute fields | eval hour=strftime(_time,"%H") |
| table | Display columns | table _time, user, src_ip |
| join | Combine searches | join type=inner user [search ...] |
| transaction | Group events | transaction user maxspan=30m |
| streamstats | Running calcs | streamstats window=1 last(field) as prev_field |
| iplocation | GeoIP lookup | iplocation ClientIP |
