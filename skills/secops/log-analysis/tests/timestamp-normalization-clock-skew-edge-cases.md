# Timestamp Normalization and Clock-Skew Edge Cases

These fixtures calibrate the `log-analysis` timestamp trust gate. Each case should force the skill to record event time, ingestion/index time, parser-selected timestamp field, source timezone, clock synchronization / skew evidence, and a confidence decision before reconstructing a cross-source timeline.

## Vulnerable: Windows Local Time Ambiguity

```yaml
case: windows-local-time-ambiguous
source: Windows Security Event Log export
event:
  EventID: 4624
  TimeCreated: "2026-06-05 01:14:22"
  Computer: "workstation-17.corp.example"
  TargetUserName: "svc-build"
  LogonType: 10
collection:
  siem_time_field: "_time"
  siem_time_value: "2026-06-05T01:14:22Z"
  index_time: "2026-06-05T09:17:04Z"
  source_timezone: "unknown"
  clock_sync_evidence: "not provided"
expected_result:
  confidence: "Not Evaluable"
  reason: "Windows local TimeCreated was normalized as UTC without timezone or host clock evidence."
  required_handling: "Do not place this RDP logon in the definitive UTC timeline until source timezone and skew are established."
```

## Vulnerable: CloudTrail eventTime vs SIEM Ingestion Delay

```yaml
case: cloudtrail-eventtime-ingestion-delay
source: AWS CloudTrail through SIEM
event:
  eventName: "AttachUserPolicy"
  eventTime: "2026-06-05T12:03:19Z"
  userIdentity:
    type: "IAMUser"
    userName: "temporary-admin"
  sourceIPAddress: "198.51.100.44"
collection:
  siem_time_field: "_indextime"
  siem_time_value: "2026-06-05T12:48:52Z"
  parser_event_time_field: "missing"
  source_timezone: "UTC"
  clock_sync_evidence: "AWS managed service time"
expected_result:
  confidence: "Low"
  reason: "SIEM used index time rather than CloudTrail eventTime; CloudTrail delivery does not guarantee order."
  required_handling: "Use eventTime as activity time and document the 45 minute ingestion delay before correlating with endpoint or identity events."
```

## Vulnerable: Sysmon Host Clock Skew

```yaml
case: sysmon-host-clock-skew
source: Sysmon Event ID 1
event:
  EventID: 1
  UtcTime: "2026-06-05 18:22:10.112"
  Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  CommandLine: "powershell -enc <redacted>"
  Computer: "finance-laptop-04"
collection:
  collector_receive_time: "2026-06-05T18:09:51Z"
  siem_time_field: "UtcTime"
  source_timezone: "UTC"
  clock_sync_evidence: "EDR reports host clock +12m19s ahead of collector"
expected_result:
  confidence: "Medium"
  reason: "Clock skew is documented and bounded, but it can alter ordering inside a narrow attack chain."
  required_handling: "Apply skew correction or show a bounded time range; do not claim second-level ordering against firewall or proxy logs."
```

## Vulnerable: Linux auth.log Missing Year and Timezone

```yaml
case: linux-auth-missing-year-timezone
source: /var/log/auth.log
event:
  raw: "Jun 05 23:58:03 bastion-02 sshd[2201]: Accepted publickey for deploy from 203.0.113.77 port 55112 ssh2"
collection:
  file_mtime: "2026-06-06T00:03:14Z"
  collector_timezone: "America/Los_Angeles"
  host_timezone: "unknown"
  siem_time_field: "@timestamp"
  siem_time_value: "2026-06-06T06:58:03Z"
  clock_sync_evidence: "not provided"
expected_result:
  confidence: "Low"
  reason: "Syslog line lacks year/timezone and host timezone was inferred from collector context."
  required_handling: "Include the SSH event as lower-confidence evidence unless host timezone and collection year are proven."
```

## Vulnerable: Parser Mapping Mistake

```yaml
case: parser-mapped-ingestion-as-event-time
source: SaaS audit log
event:
  activity: "mailbox_forwarding_rule_created"
  activity_time: "2026-06-05T14:05:44Z"
  received_at: "2026-06-05T16:42:03Z"
  actor: "finance.user@example.com"
collection:
  parser_time_field: "received_at"
  canonical_timestamp: "2026-06-05T16:42:03Z"
  index_time: "2026-06-05T16:42:05Z"
  source_timezone: "UTC"
  clock_sync_evidence: "SaaS provider signed audit export"
expected_result:
  confidence: "Low"
  reason: "Parser selected receipt time as canonical event time, moving the activity more than two hours later."
  required_handling: "Correct the parser field or cite both activity_time and received_at before correlating with mailbox sign-in events."
```

## Benign: Complete Normalized Multi-Source Timeline

```yaml
case: complete-normalized-multi-source-timeline
sources:
  windows_security:
    event_time: "2026-06-05T15:01:04Z"
    ingestion_time: "2026-06-05T15:01:11Z"
    parser_time_field: "TimeCreated converted from UTC"
    source_timezone: "UTC"
    clock_sync_evidence: "w32time synchronized to dc-01; observed skew +1.2s"
  cloudtrail:
    event_time: "2026-06-05T15:03:48Z"
    ingestion_time: "2026-06-05T15:07:29Z"
    parser_time_field: "eventTime"
    source_timezone: "UTC"
    clock_sync_evidence: "AWS managed service time; delivery delay recorded separately"
  linux_auth:
    event_time: "2026-06-05T15:06:32Z"
    ingestion_time: "2026-06-05T15:06:38Z"
    parser_time_field: "auth.log timestamp plus host timezone metadata"
    source_timezone: "UTC"
    clock_sync_evidence: "chronyc tracking offset -0.8s"
  elastic:
    event_time: "2026-06-05T15:08:10Z"
    ingestion_time: "2026-06-05T15:08:16Z"
    parser_time_field: "@timestamp from source event.created"
    source_timezone: "UTC"
    clock_sync_evidence: "event.ingested - @timestamp = 6s"
expected_result:
  confidence: "High"
  reason: "Each source has event time, ingestion time, parser field, timezone, and bounded clock evidence."
  required_handling: "Use the events in the definitive timeline and cite timestamp evidence in the report."
```
