# Vulnerable: Sentinel Rule Uses Frequency-Equal Lookback For Delayed Logs

This fixture should fail because the rule only looks back as far as its run frequency while the data source commonly arrives later than that window.

```text
platform: Microsoft Sentinel
source: Entra ID SigninLogs
query_frequency: 5m
lookback_period: 5m
expected_source_latency: 6m to 20m for the connector
built_in_platform_delay: not recorded
deduplication_key: not recorded
late_event_validation: not performed
```

```kql
SigninLogs
| where TimeGenerated between (ago(5m) .. now())
| where ResultType != 0
| summarize Attempts=count() by IPAddress, bin(TimeGenerated, 5m)
```

Expected result: fail. A true positive whose event time is inside the prior five-minute window but whose ingestion occurs after that run can be skipped, and there is no overlap, platform-delay evidence, or duplicate-suppression design.
