# Vulnerable: Splunk Search Ignores Index-Time Lag For Batch Source

This fixture should fail because a scheduled search uses only event time for a batch-delivered source without durable-search or index-time coverage.

```text
platform: Splunk Enterprise Security
source: Microsoft 365 audit logs
schedule: every 15m
event_time_window: earliest=-15m latest=now
index_time_window: not used
durable_search: disabled
lag_time: not configured
deduplication_key: UserId + ClientIP + Operation
late_event_validation: missing
```

```spl
index=o365 sourcetype="o365:management:activity" earliest=-15m latest=now Operation=UserLoggedIn
| stats count min(_time) as first_event max(_time) as last_event by UserId, ClientIP
| where count > 5
```

Expected result: fail. The rule can miss events that are indexed after the scheduled event-time window closes. The review should require `_indextime` or durable-search evidence, lag-time reasoning, and a replayed late-arrival test before calling the rule production-ready.
