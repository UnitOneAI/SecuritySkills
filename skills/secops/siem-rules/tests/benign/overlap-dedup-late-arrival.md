# Benign: Scheduled Rule Uses Overlap With Deduplication

This fixture should pass because the scheduled detection accounts for expected connector latency and prevents duplicate incidents.

```text
platform: Microsoft Sentinel
source: Entra ID SigninLogs
query_frequency: 5m
lookback_period: 30m
expected_source_latency: p95 12m, p99 18m
built_in_platform_delay: 5m
event_time_field: TimeGenerated
deduplication_key: IPAddress + ResultType + bin(TimeGenerated, 10m)
suppression_window: 30m
late_event_validation: synthetic sign-in event arrived 14m after event time and still matched on the second run
owner: identity-detections
```

Expected result: pass. The frequency, lookback, latency evidence, platform delay, deduplication key, suppression window, and late-event validation are all recorded, so the overlap is deliberate rather than accidental duplicate noise.
