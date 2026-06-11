---
case: time-normalized-no-sampling-or-fallback
expected: benign
issue: 249
---

# Benign: Normalized Time With No Sampling Or Fallback

```yaml
analysis_window:
  start_utc: "2026-06-03T01:00:00Z"
  end_utc: "2026-06-03T01:15:00Z"
sources:
  app:
    timestamp_source: event_time
    source_timezone: UTC
    normalized_timezone: UTC
    clock_drift: "NTP synchronized, drift < 1s"
    sampling_policy: disabled
    security_force_keep: true
    primary_parser: json
    fallback_parser: none
    parser_fallback_rate: "0%"
  proxy:
    timestamp_source: event_time
    source_timezone: UTC
    normalized_timezone: UTC
    clock_drift: "NTP synchronized, drift < 1s"
    sampling_policy: disabled
    security_force_keep: true
    primary_parser: cef
    fallback_parser: none
    parser_fallback_rate: "0%"
```

Expected review result: the analyst can make high-confidence timeline and absence-of-event conclusions for this window because timezone normalization, sampling, and parser fidelity evidence are present.
