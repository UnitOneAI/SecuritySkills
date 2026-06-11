---
case: sampling-loss-parser-fallback
expected: vulnerable
issue: 249
---

# Vulnerable: Sampled Security Events And Parser Fallback Loss

```yaml
analysis_window:
  start_utc: "2026-06-03T01:00:00Z"
  end_utc: "2026-06-03T01:15:00Z"
sources:
  traces:
    timestamp_source: ingest_time
    source_timezone: missing
    normalized_timezone: assumed_utc
    clock_drift: unknown
    sampling_policy: "5% adaptive"
    security_force_keep: false
    dropped_event_counters: unavailable
  app_auth:
    primary_parser: json
    fallback_parser: regex
    parser_fallback_rate: unknown
    field_fidelity_impact:
      lost_fields:
        - user_id
        - tenant_id
        - request_id
        - auth_outcome
```

Expected review result: the analyst must not conclude "no suspicious authentication activity" from these logs alone. The report should raise `LOG-TIME-01`, `LOG-SAMPLING-01`, and `LOG-PARSER-02` or equivalent visibility limitations before scoring the incident timeline.
