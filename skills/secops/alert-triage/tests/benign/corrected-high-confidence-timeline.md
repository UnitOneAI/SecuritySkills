# Benign: corrected high-confidence timeline

## Scenario

The analyst preserves original event times and ingestion times, normalizes all sources to UTC, records clock health, and uses corrected event times before deciding that the alert sequence is reliable.

```yaml
alert_id: ALERT-2026-0606-1324B
rule: impossible travel followed by suspicious token use
timeline_evidence_matrix:
  - source: vpn
    event_time: 2026-06-06T07:58:55Z
    ingestion_time: 2026-06-06T07:59:20Z
    timezone: UTC
    precision: seconds
    clock_offset_seconds: 0
    corrected_event_time: 2026-06-06T07:58:55Z
    ingestion_latency_seconds: 25
  - source: idp
    event_time: 2026-06-06T08:00:04Z
    ingestion_time: 2026-06-06T08:01:02Z
    timezone: UTC
    precision: seconds
    clock_offset_seconds: 0
    corrected_event_time: 2026-06-06T08:00:04Z
    ingestion_latency_seconds: 58
  - source: edr
    event_time: 2026-06-06T08:06:30Z
    ingestion_time: 2026-06-06T08:07:10Z
    timezone: UTC
    precision: seconds
    ntp_status: synchronized
    clock_offset_seconds: 1
    corrected_event_time: 2026-06-06T08:06:29Z
    ingestion_latency_seconds: 40
corrected_ordering:
  - vpn_login
  - idp_token_use
  - edr_process_execution
timeline_confidence: High
triage_decision:
  disposition: true_positive
  priority: P2
  escalation_required: Tier 2
```

## Expected Assessment

Do not flag `ALERT-TIME-01` through `ALERT-TIME-08` when the analyst records event time, ingestion time, timezone, precision, source clock confidence, corrected event time, ingestion latency, corrected ordering, and timeline confidence.
