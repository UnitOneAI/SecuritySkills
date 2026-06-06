# Vulnerable: clock skew reverses alert sequence

## Scenario

The SIEM view sorts events by displayed event time and suggests impossible travel followed by suspicious token use. The endpoint clock is fast by several minutes and the IdP log arrived late, so the apparent order is not reliable.

```yaml
alert_id: ALERT-2026-0606-1324
rule: impossible travel followed by suspicious token use
displayed_timeline:
  - source: vpn
    event_time: 2026-06-06T07:58:55Z
    ingestion_time: 2026-06-06T07:59:20Z
    timezone: UTC
    precision: seconds
    clock_offset_seconds: 0
  - source: idp
    event_time: 2026-06-06T08:00:04Z
    ingestion_time: 2026-06-06T08:12:44Z
    timezone: UTC
    precision: seconds
    delivery_delay: delayed
  - source: edr
    event_time: 2026-06-06T08:06:30Z
    ingestion_time: 2026-06-06T08:13:02Z
    timezone: UTC
    precision: seconds
    clock_offset_seconds: 390
triage_decision:
  disposition: true_positive
  priority: P2
  reason: EDR process event appears after IdP token use
  corrected_ordering: missing
  timeline_confidence: missing
```

## Expected Findings

- `ALERT-TIME-01`: Event and ingestion time must both be preserved before ordering cross-source events.
- `ALERT-TIME-03`: The EDR source clock offset changes the apparent sequence and must be recorded.
- `ALERT-TIME-04`: Corrected event time is missing, so the displayed order is not reliable evidence.
- `ALERT-TIME-05`: IdP ingestion latency could hide the actual sequence.
- `ALERT-TIME-06`: Timeline confidence is missing and should be Low until corrected ordering is documented.

## Expected Assessment

Do not assign high-confidence TP or P2 solely from this displayed timeline. Correct the EDR event time, preserve ingestion latency, and state timeline confidence before using event order in the disposition.
