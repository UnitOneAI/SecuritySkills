# log-analysis time normalization edge cases

These fixtures calibrate the `log-analysis` skill's time normalization and log integrity preflight. They are documentation-style tests for the reviewer behavior expected from `SKILL.md`.

## Vulnerable / Not Evaluable Case: Mixed Time Bases

```json
{
  "analysis_window": "2026-06-05T01:00:00Z/2026-06-05T02:00:00Z",
  "timeline_basis": "siem_index_time_only",
  "clock_skew_tolerance": "unknown",
  "events": [
    {
      "source": "endpoint-edr",
      "event_time": "2026-06-04 18:12:03",
      "timezone": "local timezone not recorded",
      "ingestion_time": "2026-06-05T01:44:12Z",
      "event": "powershell encoded command"
    },
    {
      "source": "cloud-audit",
      "event_time": "2026-06-05T01:18:30Z",
      "ingestion_time": "2026-06-05T01:18:41Z",
      "event": "security group opened to internet"
    }
  ],
  "collector_health": {
    "endpoint_forwarder_gap": "35 minutes",
    "ntp_or_clock_sync_evidence": "missing"
  }
}
```

Expected reviewer behavior:

- Do not present the sequence as confirmed.
- Flag the endpoint event as `Low confidence` or `Not Evaluable` until timezone and clock sync evidence are supplied.
- Treat the forwarder gap as a visibility gap during the analysis window.
- Use `event_time`, `ingestion_time`, and the uncertainty fields in the report.

## Benign / High-Confidence Case: Normalized UTC Event Time

```json
{
  "analysis_window": "2026-06-05T01:00:00Z/2026-06-05T02:00:00Z",
  "timeline_basis": "normalized_event_time_utc",
  "clock_skew_tolerance": "+/- 60 seconds",
  "sources": [
    {
      "source": "windows-security",
      "event_time_field": "TimeCreated",
      "timezone": "UTC",
      "collector_time_field": "event.ingested",
      "clock_sync": "Windows Time Service healthy",
      "observed_skew": "12 seconds",
      "continuity": "heartbeat events present every 5 minutes"
    },
    {
      "source": "aws-cloudtrail",
      "event_time_field": "eventTime",
      "timezone": "UTC",
      "collector_time_field": "ingestionTime",
      "clock_sync": "AWS managed source timestamp",
      "observed_skew": "not applicable",
      "continuity": "CloudTrail delivery logs complete"
    }
  ],
  "timeline_rows": [
    {
      "normalized_event_time": "2026-06-05T01:12:03Z",
      "source_timestamp": "2026-06-05T01:12:03Z",
      "collector_time": "2026-06-05T01:12:15Z",
      "source": "windows-security",
      "event": "4624 successful logon",
      "time_confidence": "High"
    }
  ]
}
```

Expected reviewer behavior:

- Accept the timeline ordering as high confidence.
- Preserve both source event time and collector/SIEM time in the report.
- Document the UTC normalization rule and clock-skew tolerance.
