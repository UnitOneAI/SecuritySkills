# Log Analysis Timeline Evidence Edge Cases

These fixtures validate that log-analysis reports preserve timeline integrity
and avoid overconfident conclusions when timestamps, pipeline health, or raw
evidence are incomplete.

## Edge Case 1: Mixed Local Time and UTC

Input evidence:

```json
[
  {
    "source": "windows_security",
    "event_id": 4624,
    "event_time": "2026-06-06 01:58:03",
    "timezone": "America/Los_Angeles",
    "host": "ws-17",
    "user": "alice"
  },
  {
    "source": "azure_ad_signin",
    "event_time": "2026-06-06T09:59:10Z",
    "ingestion_time": "2026-06-06T10:04:33Z",
    "user": "alice"
  }
]
```

Expected output:

- Finding ID: `LOG-TIME-01` if timezone is missing for any source
- Timeline shows UTC-normalized timestamps and retains original timestamps
- Do not assert exact sequence ordering unless clock-skew tolerance is documented

## Edge Case 2: Log Pipeline Gap During Incident Window

Input evidence:

```yaml
incident_window_utc: "2026-06-06T02:00:00Z/2026-06-06T03:00:00Z"
pipeline_health:
  source: edr_telemetry
  dropped_events: 12943
  outage_window_utc: "2026-06-06T02:15:00Z/2026-06-06T02:41:00Z"
finding_claim: "No process execution occurred after suspicious logon"
```

Expected output:

- Finding ID: `LOG-TIME-04`
- Visibility Gaps records the EDR outage
- Report avoids definitive negative claims about missing process execution
- Recommendations include pipeline recovery and alternate-source review

## Edge Case 3: Normalized Fields Without Raw Event Spot Check

Input evidence:

```yaml
siem_result:
  query_id: q-8842
  parser_version: auth_parser_v9
  normalized_fields:
    action: login_success
    src_ip: 203.0.113.50
    user: svc-build
    timestamp_utc: "2026-06-06T04:12:00Z"
raw_export:
  path: null
  sha256: null
```

Expected output:

- Finding ID: `LOG-EVID-01`, `LOG-EVID-03`, or `LOG-EVID-05`
- Confidence is reduced because no raw-event spot check is available
- Evidence Handling records missing export path and hash
- Remediation requests raw export preservation and query text retention
