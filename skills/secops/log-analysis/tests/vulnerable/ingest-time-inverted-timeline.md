# Vulnerable: Ingestion Time Inverts Event Order

## Scenario

A SIEM export mixes raw event timestamps with ingestion timestamps. If the analyst sorts by ingestion time, the timeline incorrectly suggests endpoint execution happened before the cloud identity event.

## Log Sample

```text
cloud_audit event_time=2026-06-02T10:01:00Z ingest_time=2026-06-02T10:47:00Z user=maria action=ConsoleLogin result=Success
endpoint_edr event_time=2026-06-02T10:20:00Z ingest_time=2026-06-02T10:21:30Z host=LAPTOP-22 process=powershell.exe
proxy event_time=2026-06-02T10:22:03Z ingest_time=2026-06-02T10:22:29Z host=LAPTOP-22 url=internal.example
```

## Expected Handling

- Preserve both `event_time` and `ingest_time`.
- Build the investigation timeline from normalized event time unless the source documents that only ingestion time is available.
- Record the timestamp type and confidence for each row.
- Flag any conclusion that depends on ingestion-time ordering as low confidence.
