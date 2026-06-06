# Timeline Confidence Fixtures

Use these edge cases when validating `alert-triage` output. The expected behavior is that timeline-dependent conclusions include a timeline confidence rating and do not rely on ingestion order when event-time reliability is missing.

## Fixture 1: Clock Skew Reverses Endpoint Sequence

```yaml
alert: impossible-travel-followed-by-token-use
idp_event_time: 2026-06-06T08:00:04Z
vpn_event_time: 2026-06-06T07:58:55Z
edr_event_time: 2026-06-06T08:06:30Z
edr_host_clock_offset_seconds: 390
siem_ingested_at: 2026-06-06T08:12:44Z
```

Expected result:
- Corrected EDR event time is 2026-06-06T08:00:00Z.
- The output records raw and corrected order.
- Sequence-dependent confidence is Medium or Low unless another source corroborates the order.

## Fixture 2: Ingestion Latency Hides Cloud Audit Order

```yaml
alert: suspicious-storage-token-use
cloud_event_time: 2026-06-06T08:01:00Z
cloud_ingested_at: 2026-06-06T08:29:00Z
edr_event_time: 2026-06-06T08:08:15Z
edr_ingested_at: 2026-06-06T08:13:00Z
```

Expected result:
- Event-time order and ingestion-time order are both shown.
- The triage report does not claim the EDR event happened first.
- Timeline confidence is reduced if cloud delivery delay is not explained.

## Fixture 3: Coarse SaaS Precision

```yaml
alert: suspicious-admin-role-change
saas_event_time: 2026-06-06T08:04Z
saas_timestamp_precision: minute
idp_event_time: 2026-06-06T08:04:42.311Z
idp_timestamp_precision: millisecond
```

Expected result:
- The output treats events inside the same minute as unordered unless more evidence exists.
- Corrected event order is Not Evaluable for sub-minute claims.

## Fixture 4: Offline Endpoint Upload

```yaml
alert: malware-detected-after-vpn-login
vpn_event_time: 2026-06-06T08:10:00Z
vpn_ingested_at: 2026-06-06T08:10:12Z
edr_detection_time: 2026-06-06T08:03:00Z
edr_ingested_at: 2026-06-06T08:45:00Z
endpoint_offline_until: 2026-06-06T08:44:00Z
```

Expected result:
- Ingestion order is explicitly rejected as attack order.
- Timeline confidence remains Medium only if the offline upload indicator is documented.

## Fixture 5: Unknown Clock Offset

```yaml
alert: token-use-after-process-launch
process_start_time: 2026-06-06T08:00:15Z
token_use_time: 2026-06-06T08:00:26Z
host_clock_offset_seconds: unknown
```

Expected result:
- The report can list both events but marks the ordering conclusion Low confidence or Not Evaluable.
- Priority is not raised solely because the process event appears eleven seconds before token use.
