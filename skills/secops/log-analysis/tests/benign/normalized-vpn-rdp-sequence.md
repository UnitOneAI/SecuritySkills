# Benign: Normalized VPN to RDP Sequence

## Scenario

At first glance, Windows logon appears to precede VPN MFA because the VPN log is in Pacific time and the endpoint has minor clock drift. After normalization, the sequence is expected.

## Log Sample

```text
vpn original_timestamp="2026-06-02 01:58:12 -0700" event_time_utc=2026-06-02T08:58:12Z user=maria result=success mfa=passed
windows_security_4624 original_timestamp="2026-06-02 09:03:44 UTC" event_time_utc=2026-06-02T08:59:03Z user=maria logon_type=10 clock_offset=+00:04:41
proxy original_timestamp="2026-06-02 09:04:10 UTC" event_time_utc=2026-06-02T09:04:10Z host=LAPTOP-22 url=internal.example
```

## Expected Handling

- Treat the sequence as VPN MFA, then RDP logon, then proxy activity.
- Include original timestamps, normalized UTC values, timezone assumptions, and clock offset in the timeline.
- Classify impossible-travel or credential-misuse conclusions as unsupported for this evidence.
