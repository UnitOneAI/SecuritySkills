# Vulnerable: Clock Skew Creates False Lateral Movement Order

## Scenario

Cross-host correlation appears to show service creation before authentication because one endpoint clock is seven minutes slow.

## Log Sample

```text
dc01 Security 4624 event_time=2026-06-02T14:05:12Z user=svc_deploy src=10.0.4.20 logon_type=3 ntp_status=healthy
app02 System 7045 event_time=2026-06-02T13:59:41Z service=UpdaterSvc account=svc_deploy clock_offset=-00:07:05
edr app02 process event_time=2026-06-02T14:00:03Z process=sc.exe parent=cmd.exe clock_offset=-00:07:05
```

## Expected Handling

- Capture known clock offset or NTP health for each host.
- Normalize the host-local event timestamps before concluding event order.
- Mark timeline ordering as uncertain when clock skew evidence is missing.
- Avoid escalating solely because an adjusted event appears out of order.
