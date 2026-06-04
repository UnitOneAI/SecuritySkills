# Benign: Documented Maintenance Explains a Telemetry Gap

This fixture should be recorded as a visibility limitation, not as compromise by itself, because the gap has enough health and change evidence.

```text
analysis window: 2026-05-12T02:00:00Z to 2026-05-12T03:00:00Z
hypothesis: account compromise
required source: IdP sign-in logs
source status: delayed
last event time before window: 2026-05-12T01:58:41Z
last ingest time before window: 2026-05-12T01:59:10Z
heartbeat: healthy before and after planned parser deployment
change ticket: CHG-48291, IdP parser schema migration
drop counters: zero rejected authentication events after replay completed
post-maintenance recovery: backlog replay completed at 2026-05-12T03:18:00Z
corroboration: endpoint, proxy, and MFA logs show no suspicious activity during the same window
```

Expected result: pass or informational limitation. The analyst should lower confidence for the delayed window, preserve the maintenance evidence, and avoid treating the gap alone as proof of compromise.
