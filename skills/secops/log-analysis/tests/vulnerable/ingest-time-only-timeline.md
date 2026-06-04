# Vulnerable: Timeline Uses Ingest Time Instead of Event Time

This fixture should fail because replayed events are ordered only by SIEM ingestion time, hiding the true event sequence.

```text
event A:
  source: endpoint EDR
  event time: 2026-05-20T08:03:14Z
  ingest time: 2026-05-20T08:05:02Z
  stable event id: edr-173839
  summary: process creation alert

event B:
  source: identity provider
  event time: 2026-05-20T07:58:22Z
  ingest time: 2026-05-20T08:11:47Z
  stable event id: idp-99271
  arrival status: late replay after collector backlog
  summary: privileged sign-in

reported timeline:
  08:05 process creation
  08:11 privileged sign-in
```

Expected result: fail. The report must preserve both event time and ingest time, mark event B as late replay, deduplicate by stable event ID, and build the investigation timeline from event occurrence time rather than SIEM arrival order.
