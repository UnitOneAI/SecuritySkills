# Vulnerable: Search Scope Causes False Negative

This fixture should fail closed because the analyst cannot prove that the required source was queryable for the affected tenant.

```text
analysis objective: determine whether privileged account admin01 had suspicious cloud console activity
time window: 2026-05-14T10:00:00Z to 2026-05-14T11:00:00Z
queried source: cloud audit logs
query scope: project=dev-sandbox
required scope: org production projects and identity tenant
SIEM response: no events found
index permissions: analyst role excludes production-cloud-audit
heartbeat evidence: unavailable for excluded indexes
last event time: N/A
last ingest time: N/A
drop/error counters: not visible to analyst role
```

Expected result: fail. The hypothesis is Not Evaluable from the available query because access scope can create a false "no logs found" result.
