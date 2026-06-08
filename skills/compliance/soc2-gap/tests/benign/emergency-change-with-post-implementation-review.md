# Benign: Emergency change with traceable rollback and post-implementation review

This fixture should satisfy the CC8.1 emergency-change evidence gate because the emergency path is expedited while preserving authorization, segregation, validation, rollback, and after-the-fact review evidence.

```yaml
change_id: CHG-2026-0522
type: emergency
production_deployment: true
reason: "patch exploited dependency in public API image"
incident_link: SEC-INC-2026-2214
requester: appsec-oncall
approver: engineering-manager
deployer: platform-release-engineer
verifier: sre-oncall
approval:
  status: retroactive_approved
  retroactive_approval_due: "2026-05-23T10:00:00Z"
  retroactive_approval_completed: "2026-05-22T22:40:00Z"
ci_result: "passed"
smoke_test: "api-healthcheck-run-1942"
rollback_plan: "redeploy image digest sha256:previous-known-good and disable feature flag api.v2.cache"
abort_criteria: "5xx rate above 2 percent for 5 minutes or auth latency above 500 ms p95"
post_implementation_review:
  reviewer: security-engineering-manager
  completed_at: "2026-05-23T15:30:00Z"
  follow_up_actions:
    - "add dependency alert auto-ticket routing"
    - "add emergency-change evidence checklist to release template"
```

Expected result:

- No emergency-change finding if the evidence is complete and timestamps fall within the policy-defined approval SLA.
- Record `CHG-2026-0522` in the CC8.1 emergency-change evidence checklist with approval, SoD, test, rollback, and review evidence present.
