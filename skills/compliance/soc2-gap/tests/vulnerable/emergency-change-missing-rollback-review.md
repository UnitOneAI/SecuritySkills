# Vulnerable: Emergency change without rollback or post-implementation review

This fixture should be treated as incomplete CC8.1 evidence because the emergency path bypasses the controls needed for SOC 2 operating-effectiveness testing.

```yaml
change_id: CHG-2026-0418
type: emergency
production_deployment: true
reason: "hotfix login failures"
incident_link: INC-2026-8871
requester: api-team-lead
approver: api-team-lead
deployer: api-team-lead
verifier: api-team-lead
approval:
  status: missing
  retroactive_approval_due: "2026-04-19T18:00:00Z"
  retroactive_approval_completed: null
ci_result: "passed"
smoke_test: null
rollback_plan: null
abort_criteria: null
post_implementation_review: null
```

Expected result:

- `SOC2-CC8-EMERG-03` because approval evidence is missing.
- `SOC2-CC8-EMERG-04` because one actor requested, approved, deployed, and verified the emergency change.
- `SOC2-CC8-EMERG-05` because rollback and abort criteria are missing.
- `SOC2-CC8-EMERG-06` because there is no post-implementation review.
