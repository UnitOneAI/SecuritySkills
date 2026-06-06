# Vulnerable: containment change closed without validation

## Scenario

An incident team pushed several containment changes, then marked the action complete because the change tickets were closed. There is no proof that the attacker capability stopped, no named validation owner, and no rollback proof.

```yaml
incident_id: INC-2026-0606-17
containment_actions:
  - action: block_c2_domain
    target: bad.example
    ticket: CHG-1021
    ticket_status: closed
    approved_by: missing
    executor: network-team
    validation_owner: missing
    validation_method: missing
    rollback_owner: missing
    rollback_test: missing
  - action: disable_compromised_account
    target: svc-build-prod
    ticket: CHG-1022
    ticket_status: closed
    old_sessions_invalidated: unknown
    authentication_failure_observed: false
business_impact:
  affected_service: checkout-api
  dependency_assessment: missing
evidence_gate:
  volatile_evidence_captured: not_evaluable
```

## Expected Findings

- `CONT-AUTH-01`: Containment action has no incident commander or business owner approval.
- `CONT-AUTH-02`: Action owner, executor, validation owner, or rollback owner is missing.
- `CONT-AUTH-05`: Validation result is missing or based only on change-ticket closure.
- `CONT-AUTH-06`: Rollback criteria exist but rollback test/proof is missing.
- `CONT-AUTH-07`: Action status is marked complete while evidence preservation is Not Evaluable.

## Expected Assessment

Do not mark containment complete. Record approval, business impact, evidence gate status, validation owner, validation method, rollback owner, rollback proof, and expiry/review fields before closure.
