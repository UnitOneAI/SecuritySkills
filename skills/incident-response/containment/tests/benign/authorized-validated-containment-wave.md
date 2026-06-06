# Benign: authorized and validated containment wave

## Scenario

The incident team grouped coordinated containment actions into one execution wave to avoid tipping off an attacker with multiple footholds. The action ledger records approvals, execution timing, validation evidence, and rollback ownership.

```yaml
incident_id: INC-2026-0606-22
action_group: wave-1-identity-and-c2
approval:
  incident_commander: ic@example.com
  business_owner: checkout-owner@example.com
  approved_at: 2026-06-06T08:15:00Z
business_impact:
  service: checkout-api
  impact: degraded admin automation for 30 minutes
  accepted_by: checkout-owner@example.com
evidence_gate:
  memory_capture: completed
  volatile_artifacts_hash_verified: true
execution:
  planned_window: 2026-06-06T08:30:00Z
  actual_window: 2026-06-06T08:31:00Z
  simultaneous_actions:
    - revoke svc-build-prod sessions
    - block c2 domains at DNS and proxy
    - isolate workstation subnet from server segment
validation:
  owner: soc-lead@example.com
  methods:
    - proxy logs show no outbound C2 after 2026-06-06T08:34:00Z
    - identity logs show revoked service account authentication fails
    - EDR shows no new lateral movement from isolated subnet
rollback:
  owner: network-lead@example.com
  proof: staged rollback tested on quarantine VLAN
expiry_review:
  next_review: 2026-06-07T08:30:00Z
  permanent_control_path: firewall rule change request CHG-1109
```

## Expected Assessment

Do not flag `CONT-AUTH-01` through `CONT-AUTH-08` when the ledger proves:

- Approval and business-impact acceptance are recorded.
- Containment actions were grouped into a coordinated execution wave.
- Evidence preservation state is known.
- Validation owner and validation methods prove the attacker capability stopped.
- Rollback owner and rollback proof are recorded.
- Temporary controls have review or permanent-control conversion paths.
