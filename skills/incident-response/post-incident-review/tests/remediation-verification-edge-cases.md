# Remediation Verification Edge Cases

These fixtures verify that `post-incident-review` separates action creation, implementation, verification, residual-risk acceptance, and recurrence tracking.

```yaml
case_id: PIR-VERIFY-01
title: Detection rule action is implemented but not replay-tested
action:
  id: REM-001
  mapped_control_failure: detective detection gap
  priority: P1
  closure_criterion: alert fires and routes to on-call queue for representative telemetry
  implementation_ticket: closed
  verification_method: detection replay
  verification_evidence: missing
expected_classification:
  status: Not verified
  reason: "Ticket closure does not prove the detection catches the original failure mode."
```

```yaml
case_id: PIR-VERIFY-02
title: Detection remediation verified with replay and routing evidence
action:
  id: REM-002
  mapped_control_failure: detective alert routing gap
  priority: P1
  closure_criterion: replayed telemetry creates high-severity alert and pages SOC
  verification_method: detection replay
  verification_evidence:
    replay_job_id: replay-2026-06-06-01
    alert_id: ALRT-4481
    on_call_page: delivered
  verifier: detection-engineering
expected_classification:
  status: Verified
  reason: "Replay evidence proves the updated detection and routing path work."
```

```yaml
case_id: PIR-VERIFY-03
title: Segmentation fix needs source-to-target validation
action:
  id: REM-003
  mapped_control_failure: preventive segmentation failure
  priority: P0
  closure_criterion: lateral movement path from user subnet to database subnet is denied and logged
  implementation_ticket: firewall rule deployed
  verification_method: segmentation validation
  verification_evidence:
    denied_path_test: missing
    allowed_business_path_test: missing
expected_classification:
  status: Not verified
  reason: "A deployed firewall rule must be tested from the relevant source and destination paths."
```

```yaml
case_id: PIR-VERIFY-04
title: Vendor-dependent action is blocked with interim controls and risk owner
action:
  id: REM-004
  mapped_control_failure: vendor patch dependency
  priority: P1
  closure_criterion: vendor patch deployed or compensating control verified
  vendor_ticket: VEND-9912
  interim_controls:
    - WAF virtual patch
    - increased logging
  residual_risk:
    status: Accepted
    owner: security-risk-committee
    expiry: "2026-07-31"
expected_classification:
  status: Accepted risk
  reason: "Blocked vendor action has interim controls, accountable risk owner, and expiry date."
```

```yaml
case_id: PIR-VERIFY-05
title: Restore drill verifies backup remediation
action:
  id: REM-005
  mapped_control_failure: corrective recovery gap
  priority: P1
  closure_criterion: critical database restores within four-hour objective
  verification_method: restore drill
  verification_evidence:
    drill_id: DRILL-2026-06
    restore_time_minutes: 132
    data_integrity_check: passed
  verifier: sre-platform
expected_classification:
  status: Verified
  reason: "Restore drill evidence proves the corrective control meets the recovery objective."
```

```yaml
case_id: PIR-VERIFY-06
title: Recurrence signal reopens a prior incomplete action
current_incident: IR-2026-044
similar_prior_incidents:
  - IR-2026-012
prior_action:
  id: REM-012-03
  status: Implemented
  verification: failed
recurrence_signal:
  detection: phishing-click-to-oauth-consent
  count_30_days: 3
  reopen_threshold: 1
expected_classification:
  status: Action reopened
  reason: "A recurring precursor exceeded the threshold and the prior action was never verified."
```

```yaml
case_id: PIR-VERIFY-07
title: Process update requires tabletop evidence
action:
  id: REM-007
  mapped_control_failure: process escalation gap
  priority: P2
  closure_criterion: responders can execute updated escalation path during tabletop
  implementation_artifact: playbook updated
  verification_method: tabletop exercise
  verification_evidence: missing
expected_classification:
  status: Implemented but not verified
  reason: "A playbook update needs walkthrough or tabletop evidence before the process action is closed."
```
