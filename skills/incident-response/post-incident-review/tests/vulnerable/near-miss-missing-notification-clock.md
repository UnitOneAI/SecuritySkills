# Vulnerable: near miss forced into compromise metrics

This fixture should be flagged by the post-incident-review skill because the
PIR treats a blocked attempt as an incomplete compromise incident, omits
near-miss metrics, fails to review response-induced harm, and leaves the
legal/privacy notification clock undocumented.

```yaml
incident:
  id: IR-2026-0610
  type: credential-stuffing
  outcome: blocked by IdP risk policy
  initial_compromise_timestamp: null
  detection_timestamp: 2026-06-01T13:10:00Z
  containment_timestamp: 2026-06-01T13:16:00Z
  recovery_timestamp: null
  data_impact: suspected_personal_data_exposure

metrics:
  mttd: missing
  mttr: missing
  near_miss_metrics: omitted
  control_that_blocked_attempt: omitted
  false_negative_review: not_performed

response_actions:
  - action: disabled all VPN accounts sharing the impacted IdP group
    expected_benefit: stop possible credential reuse
    side_effect: forensic jump host access blocked for responders
    evidence_export_delay: 4h
    rollback_criteria: ""
    break_glass_owner: ""

notification_clock:
  legal_privacy_engaged_at: 2026-06-03T18:00:00Z
  regulatory_assessment_started_at: ""
  customer_notification_decision: ""
  decision_deadline: ""
  status: unknown
```

Expected findings:

- Medium: MTTD/MTTR are forced as missing even though compromise and recovery
  were not applicable to the blocked attempt.
- High: near-miss metrics do not identify attempt detection time, time to
  block, recurrence, control evidence, or false-negative review.
- High: the VPN containment action delayed evidence export without rollback
  criteria or break-glass ownership.
- High: possible personal-data exposure lacks regulatory assessment timestamp,
  notification decision, deadline, and status.
