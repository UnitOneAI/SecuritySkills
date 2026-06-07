# Benign: near miss with complete metrics and notification evidence

This fixture should pass the near-miss, response-impact, and notification-clock
gates because the PIR records why compromise metrics are not applicable,
captures the prevention evidence, documents response tradeoffs, and tracks
legal/privacy decision timing.

```yaml
incident:
  id: IR-2026-0611
  type: credential-stuffing
  outcome: blocked before account takeover
  first_attempt_timestamp: 2026-06-01T13:08:00Z
  detection_timestamp: 2026-06-01T13:10:00Z
  block_timestamp: 2026-06-01T13:11:00Z
  initial_compromise_timestamp: not_applicable
  recovery_timestamp: not_applicable
  data_impact: none_confirmed

metrics:
  metric_mode: near_miss_blocked_attempt
  compromise_recovery_metrics_applicability: not_applicable_no_session_or_data_access
  attempt_detection_time: 2m
  time_to_block: 3m
  control_that_blocked_attempt: IdP risk policy with impossible-travel and password-spray guard
  recurrence_count_12_months: 2
  false_negative_review: complete_no_related_successful_logins
  evidence:
    - idp_risk_policy_event_2026_06_01
    - siem_query_credential_stuffing_sweep
    - authentication_session_review

response_actions:
  - action: temporarily blocked source ASN at edge WAF
    expected_benefit: reduce password-spray volume during investigation
    side_effect: possible false positive for one partner NAT range
    evidence_impact: none
    rollback_criteria: source volume below threshold for 30m or partner allowlist request
    break_glass_owner: security-operations-oncall
    decision_owner: incident_commander
    pir_finding: no_follow_up_required_tradeoff_documented

notification_clock:
  potentially_regulated_data: none_confirmed_after_session_review
  legal_privacy_engaged_at: 2026-06-01T13:25:00Z
  regulatory_assessment_started_at: 2026-06-01T13:40:00Z
  customer_notification_decision: no_notify
  decision_deadline: internal_24h_review_sla
  current_status: completed_on_time
  rationale: no account takeover, no personal-data access, no contractual notification trigger
```

Expected result:

- Pass: compromise/recovery metrics are explicitly not applicable and backed by
  session/data-access evidence.
- Pass: near-miss metrics include attempt detection time, time to block,
  recurrence count, blocking control, and false-negative review.
- Pass: response side effects, rollback criteria, owner, and evidence impact
  are documented.
- Pass: legal/privacy assessment and no-notify decision are timestamped with a
  deadline and rationale.
