# Evidence Preservation and Notification Handoff Edge Cases

These fixtures verify that alert-triage preserves volatile evidence, notification-candidate facts, and escalation ownership without forcing the SOC analyst to make a final breach determination.

```yaml
case_id: ALERT-HANDOFF-01
title: Regulated data alert is notification candidate, not confirmed breach
alert:
  rule: Possible bulk download from document repository
  data_classification: HR
  first_detected_at: "2026-06-05T01:10:00Z"
  matched_events: 45_file_reads_in_10_minutes
missing_impact_evidence:
  - file_names_exported
  - external_sharing_event
  - dlp_export
handoff:
  privacy_legal_required: true
  owner: privacy_officer_queue
  acknowledged_at: null
expected_triage:
  breach_status_language: Notification candidate
  disposition: pending_handoff
  reason: "Preserve clock and missing evidence without claiming confirmed breach."
```

```yaml
case_id: ALERT-HANDOFF-02
title: Benign migration still needs evidence preservation before BTP closure
alert:
  rule: Bulk SharePoint reads
  data_classification: Customer
  proposed_disposition: BTP
business_context:
  migration_ticket: MIG-2026-441
  asset_owner_approval: present
evidence_preservation:
  raw_alert_payload: missing
  siem_query_time_range: preserved
  dlp_cloud_export: missing
  approval_evidence: present
expected_triage:
  action: block_closure_until_preserved
  reason: "A BTP decision on sensitive data must preserve raw alert and DLP/cloud export evidence."
```

```yaml
case_id: ALERT-HANDOFF-03
title: Unknown data classification remains not evaluable
alert:
  rule: Large SaaS export by contractor
  data_classification: unknown
  user_type: contractor
  destination: external_ip
asset_context:
  owner: missing
  data_inventory_match: missing
handoff:
  privacy_legal_required: unknown
expected_triage:
  priority_floor: P3
  regulated_data_status: Not evaluable
  reason: "Unknown classification should not silently decrease priority or bypass handoff review."
```

```yaml
case_id: ALERT-HANDOFF-04
title: Escalation to IR lacks recipient acknowledgment
alert:
  rule: Suspected ransomware staging
  priority: P1
  disposition: TP
escalation:
  escalated_to: IR_team_queue
  escalated_at: "2026-06-05T02:00:00Z"
  acknowledged_by: null
  current_owner: null
  next_decision_deadline: null
expected_triage:
  action: keep_open_pending_acknowledgment
  reason: "P1/P2 handoff is incomplete until recipient acknowledgment, owner, and next deadline are recorded."
```

```yaml
case_id: ALERT-HANDOFF-05
title: Volatile cloud audit logs have high retention risk
alert:
  rule: Suspicious object storage enumeration
  source_system: cloud_security
  data_classification: Confidential
evidence_preservation:
  raw_alert_payload: preserved
  siem_query_time_range: preserved
  cloud_audit_export:
    preserved: false
    retention_hours_remaining: 18
  edr_network_context: not_applicable
expected_triage:
  action: preserve_cloud_audit_export_before_closure
  retention_risk: High
```

```yaml
case_id: ALERT-HANDOFF-06
title: False positive on crown-jewel asset still needs approval evidence
alert:
  rule: Admin query against customer database
  asset_criticality: crown_jewel
  proposed_disposition: FP
rule_logic_issue:
  confirmed: true
approval_evidence:
  asset_owner_approval: missing
  maintenance_window_ticket: CHG-2026-778
evidence_preservation:
  raw_alert_payload: preserved
  siem_query_time_range: preserved
expected_triage:
  action: require_asset_owner_evidence
  reason: "FP/BTP closure on crown-jewel assets needs approval or owner context, not only rule-logic evidence."
```

```yaml
case_id: ALERT-HANDOFF-07
title: Legal hold required for suspicious PHI access
alert:
  rule: Unusual EHR record access
  data_classification: PHI
  first_detected_at: "2026-06-05T04:15:00Z"
  user_context: nurse_float_pool
notification_candidate:
  potential_regime: HIPAA
  reportability_decision_owner: privacy_officer
  legal_hold_required: true
evidence_preservation:
  raw_alert_payload: preserved
  siem_query_time_range: preserved
  dlp_cloud_export: not_applicable
  ehr_audit_export:
    preserved: true
    export_id: EHR-20260605-0415
expected_triage:
  breach_status_language: Notification candidate
  action: handoff_to_privacy_and_record_decision_deadline
```
