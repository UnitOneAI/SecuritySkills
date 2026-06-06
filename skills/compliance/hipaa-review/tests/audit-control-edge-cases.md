# HIPAA Audit-Control Edge Cases

Use these fixtures to validate that `hipaa-review` does not over-credit generic
logging evidence for 45 CFR 164.312(b) audit controls.

## Vulnerable: Login-Only ePHI Logging

```yaml
system: ehr-prod
contains_ephi: true
technical_safeguards:
  164_312_b_audit_controls: implemented
logging_enabled: true
siem_connected: true
retention_policy: six_years
sampled_events:
  - user_login
  - user_logout
missing_events:
  - patient_record_view
  - patient_record_export
  - patient_record_update
  - patient_record_delete
  - failed_access
  - break_glass_access
  - admin_privilege_change
activity_review:
  report: weekly_login_summary
  reviewed_ephi_activity: false
expected_decision: partial_compliance
reason: Login events do not prove activity can be recorded and examined for ePHI use.
```

## Vulnerable: Retention Without Integrity or Time Basis

```yaml
system: claims-data-warehouse
contains_ephi: true
logged_events:
  - login
  - query
  - export
retention_policy: six_years
archive_location: siem_hot_warm_archive
time_sync: unknown
immutability: missing
export_hash: missing
chain_of_custody: missing
restore_or_export_test: missing
expected_decision: partial_compliance
reason: Retention text alone does not prove reliable audit evidence.
```

## Vulnerable: Business Associate Coverage Unknown

```yaml
system: ba-patient-engagement-platform
contains_ephi: true
baa_present: true
ba_audit_report:
  event_taxonomy: missing
  ephi_view_export_events: unknown
  break_glass_events: unknown
  admin_change_events: unknown
  exception_review: missing
expected_decision: not_evaluable
reason: The reviewer cannot infer 164.312(b) coverage from a BAA without audit-event evidence.
```

## Vulnerable: Logs Collected but Activity Review Disconnected

```yaml
systems:
  - ehr-prod
  - patient-api
  - billing-platform
audit_logs:
  event_taxonomy:
    - login
    - ephi_view
    - ephi_export
    - admin_privilege_change
activity_review:
  cfr: 164.308(a)(1)(ii)(D)
  review_report: missing
  owner: missing
  cadence: missing
  exceptions_reviewed: false
  escalation_outcome: missing
expected_decision: non_compliance
reason: Audit collection is not enough when the organization cannot show records are examined and exceptions are followed up.
```

## Benign: Legacy System With Compensating Audit Evidence

```yaml
system: legacy-lab-interface
contains_ephi: true
native_audit_events:
  ephi_view_export: unsupported
compensating_controls:
  upstream_api_gateway:
    authenticated_requests: covered
    ephi_payload_export: covered
    service_account_access: covered
  database_audit:
    create_update_delete: covered
    admin_schema_change: covered
  network_tap:
    interface_messages: sampled
integrity_time_basis:
  ntp_source: documented
  immutable_archive: enabled
retention_evidence:
  period: six_years
  archive_location: compliance_archive
  export_test: 2026-05-30
activity_review_linkage:
  cfr: 164.308(a)(1)(ii)(D)
  report: weekly_legacy_interface_review
  owner: security_official
  exceptions_tracked: true
expected_decision: partial_compliance
reason: Native logging is incomplete, but compensating audit evidence is documented and reviewable.
```

## Benign: Complete Audit-Control Evidence

```yaml
system: ehr-prod
contains_ephi: true
event_coverage:
  authentication_success_failure: covered
  ephi_view: covered
  ephi_export: covered
  ephi_modify_delete_restore: covered
  failed_access: covered
  break_glass_access: covered
  admin_privilege_change: covered
  api_service_account_access: covered
log_sources:
  - application_audit_log
  - database_audit_log
  - cloud_audit_trail
  - siem_query
integrity_time_basis:
  ntp_source: documented
  immutable_archive: enabled
  export_hash: sha256_recorded
  chain_of_custody: documented
retention_evidence:
  period: six_years
  archive_location: compliance_archive
  restore_or_export_test: 2026-05-31
activity_review_linkage:
  cfr: 164.308(a)(1)(ii)(D)
  report: weekly_ephi_activity_review
  owner: security_official
  cadence: weekly
  exceptions_tracked: true
  follow_up_tickets: linked
expected_decision: compliant
reason: The record proves event coverage, integrity, retention, and activity-review linkage.
```
