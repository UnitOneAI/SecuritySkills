# Privileged activation and session edge cases

These cases calibrate `privileged-access` reviews so eligible access, active privilege, session persistence, and break-glass lifecycle evidence are not collapsed into one finding.

## Benign: eligible assignment with strong activation controls

```yaml
platform: Microsoft Entra PIM
principal: alex@example.com
role: Privileged Role Administrator
assignment_state: eligible
activation:
  phishing_resistant_mfa: required
  approval: required
  justification: required
  maximum_duration: 2h
evidence:
  permanent_active_assignment: none
  active_sessions: none
  last_activation: 2026-05-29T10:15:00Z
  activation_log_export: present
```

Expected result: do not report this as standing active administrator access. Record it as eligible JIT access and verify the activation log, maximum duration, and no-current-session evidence.

## Vulnerable: permanent active admin hidden behind a JIT label

```yaml
platform: Microsoft Entra PIM
principal: blair@example.com
role: Global Administrator
assignment_state: permanent_active
activation:
  approval: not_required
  maximum_duration: none
evidence:
  report_label: "protected by PIM"
  current_active_assignment: true
```

Expected result: report `PAM-ACT-02` because the JIT/PIM label does not mitigate a permanent active administrator assignment.

## Vulnerable: revocation blocks future use but not current sessions

```yaml
platform: AWS IAM Identity Center
principal: chris@example.com
permission_set: ProductionAdmin
access_portal_session_duration: 30d
permission_set_session_duration: 12h
revocation_test:
  user_removed_from_admin_group: 2026-06-03T09:00:00Z
  existing_account_session_terminated: false
  emergency_session_kill_runbook: missing
```

Expected result: report `PAM-ACT-07` and record the actual revocation behavior. Future activation removal is not equivalent to termination of existing privileged sessions.

## Vulnerable: cloud-native PAM grant lifecycle is policy-only

```yaml
platform: Google Cloud Privileged Access Manager
entitlement: production-database-admin
approval_policy: configured
missing_evidence:
  - grant_request_log
  - approval_or_denial_log
  - active_grant_end_time
  - audit_log_sink
  - retention_period
```

Expected result: report `PAM-ACT-04` or mark the control not evaluable when only entitlement configuration is available and grant lifecycle evidence is missing.

## Vulnerable: break-glass test proves login only

```yaml
account: break-glass-prod-admin
test_result:
  credential_login: success
  privileged_action_scope: not_recorded
  alert_fired: unknown
  session_recording: missing
  active_session_terminated: unknown
  credential_rotated_after_use: false
  post_use_review: missing
```

Expected result: report `PAM-BG-11` and require a full Break-Glass Test Evidence row before treating the procedure as tested.
