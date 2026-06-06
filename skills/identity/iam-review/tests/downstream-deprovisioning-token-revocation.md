# Downstream Deprovisioning and Token Revocation Edge Cases

These fixtures calibrate the `iam-review` downstream deprovisioning gate. A review should verify relying-party account state, token/session revocation, app-local authorization, and owned machine identities before marking lifecycle removal complete.

## Vulnerable: IdP Disabled But Tokens Still Active

```yaml
case: idp-disabled-tokens-still-active
lifecycle_event:
  type: termination
  source_of_truth: hris
  idp_user_status: disabled
  scim_patch_sent: true
downstream_app:
  local_user_active: false
  browser_sessions_active: true
  oauth_refresh_tokens_active: true
  personal_api_tokens_active: true
  mobile_device_tokens_active: true
expected_result:
  finding_codes:
    - IAM-DEPROV-01
    - IAM-DEPROV-02
  decision: Fail
  severity: Critical
  reason: Effective authentication remains possible after IdP disablement.
```

## Vulnerable: Group Removal Not Propagated To App-Local Role

```yaml
case: group-removal-app-local-role-cache
access_change:
  idp_group_removed: engineering-prod-admin
  scim_user_active: true
downstream_app:
  scim_groups_synced: false
  app_local_role_cache:
    role: prod_admin
    expires_in_hours: 24
  last_full_sync: "2026-06-01T00:00:00Z"
expected_result:
  finding_codes:
    - IAM-DEPROV-03
  decision: Fail
  severity: High
  reason: The IdP group change has not removed effective app-local authorization.
```

## Vulnerable: Owner Termination Leaves Machine Identity Active

```yaml
case: owner-terminated-machine-identity-active
service_account:
  owner_user: alice@example.invalid
  owner_status: terminated
  cloud_role: prod-deploy
  oidc_trust_policy: still_allows_repo_branch
  static_key_count: 2
  last_key_use: "2026-06-06T09:55:00Z"
  owner_reassignment: missing
  breakglass_exception: undocumented
expected_result:
  finding_codes:
    - IAM-DEPROV-05
  decision: Fail
  severity: High
  reason: Human owner lifecycle did not trigger service account, OIDC trust, key, and exception review.
```

## Vulnerable: Non-SCIM App Without Compensating Evidence

```yaml
case: non-scim-app-no-compensating-control
application:
  name: legacy-crm
  supports_sso: true
  supports_scim: false
compensating_control:
  manual_disable_checklist: missing
  local_account_state: unknown
  session_revocation: unknown
  token_revocation: unknown
  reconciliation_date: missing
expected_result:
  finding_codes:
    - IAM-DEPROV-04
    - IAM-DEPROV-08
  decision: Not Evaluable
  severity: Medium
  reason: SSO-only integration cannot be passed without local account, token, session, and reconciliation evidence.
```

## Vulnerable: Break-Glass Exception Never Rotated

```yaml
case: breakglass-post-use-rotation-missing
breakglass_account:
  owner: security-operations
  emergency_use_date: "2026-06-02T13:00:00Z"
  expiry: missing
  monitoring: enabled
  test_evidence: present
  post_use_password_rotation: missing
  post_use_token_rotation: missing
  approval_record: present
expected_result:
  finding_codes:
    - IAM-DEPROV-06
  decision: Partial
  severity: High
  reason: Emergency access was monitored but not time-bounded or rotated after use.
```

## Benign: Complete Downstream Deprovisioning Evidence

```yaml
case: complete-downstream-deprovisioning
identity_lifecycle:
  source_of_truth: okta
  provisioning_protocol: scim
  termination_event: user-disabled
  event_id: evt-789
  event_timestamp: "2026-06-06T10:12:00Z"
downstream_apps:
  - name: payroll-saas
    scim_user_active: false
    app_sessions_revoked: true
    oauth_refresh_tokens_revoked: true
    api_tokens_revoked: true
    mobile_tokens_revoked: true
    group_membership_removed: true
    app_local_roles_removed: true
    audit_event_id: audit-456
machine_identities:
  owned_service_accounts_reassigned: true
  deploy_keys_revoked_or_reassigned: true
  oidc_trust_policies_reviewed: true
  static_keys_rotated: true
verification:
  residual_access: none_found
  reconciled_at: "2026-06-06T10:20:00Z"
expected_result:
  finding_codes: []
  decision: Pass
  severity: Informational
  reason: IdP, relying-party, token/session, role, and machine-identity evidence all show access removal.
```
