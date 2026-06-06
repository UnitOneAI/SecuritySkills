# Authentication Recovery and Exception Path Edge Cases

These fixtures verify that iam-review does not treat normal sign-in MFA as complete coverage when recovery, enrollment, token, consent, or emergency paths have weaker assurance.

```yaml
case_id: IAM-RECOVERY-01
title: Password reset bypasses MFA through helpdesk callback weakness
identity_provider: Entra ID
path: password_reset
population:
  users: 1840
  privileged_users: 42
normal_sign_in:
  mfa_required: true
  phishing_resistant_for_admins: true
recovery_flow:
  identity_proofing: employee_id_and_manager_name
  second_factor_required: false
  approval_record_required: false
  post_reset_token_revocation: false
  audit_log_source: helpdesk_ticket
expected_finding:
  id: IAM-AUTH-11
  severity: High
  disposition: gap
  reason: "Password reset can restore access with weaker assurance than normal sign-in MFA."
```

```yaml
case_id: IAM-RECOVERY-02
title: MFA re-enrollment from active session allows attacker device registration
identity_provider: Okta
path: mfa_reenrollment
population:
  groups:
    - all_employees
normal_sign_in:
  mfa_required: true
  allowed_methods:
    - WebAuthn
    - push
mfa_reenrollment:
  requires_existing_factor: false
  requires_admin_approval: false
  user_notification: email_only
  new_device_quarantine_hours: 0
  risk_signal_review: absent
expected_finding:
  id: IAM-AUTH-13
  severity: High
  disposition: gap
  reason: "A stolen password or session can register a new authenticator without independent approval."
```

```yaml
case_id: IAM-RECOVERY-03
title: Break-glass account is intentionally excluded but controlled
identity_provider: Entra ID
path: break_glass
accounts:
  count: 2
  roles:
    - Global Administrator
conditional_access:
  excluded_from_mfa: true
compensating_controls:
  hardware_credential_custody: dual_control_safe
  sign_in_alerting: security_pager_and_siem
  last_tested: "2026-05-15"
  password_rotation_after_test: true
  network_location_restriction: true
expected_finding:
  id: IAM-AUTH-20
  severity: Informational
  disposition: pass_with_exception
  reason: "Emergency bypass is documented, monitored, tested, and compensated."
```

```yaml
case_id: IAM-RECOVERY-04
title: Legacy protocol exception bypasses conditional access MFA
identity_provider: Microsoft 365
path: legacy_protocol
normal_sign_in:
  conditional_access_mfa: enforced
legacy_protocols:
  pop3: disabled
  imap: disabled
  smtp_auth:
    enabled: true
    exception_group: finance-shared-mailboxes
  app_passwords: enabled
evidence:
  sign_in_logs_show_basic_auth: true
  exception_owner: missing
expected_finding:
  id: IAM-AUTH-17
  severity: High
  disposition: gap
  reason: "SMTP/app-password exception allows access outside the MFA-enforced sign-in path."
```

```yaml
case_id: IAM-RECOVERY-05
title: Refresh tokens persist after recovery and risk changes
identity_provider: Google Workspace
path: session_token
session_policy:
  max_session_hours: 720
  remembered_device_days: 90
  risk_change_reauth: false
  token_revocation_after_password_reset: false
recovery_event:
  password_reset_date: "2026-06-01"
  existing_oauth_tokens_remain_valid: true
expected_finding:
  id: IAM-AUTH-18
  severity: Medium
  disposition: gap
  reason: "Recovery does not invalidate existing sessions or force reauthentication after risk changes."
```

```yaml
case_id: IAM-RECOVERY-06
title: Admin consent allows tenant-wide OAuth grants without review
identity_provider: Entra ID
path: admin_consent
oauth_policy:
  users_can_consent: false
  admins_can_grant_tenant_wide_consent: true
  security_review_required: false
  publisher_verification_required: false
  app_risk_scoring: absent
recent_grant:
  app_name: reporting-exporter
  scopes:
    - Mail.Read
    - Files.Read.All
  approval_ticket: missing
expected_finding:
  id: IAM-AUTH-19
  severity: High
  disposition: gap
  reason: "Tenant-wide OAuth grant can bypass least-privilege and MFA expectations without app-risk review."
```

```yaml
case_id: IAM-RECOVERY-07
title: External vendor IdP recovery assurance is unknown
identity_provider: Okta
path: external_idp
federation:
  vendor_domain: vendor.example
  guest_count: 76
  cross_tenant_trust_enabled: true
  home_tenant_mfa_trusted: true
  recovery_policy_evidence: missing
  vendor_helpdesk_process: unknown
expected_finding:
  id: IAM-AUTH-21
  severity: Medium
  disposition: not_evaluable
  reason: "Local policy trusts external MFA, but the vendor recovery path assurance is not evidenced."
```
