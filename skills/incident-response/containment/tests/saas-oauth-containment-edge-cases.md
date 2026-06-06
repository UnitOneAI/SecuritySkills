# SaaS and OAuth Containment Edge Cases

These fixtures verify that containment does not stop at password reset when SaaS, OAuth, mailbox, service-principal, or cloud session persistence can keep access alive.

```yaml
case_id: CONTAIN-OAUTH-01
title: BEC password reset leaves malicious OAuth consent active
incident_path: BEC
platform: Microsoft 365
initial_actions:
  password_reset: complete
  user_sessions_revoked: complete
oauth_grants:
  app_id: 11111111-2222-3333-4444-555555555555
  app_name: invoice-sync
  scopes:
    - Mail.Read
    - offline_access
  consent_type: delegated
  grant_revoked: false
post_reset_activity:
  api_calls_after_password_reset: true
  last_call: "2026-06-06T03:22:00Z"
expected_containment:
  action: revoke_oauth_grant_and_refresh_tokens
  validation: "No post-revocation Graph API calls from the app."
  residual_risk: "Password reset alone is incomplete containment."
```

```yaml
case_id: CONTAIN-OAUTH-02
title: Tenant-wide malicious consent app requires per-app containment
incident_path: oauth_consent_abuse
platform: Entra ID
oauth_app:
  publisher_verified: false
  consent_type: admin_tenant_wide
  risky_scopes:
    - Files.Read.All
    - Mail.ReadWrite
    - Directory.Read.All
affected_users: 740
revocation_plan:
  scope: per_app
  disable_enterprise_app: true
  remove_admin_consent: true
  review_app_role_assignments: true
expected_validation:
  app_sign_in_status: blocked
  previous_refresh_tokens_rejected: true
```

```yaml
case_id: CONTAIN-OAUTH-03
title: Mailbox forwarding and delegate rules survive session revocation
incident_path: BEC
platform: Exchange Online
mailbox_persistence:
  forwarding_smtp_address: attacker@example.net
  inbox_rules:
    - name: move invoices
      action: forward_and_delete
  delegates:
    - external.partner@example.org
initial_actions:
  password_reset: complete
  session_revocation: complete
  mailbox_rules_removed: false
expected_containment:
  action: remove_forwarding_rules_delegates_and_external_shares
  validation: "Mailbox audit shows no forwarding, delegate access, or external share activity after cleanup."
```

```yaml
case_id: CONTAIN-OAUTH-04
title: SaaS admin session remains active after IdP password reset
incident_path: idp_admin_compromise
platform: Okta_and_Salesforce
affected_admin:
  user: admin@example.com
  idp_password_reset: true
saas_sessions:
  salesforce_admin_session_active: true
  slack_owner_session_active: true
  github_org_owner_session_active: unknown
expected_containment:
  scope: tenant_wide_admin_sessions
  actions:
    - revoke_saas_admin_sessions
    - force_reauthentication
    - verify_admin_audit_logs
  residual_risk: "Unknown SaaS session APIs require monitored residual-risk window."
```

```yaml
case_id: CONTAIN-OAUTH-05
title: Service principal secret leak continues cloud API access
incident_path: cloud_control_plane
platform: Azure
service_principal:
  app_id: 99999999-aaaa-bbbb-cccc-dddddddddddd
  role_assignments:
    - Contributor
  leaked_client_secret: true
  secret_removed: false
  certificate_credentials_present: true
api_activity:
  post_user_password_reset_activity: true
expected_containment:
  action: rotate_service_principal_credentials_and_review_role_assignments
  validation: "No sign-ins with old secret or certificate thumbprint after rotation."
```

```yaml
case_id: CONTAIN-OAUTH-06
title: Cloud STS token cannot be revoked immediately and needs residual monitoring
incident_path: cloud_sts_token_theft
platform: AWS
sts_session:
  role: arn:aws:iam::123456789012:role/prod-admin
  issued_at: "2026-06-06T01:00:00Z"
  expires_at: "2026-06-06T13:00:00Z"
  immediate_revocation_supported: false
containment_actions:
  disable_source_access_key: true
  tighten_role_policy: true
  alert_on_session_activity_until_expiry: true
expected_containment:
  scope: residual_risk_monitored
  validation: "CloudTrail shows no actions from the compromised session until expiry."
```

```yaml
case_id: CONTAIN-OAUTH-07
title: File-sharing links remain after OAuth app revocation
incident_path: saas_token_theft
platform: Google Workspace
oauth_revoked: true
file_exfil_paths:
  anonymous_links:
    count: 18
    revoked: false
  external_collaborators:
    count: 6
    reviewed: false
  drive_export_jobs_after_revocation: true
expected_containment:
  action: revoke_file_sharing_links_and_external_collaborators
  validation: "Drive audit and DLP logs show no new downloads or external sharing after cleanup."
```
