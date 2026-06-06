# Benign: phishing-resistant MFA with token revocation proof

## Scenario

A privileged access workflow uses phishing-resistant MFA, restricts device-code
flow to approved CLI clients, enforces sign-in risk policy, and records a tested
token revocation path. The review includes policy configuration and recent audit
evidence from the IdP and downstream resources.

```yaml
provider: azure-entra-id
account_group: privileged-security-operators
role: security-reader-plus-export
authentication:
  mfa_required: true
  phishing_resistant_methods_required: true
  allowed_methods:
    - fido2
    - certificate_based_authentication
  number_matching_enabled: true
  push_fatigue_detection:
    repeated_denial_alert: enabled
    threshold: 3_denials_in_15_minutes
device_code_flow:
  enabled: true
  approved_clients:
    - azure-cli
    - graph-powershell
  blocked_unknown_clients: true
  monitoring_query: last_30_days_reviewed
risk_policy:
  user_risk_policy_mode: enforce
  sign_in_risk_policy_mode: enforce
  risky_sign_ins_reviewed: true
token_lifecycle:
  refresh_token_revoked_at: 2026-06-07T02:04:00Z
  session_invalidated_at: 2026-06-07T02:05:00Z
  sign_in_frequency_hours: 8
  persistent_browser_session_days: 0
  cae_resource_coverage:
    graph: enabled
    sharepoint: enabled
    custom_admin_api: compensating_short_token_lifetime
incident_test:
  user_disabled_at: 2026-06-07T02:03:00Z
  post_disable_token_replay: denied
  downstream_app_access_after_revocation: denied
  validation_window: last_30_days
review_decision:
  disposition: acceptable
  evidence_owner: identity-security@example.com
  next_validation_date: 2026-07-07
```

## Expected Assessment

Do not flag `IAM-TOKEN-01` through `IAM-TOKEN-08` when the review proves approved
device-code clients, phishing-resistant MFA, enforced risk policies, bounded
session lifetime, refresh-token revocation, CAE or compensating resource coverage,
and denied post-revocation token replay.
