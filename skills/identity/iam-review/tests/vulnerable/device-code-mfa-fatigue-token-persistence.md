# Vulnerable: device-code MFA fatigue with persistent tokens

## Scenario

An organization reports that MFA and Conditional Access are enabled for all users.
A privileged analyst account can still authenticate through device-code flow, approve
repeated push prompts without number matching, and retain refresh tokens after the
account is disabled during an incident. The review closes the posture as acceptable
because the IdP dashboard shows MFA coverage above 95 percent.

```yaml
provider: azure-entra-id
account: privileged-analyst@example.com
role: security-reader-plus-export
authentication:
  mfa_required: true
  phishing_resistant_methods_required: false
  number_matching_enabled: false
  mfa_push_denials_last_24h: 14
  approved_after_denial_burst: true
device_code_flow:
  enabled: true
  approved_clients: []
  monitoring_query: missing
risk_policy:
  user_risk_policy_mode: report_only
  sign_in_risk_policy_mode: report_only
  risky_sign_ins_reviewed: false
token_lifecycle:
  refresh_token_revoked_at: null
  session_invalidated_at: null
  persistent_browser_session_days: 30
  cae_resource_coverage:
    graph: enabled
    legacy_sharepoint: unknown
    custom_admin_api: not_supported
incident_test:
  user_disabled_at: 2026-06-07T01:30:00Z
  post_disable_token_replay: allowed
  downstream_app_access_after_revocation: allowed
review_decision:
  disposition: acceptable
  reason: tenant-wide MFA dashboard shows broad coverage
```

## Expected Findings

- `IAM-TOKEN-01`: Device-code flow is enabled without an approved client list or monitoring evidence.
- `IAM-TOKEN-02`: MFA push approval lacks number matching and fatigue detection despite repeated denial bursts.
- `IAM-TOKEN-03`: User and sign-in risk policies are report-only and risky sign-ins are not reviewed.
- `IAM-TOKEN-04`: Refresh tokens and persistent sessions remain valid after account disablement.
- `IAM-TOKEN-05`: CAE coverage is partial and not proven for the downstream admin resource.
- `IAM-TOKEN-06`: Persistent browser session lifetime exceeds the risk of privileged export access.
- `IAM-TOKEN-08`: Post-revocation validation shows token replay and downstream access still allowed.

## Expected Assessment

Do not accept tenant-wide MFA coverage as sufficient. The assessment must require
policy enforcement mode, device-code controls, MFA fatigue evidence, refresh-token
revocation proof, CAE resource coverage, and a post-revocation access test.
