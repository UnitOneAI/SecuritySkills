# Cloud Identity and Metadata Containment Fixtures

These fixtures calibrate cloud identity, metadata-service, API throttling, volatile-evidence, and reconnection integrity containment decisions.

```yaml
case: power_off_before_volatile_evidence
incident:
  severity: SEV-1
  type: malware_without_confirmed_wiper
  affected_asset: production_vm
proposed_containment:
  action: power_off
evidence:
  memory_capture: missing
  process_listing: missing
  network_connections: missing
  vm_snapshot_or_suspend_option: available
expected_decision: Gap
expected_findings:
  - check: CONT-CLOUD-01
    severity: High
    reason: Destructive containment was selected before volatile evidence status was recorded.
```

```yaml
case: saas_admin_token_network_only
incident:
  vector: compromised_saas_admin
  attacker_access:
    valid_refresh_token: true
    oauth_app_grant: present
proposed_containment:
  action: isolate_admin_laptop
evidence:
  refresh_token_revocation: missing
  oauth_grant_revocation: missing
  tenant_signout_log: missing
expected_decision: Gap
expected_findings:
  - check: CONT-CLOUD-02
    severity: Critical
    reason: Network isolation does not revoke SaaS sessions, OAuth grants, or refresh tokens.
```

```yaml
case: aws_workload_compromise_imds_not_checked
incident:
  platform: aws_ec2
  affected_workload: payments_api
  suspected_ssrf: true
evidence:
  imds_version: missing
  hop_limit: missing
  route_or_firewall_block: missing
  role_credentials_review: missing
  cloudtrail_sts_review: missing
expected_decision: Not Evaluable
expected_findings:
  - check: CONT-CLOUD-03
    severity: High
    reason: Metadata-service credential blast radius and IMDS isolation evidence are missing.
  - check: CONT-CLOUD-06
    severity: Medium
    reason: Missing IMDS and credential evidence must be called out as Not Evaluable.
```

```yaml
case: api_exfiltration_should_throttle
incident:
  type: automated_api_scraping
  token_status: valid_partner_key
  business_service: customer_portal
proposed_containment:
  action: global_api_block
evidence:
  rate_limit_option: available
  scoped_key_revocation: available
  gateway_logging: active
  legal_approval_for_observation: present
expected_decision: Partial
expected_findings:
  - check: CONT-CLOUD-04
    severity: Medium
    reason: Throttling and scoped key containment can preserve telemetry while limiting exfiltration.
```

```yaml
case: reconnect_without_integrity_scan
incident:
  affected_asset: quarantined_server
rollback_request: reconnect_to_production
evidence:
  edr_scan: missing
  persistence_review: missing
  local_admin_review: present
  credential_session_review: partial
  config_drift_check: missing
  telemetry_restored: false
expected_decision: Not Evaluable
expected_findings:
  - check: CONT-CLOUD-05
    severity: High
    reason: Reconnection lacks post-containment integrity validation.
  - check: CONT-CLOUD-06
    severity: Medium
    reason: Missing rollback evidence must hold the asset in Not Evaluable status.
```

```yaml
case: complete_cloud_identity_imds_containment
incident:
  platform: aws_ec2_and_saas
  severity: SEV-1
actions:
  host_network_isolation: edr_network_containment
  volatile_evidence: memory_process_netstat_captured_and_hashed
  refresh_token_revocation: complete
  oauth_grant_revocation: complete
  imds_controls:
    imdsv2_required: true
    hop_limit: 1
    affected_role_credentials_reviewed: true
  api_abuse:
    affected_key_revoked: true
    gateway_quota_reduced: true
  reconnection_gate:
    edr_scan: pass
    persistence_review: pass
    credential_session_review: pass
    config_drift_check: pass
    telemetry_restored: true
expected_decision: Pass
expected_findings: []
```
