# SEC Materiality, Wiper, Cloud Token, and Deepfake Fixtures

These fixtures calibrate the supplemental incident-response gates in `SKILL.md`.

```yaml
case: sec_materiality_not_evaluable
incident:
  company_type: public_company
  category: data_exfiltration
  affected_services:
    - customer_portal
evidence:
  functional_impact: partial
  financial_impact: missing
  legal_regulatory_impact: missing
  customer_impact: missing
  materiality_owner: missing
  determination_timestamp: missing
expected_decision: Not Evaluable
expected_findings:
  - check: IR-MAT-01
    severity: High
    reason: Potential materiality lacks financial, legal, customer, and reputational evidence.
  - check: IR-MAT-02
    severity: High
    reason: SEC clock owner and materiality determination status are missing.
```

```yaml
case: executive_notice_without_privilege
incident:
  severity: SEV-1
  counsel_involved: true
notification:
  audience: executive_leadership
  privilege_header: missing
  distribution: broad_all_managers
  compromised_channel_assessed: false
expected_decision: Gap
expected_findings:
  - check: IR-MAT-03
    severity: Medium
    reason: Counsel-led SEV-1 notification lacks privilege/work-product handling and need-to-know distribution.
```

```yaml
case: cloud_exfil_network_only
incident:
  category: data_exfiltration
  attacker_access:
    oauth_refresh_token: present
    service_account_key: present
containment:
  endpoint_isolated: true
  token_revocation: missing
  oauth_grant_removal: missing
  service_account_key_rotation: missing
  api_log_validation: missing
expected_decision: Gap
expected_findings:
  - check: IR-MAT-04
    severity: Critical
    reason: Valid cloud/SaaS tokens remain usable after endpoint isolation.
```

```yaml
case: wiper_restore_without_backup_integrity
incident:
  category: destructive_wiper
recovery:
  immutable_backup_status: missing
  backup_malware_scan: missing
  restore_test: missing
  last_known_good: unknown
  persistence_scan: missing
expected_decision: Not Evaluable
expected_findings:
  - check: IR-MAT-05
    severity: High
    reason: Wiper recovery lacks immutable-backup, malware-scan, restore-test, and re-wipe-loop evidence.
```

```yaml
case: deepfake_bec_not_verified
incident:
  category: social_engineering
  artifact: executive_voice_call
  requested_action: urgent_wire_transfer
evidence:
  synthetic_media_review: missing
  out_of_band_verification: missing
  payment_freeze: false
  call_metadata_preserved: false
expected_decision: Gap
expected_findings:
  - check: IR-MAT-06
    severity: High
    reason: Deepfake/BEC indicators lack verification, payment freeze, and artifact preservation.
```

```yaml
case: complete_materiality_wiper_cloud_deepfake_package
incident:
  severity: SEV-1
  company_type: public_company
evidence:
  materiality:
    owner: disclosure_committee
    functional_impact: documented
    financial_impact: documented
    legal_regulatory_impact: documented
    customer_reputation_impact: documented
    determination_timestamp: "2026-06-06T15:00:00Z"
  privilege:
    counsel_led: true
    executive_notice_labeled: attorney_client_privilege_work_product
  cloud_identity:
    refresh_tokens_revoked: true
    oauth_grants_removed: true
    service_account_keys_rotated: true
    api_logs_validated: true
  wiper_recovery:
    immutable_backup_verified: true
    malware_scan_passed: true
    restore_test_passed: true
    last_known_good: "2026-06-05T00:00:00Z"
  synthetic_social_engineering:
    out_of_band_verification: passed
    payment_freeze: true
    artifact_preserved: true
expected_decision: Pass
expected_findings: []
```
