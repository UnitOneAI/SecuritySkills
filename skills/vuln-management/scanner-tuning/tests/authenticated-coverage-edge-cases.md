# Authenticated Scan Coverage Edge Cases

These fixtures verify that scanner-tuning treats authenticated scan success as a gate before suppressions, severity downgrades, or "cleaner scan" claims.

```yaml
case_id: SCANNER-AUTH-01
title: Passed credentialed coverage allows bounded suppression review
scanner: Tenable
policy: weekly-prod-credentialed
asset_population:
  total: 420
  authenticated: 412
  failed_auth: 3
  unreachable: 5
  excluded: 0
feed_engine:
  plugin_feed_date: "2026-06-05"
  engine_version: "10.9.1"
  scan_completed: true
platform_coverage:
  windows:
    auth_method: WinRM
    privilege_reached: local_admin
    skipped_checks: []
  linux:
    auth_method: ssh_key_sudo
    privilege_reached: root_via_sudo
    skipped_checks: []
coverage_state: Passed
tuning_decision:
  action: allow_asset_scoped_suppression_review
  reason: "Authenticated coverage is above threshold and failed/unreachable assets are documented outside the suppression scope."
```

```yaml
case_id: SCANNER-AUTH-02
title: Linux sudo requires tty and blocks package-level downgrades
scanner: Qualys
policy: linux-prod-full
asset_population:
  total: 86
  authenticated: 71
  failed_auth: 12
  unreachable: 3
  excluded: 0
platform_coverage:
  linux:
    auth_method: ssh_key_sudo
    privilege_reached: ssh_only
    denied_commands:
      - rpm -qa
      - dpkg-query -W
    skipped_checks:
      - local_package_checks
      - kernel_patch_checks
failure_evidence:
  error: "sudo: sorry, you must have a tty to run sudo"
  last_successful_credential_check: "2026-05-21"
coverage_state: Failed
tuning_decision:
  action: block_suppression_or_downgrade
  reason: "Scanner cannot prove installed package or kernel patch state when sudo/local checks fail."
```

```yaml
case_id: SCANNER-AUTH-03
title: Windows WinRM succeeds but registry and WMI checks are blocked
scanner: Rapid7 InsightVM
policy: windows-server-authenticated
asset_population:
  total: 130
  authenticated: 122
  failed_auth: 8
  unreachable: 0
platform_coverage:
  windows:
    auth_method: WinRM
    privilege_reached: remote_login
    skipped_checks:
      - registry_patch_checks
      - WMI_hotfix_inventory
      - local_policy_checks
failure_evidence:
  error: "Access denied opening HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
  credential_source: CyberArk
  vault_retrieval_status: success
coverage_state: Partial
tuning_decision:
  action: asset_limited_only
  reason: "Remote login alone is not enough to downgrade Windows package or registry findings."
```

```yaml
case_id: SCANNER-AUTH-04
title: Stale cloud agent makes missing findings non-evaluable
scanner: Qualys Cloud Agent
policy: cloud-agent-continuous
asset_population:
  total: 2500
  authenticated: 2350
  failed_auth: 0
  unreachable: 0
  stale_agents: 150
agent_evidence:
  stale_threshold_hours: 72
  oldest_last_check_in: "2026-05-19T04:11:00Z"
  skipped_checks:
    - runtime_package_inventory
    - configuration_policy_checks
coverage_state: Partial
tuning_decision:
  action: block_cleaner_scan_claim_for_stale_assets
  reason: "Agents that stopped checking in cannot prove current package or configuration state."
```

```yaml
case_id: SCANNER-AUTH-05
title: SNMPv2 network scan provides inventory but insufficient local evidence
scanner: Greenbone
policy: network-device-monthly
asset_population:
  total: 64
  authenticated: 64
  failed_auth: 0
  unreachable: 0
platform_coverage:
  network_devices:
    auth_method: SNMPv2c
    privilege_reached: read_only_inventory
    skipped_checks:
      - running_config_review
      - firmware_file_integrity
      - privileged_command_output
credential_source:
  source: scanner_native_store
  rotation_age_days: 420
coverage_state: Partial
tuning_decision:
  action: require_uncertainty_note
  reason: "SNMP inventory can support asset identification but not privileged configuration or firmware suppression."
```

```yaml
case_id: SCANNER-AUTH-06
title: Unknown scan currency blocks severity override
scanner: Nessus
policy: internal-quarterly
asset_population:
  total: 310
  authenticated: null
  failed_auth: null
  unreachable: null
feed_engine:
  plugin_feed_date: null
  engine_version: null
  scan_completed: unknown
coverage_state: Unknown
severity_override_request:
  cve: CVE-2025-12345
  direction: down
  justification: "No exploit observed and finding volume dropped after retune."
tuning_decision:
  action: block_override
  reason: "Coverage, scanner/feed currency, and completion state are missing."
```

```yaml
case_id: SCANNER-AUTH-07
title: Unreachable targets require a remediation owner before final tuning
scanner: Qualys
policy: pci-internal
asset_population:
  total: 96
  authenticated: 83
  failed_auth: 2
  unreachable: 11
  excluded: 0
scan_window:
  start: "2026-06-05T02:00:00Z"
  end: "2026-06-05T05:00:00Z"
  completed: true
coverage_state: Partial
remediation_owner:
  team: network-operations
  due_date: "2026-06-12"
tuning_decision:
  action: block_final_program_rating
  reason: "A passed/tuned classification cannot be assigned until unreachable targets are documented, excluded, or successfully scanned."
```
