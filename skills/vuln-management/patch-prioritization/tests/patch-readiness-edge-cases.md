# Patch Readiness and Rollback Evidence Fixtures

These fixtures calibrate the supplemental `PATCH-READY-*` evidence gates in `patch-prioritization`.

```yaml
case: vendor_patch_ready_with_tested_rollback
cve: CVE-2026-10001
asset:
  name: payments-api-01
  environment: production
  installed_version: "2.4.1"
vendor_source:
  advisory_url: https://vendor.example/advisories/CVE-2026-10001
  affected_versions:
    - "<2.4.4"
  fixed_version: "2.4.4"
artifact:
  package_available: true
  package_name: payments-api
  repository: internal-prod-yum
dependency_impact:
  breaking_changes: none
rollback:
  backup_timestamp: "2026-06-06T01:00:00Z"
  method: blue_green_rollback
  tested_at: "2026-06-05T18:00:00Z"
  rpo_minutes: 5
expected_decision: Ready
expected_findings: []
```

```yaml
case: upstream_fix_not_packaged_for_deployed_os
cve: CVE-2026-10002
asset:
  os: ubuntu_22_04
  installed_version: "1.8.0-ubuntu1"
vendor_source:
  advisory_url: https://upstream.example/security/CVE-2026-10002
  fixed_upstream_version: "1.8.3"
artifact:
  distro_package_available: false
  ppa_or_backport: missing
  container_base_image: not_rebuilt
rollback:
  method: snapshot_restore
  tested_at: missing
expected_decision: Blocked
expected_findings:
  - check: PATCH-READY-02
    severity: High
    reason: Upstream fix exists, but no deployable package or rebuilt artifact is available for the deployed OS/image.
  - check: PATCH-READY-06
    severity: Medium
    reason: Rollback method is listed but has no test evidence.
```

```yaml
case: no_patch_workaround_needs_reevaluation
cve: CVE-2026-10003
asset:
  component: legacy_gateway
vendor_source:
  advisory_url: https://vendor.example/advisories/CVE-2026-10003
  fixed_version: none
  vendor_status: investigating
workaround:
  type: disable_vulnerable_feature
  owner: network-team
  monitoring: waf_rule_and_log_alert
  expiry: missing
  reevaluation_date: missing
expected_decision: Workaround Only
expected_findings:
  - check: PATCH-READY-05
    severity: Medium
    reason: Workaround-only remediation lacks expiry and reevaluation cadence.
```

```yaml
case: eol_product_scheduled_as_normal_patch
cve: CVE-2026-10004
asset:
  product: legacy_cms
  installed_version: "7.2"
support:
  lifecycle: eol
  extended_support_contract: missing
  upgrade_path: missing
vendor_source:
  advisory_url: https://vendor.example/eol/security
  fixed_version: not_available_for_7_2
schedule:
  proposed_action: apply_normal_patch
expected_decision: EOL
expected_findings:
  - check: PATCH-READY-04
    severity: High
    reason: Product is EOL with no vendor fix or extended support, but the plan treats it as a normal patch.
```

```yaml
case: container_needs_base_image_and_dependency_rebuild
cve: CVE-2026-10005
asset:
  image: registry.example/app:2026-05-31
  base_image: debian:12.3
  app_dependency: libfoo 3.1.0
vendor_source:
  fixed_base_image: debian:12.5
  fixed_dependency: libfoo 3.1.3
artifact:
  image_rebuild_pipeline: pending
  sbom_updated: false
  registry_image_available: false
dependency_impact:
  integration_tests: not_run
expected_decision: Blocked
expected_findings:
  - check: PATCH-READY-02
    severity: High
    reason: Fixed base image and dependency exist, but no rebuilt deployment image is available.
  - check: PATCH-READY-03
    severity: Medium
    reason: Dependency impact and integration tests are not complete.
```

```yaml
case: firmware_patch_requires_vendor_tac_window
cve: CVE-2026-10006
asset:
  product: edge_firewall
  installed_firmware: "9.1.2"
vendor_source:
  fixed_firmware: "9.1.5"
  advisory_url: https://vendor.example/security/fw-915
artifact:
  firmware_download_available: true
change_blockers:
  maintenance_contract: active
  vendor_tac_window: missing
  ha_failover_test: not_run
rollback:
  method: firmware_downgrade
  tested_at: missing
expected_decision: Blocked
expected_findings:
  - check: PATCH-READY-07
    severity: Medium
    reason: Firmware patch requires a vendor TAC or maintenance window that has not been scheduled.
  - check: PATCH-READY-06
    severity: Medium
    reason: Firmware rollback and HA failover have not been tested.
```

```yaml
case: database_migration_rollback_not_snapshot_safe
cve: CVE-2026-10007
asset:
  application: billing-platform
  installed_version: "5.6.0"
vendor_source:
  fixed_version: "5.6.2"
artifact:
  package_available: true
dependency_impact:
  includes_database_migration: true
rollback:
  method: snapshot_restore
  tested_at: "2026-06-01T12:00:00Z"
  data_migration_reverse_plan: missing
  rpo_minutes: 240
expected_decision: Blocked
expected_findings:
  - check: PATCH-READY-06
    severity: High
    reason: Rollback relies on snapshot restore but the patch includes data migrations with no reverse plan and high RPO impact.
```
