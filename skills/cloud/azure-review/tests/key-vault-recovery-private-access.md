# Key Vault Recovery and Private Access Fixtures

These fixtures calibrate supplemental `AZ-KV-REC-*` and `AZ-KV-NET-*` evidence checks in `azure-review`.

```yaml
case: private_recoverable_production_vault
vault:
  name: prod-payments-kv
  data_classification: high_value_cmk
evidence_source:
  terraform: present
  cli_inventory: present
recovery:
  soft_delete_retention_days: 90
  purge_protection_enabled: true
  delete_and_purge_separation: true
  purge_alerting: true
network:
  public_network_access_enabled: false
  firewall_default_action: Deny
  trusted_services_bypass: none
  private_endpoint:
    subresource: vault
    connection_state: Approved
    target_vault: prod-payments-kv
  private_dns:
    zone: privatelink.vaultcore.azure.net
    vnet_linked: true
    client_lookup_returns_private_ip: true
expected_decision: Pass
expected_findings: []
```

```yaml
case: private_endpoint_but_public_access_enabled
vault:
  name: shared-prod-kv
  data_classification: production_secrets
recovery:
  soft_delete_retention_days: 90
  purge_protection_enabled: true
network:
  public_network_access_enabled: true
  firewall_default_action: Allow
  private_endpoint:
    subresource: vault
    connection_state: Approved
  private_dns:
    zone: privatelink.vaultcore.azure.net
    vnet_linked: true
expected_decision: Fail
expected_findings:
  - check: AZ-KV-NET-01
    severity: High
    reason: A private endpoint exists, but public network access and firewall allow remain broadly enabled.
```

```yaml
case: private_endpoint_missing_dns_link
vault:
  name: customer-data-kv
network:
  public_network_access_enabled: false
  firewall_default_action: Deny
  private_endpoint:
    subresource: vault
    connection_state: Approved
  private_dns:
    zone: missing
    vnet_linked: false
    client_lookup_returns_private_ip: false
expected_decision: Fail
expected_findings:
  - check: AZ-KV-NET-04
    severity: High
    reason: The private endpoint is approved, but private DNS zone linkage and client lookup evidence are missing.
```

```yaml
case: purge_protection_disabled_minimal_retention
vault:
  name: prod-app-kv
  data_classification: production_secrets
evidence_source:
  terraform: present
recovery:
  soft_delete_retention_days: 7
  purge_protection_enabled: false
  exception:
    owner: missing
    rationale: missing
network:
  public_network_access_enabled: false
expected_decision: Fail
expected_findings:
  - check: AZ-KV-REC-02
    severity: High
    reason: Production vault has minimal soft-delete retention without approved exception evidence.
  - check: AZ-KV-REC-03
    severity: High
    reason: Purge protection is disabled for a production secrets vault.
```

```yaml
case: imported_vault_iac_omits_live_recovery_state
vault:
  name: imported-legacy-kv
evidence_source:
  terraform_import: present
  cli_inventory: missing
  azure_policy_export: missing
recovery:
  soft_delete_retention_days: unknown
  purge_protection_enabled: unknown
network:
  public_network_access_enabled: unknown
expected_decision: Not Evaluable
expected_findings:
  - check: AZ-KV-REC-01
    severity: Medium
    reason: Imported vault IaC is present, but live retention, purge protection, and network state evidence is missing.
```

```yaml
case: scoped_trusted_service_exception
vault:
  name: cmk-analytics-kv
network:
  public_network_access_enabled: true
  firewall_default_action: Deny
  trusted_services_bypass:
    enabled: true
    services:
      - AzureStorage
    owner: data_platform
    expiry: "2026-09-30"
    monitoring: diagnostic_logs_and_alerts
  private_endpoint:
    subresource: vault
    connection_state: Approved
expected_decision: Pass
expected_findings: []
```

```yaml
case: pending_private_endpoint_and_no_client_path
vault:
  name: finance-kv
network:
  public_network_access_enabled: false
  firewall_default_action: Deny
  private_endpoint:
    subresource: vault
    connection_state: Pending
  private_dns:
    zone: privatelink.vaultcore.azure.net
    vnet_linked: true
  client_path:
    workload_subnet: missing
    route_evidence: missing
    resolver_evidence: missing
expected_decision: Not Evaluable
expected_findings:
  - check: AZ-KV-NET-03
    severity: Medium
    reason: Private endpoint exists but is not approved.
  - check: AZ-KV-NET-05
    severity: Medium
    reason: Client network path evidence is missing, so private-only access cannot be proven.
```
