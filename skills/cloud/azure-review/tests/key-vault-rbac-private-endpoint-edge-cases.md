# Key Vault RBAC and Private Endpoint Edge Cases

These fixtures verify that `azure-review` distinguishes Key Vault control presence from effective least-privilege RBAC and private access enforcement.

```yaml
case_id: AZ-KV-01
title: RBAC and private endpoint are enforced with high-confidence evidence
key_vault:
  enable_rbac_authorization: true
  public_network_access_enabled: false
  purge_protection_enabled: true
rbac:
  live_role_export: present
  assignments:
    - principal: app-managed-identity
      role: Key Vault Secrets User
      scope: vault
      owner: platform-security
      ticket: CHG-9021
private_access:
  private_endpoint_subresource: vault
  private_dns_zone_group: privatelink.vaultcore.azure.net
  client_resolution: private_ip_observed
expected_classification:
  cis_8_6: Pass
  cis_8_7: Pass
  confidence: High
  reason: "RBAC, live assignment export, public access disablement, private DNS, and client resolution evidence are all present."
```

```yaml
case_id: AZ-KV-02
title: RBAC boolean hides broad data-plane administrator assignment
key_vault:
  enable_rbac_authorization: true
rbac:
  live_role_export: present
  assignments:
    - principal: all-engineers
      principal_type: group
      role: Key Vault Administrator
      scope: vault
      owner: missing
      expiry: missing
expected_classification:
  cis_8_6: Fail
  severity: High
  confidence: High
  reason: "RBAC is enabled, but a broad group has full data-plane administration without owner, expiry, or review evidence."
```

```yaml
case_id: AZ-KV-03
title: RBAC migration drift is not evaluable without live role export
key_vault:
  enable_rbac_authorization: true
terraform:
  access_policy_resources: present
rbac:
  live_role_export: missing
  portal_assignments: unknown
expected_classification:
  cis_8_6: Not Evaluable
  not_evaluable_reason: AZ-KV-NE-01
  reason: "IaC alone cannot prove that access policies, portal assignments, and live RBAC state are aligned after migration."
```

```yaml
case_id: AZ-KV-04
title: Private endpoint exists but public network path remains open
key_vault:
  public_network_access_enabled: true
  network_acls:
    default_action: Allow
    bypass: AzureServices
private_access:
  private_endpoint_subresource: vault
  private_dns_zone_group: privatelink.vaultcore.azure.net
expected_classification:
  cis_8_7: Fail
  severity: High
  confidence: High
  reason: "Private endpoint presence does not enforce private access while public access and default allow are still enabled."
```

```yaml
case_id: AZ-KV-05
title: Private endpoint lacks DNS and client-resolution proof
key_vault:
  public_network_access_enabled: false
private_access:
  private_endpoint_subresource: vault
  private_dns_zone_group: missing
  vnet_link: missing
  client_resolution: missing
expected_classification:
  cis_8_7: Not Evaluable
  not_evaluable_reason: AZ-KV-NE-05
  reason: "The private endpoint exists, but clients may still resolve or route incorrectly without DNS and client-side evidence."
```

```yaml
case_id: AZ-KV-06
title: Trusted services bypass is accepted without supported service justification
key_vault:
  public_network_access_enabled: true
  network_acls:
    default_action: Deny
    bypass: AzureServices
exception_evidence:
  supported_service_path: missing
  owner: missing
  ticket: missing
expected_classification:
  cis_8_7: Not Evaluable
  not_evaluable_reason: AZ-KV-NE-06
  reason: "AzureServices bypass needs a specific supported service path and exception evidence."
```

```yaml
case_id: AZ-KV-07
title: Hosted CI deployment exception has no expiry or audit trail
key_vault:
  public_network_access_enabled: true
  network_acls:
    default_action: Deny
deployment_exception:
  reason: hosted_ci_agent_needs_secret_access
  owner: release-engineering
  expiry: missing
  audit_log: missing
  compensating_control: missing
expected_classification:
  cis_8_7: Not Evaluable
  not_evaluable_reason: AZ-KV-NE-07
  reason: "Temporary public access for deployment agents requires expiry, audit log, and compensating controls."
```
