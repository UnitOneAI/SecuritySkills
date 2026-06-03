# CIS Azure Foundations Benchmark -- Version-Aware Checklist

This file contains detailed checklist guidance for the Azure Security Posture Review skill. See [SKILL.md](SKILL.md) for the main process and report format.

The current default is **CIS Microsoft Azure Foundations Benchmark v6.0.0-aware** reporting. CIS Azure v2.1.0 remains supported only as explicit legacy mode. Entra ID controls are routed to Microsoft 365/Entra scope unless legacy mode or an explicit Microsoft 365 benchmark scope is declared.

---

## Benchmark Preflight

Record these fields before evaluating controls:

| Field | Required Evidence |
|-------|-------------------|
| `benchmark_version` | `CIS Microsoft Azure Foundations Benchmark v6.0.0`, or explicit legacy version such as `v2.1.0`. |
| `benchmark_source_date` | Date of CIS update, CIS PDF/DOCX, NIST NCP record, or exported benchmark evidence. |
| `evidence_source` | Defender for Cloud, Azure Policy, Azure CLI, Terraform, Bicep, ARM, manual evidence, or mixed. |
| `legacy_baseline` | `true` only when the user requested a historical benchmark. Include the reason. |
| `entra_scope_handling` | `excluded`, `included-as-m365`, `legacy-v2.1.0`, or `not-supplied`. |
| `denominator_source` | Current CIS v6 artifact, Defender/Azure Policy mapping, legacy v2.1.0 checklist, or scoped subset. |

Do not treat the old nine-section v2.1.0 map as current v6.0.0. If exact v6.0.0 IDs are not available in the supplied material, say `exact v6 mapping requires benchmark access` instead of guessing IDs.

Use these statuses:

| Status | Use When |
|--------|----------|
| Current Azure v6 Scope | Control belongs to selected CIS Azure Foundations v6.0.0 evidence. |
| Entra/M365 Scope | Control belongs to Microsoft Entra or Microsoft 365 identity benchmark scope. |
| Legacy Azure v2.1.0 | Control came from the v2.1.0 checklist. |
| Deleted or Migrated | Control was deleted from Azure Foundations or migrated to Microsoft 365 Foundations. |
| Manual Evidence | Reviewer has portal exports, governance records, or other non-automated evidence. |
| Not Evaluable | Supplied evidence cannot prove pass or fail. |

---

## Current Azure v6.0.0-Aware Review Areas

Use the current CIS benchmark artifact, Defender for Cloud regulatory compliance evidence, Azure Policy compliance exports, or Azure CLI exports to map exact control IDs. The review areas below guide evidence collection without inventing recommendation IDs.

### Defender for Cloud and Azure Policy

Review focus:

- Defender plans enabled for relevant resource types.
- Security contacts and notification routing.
- Auto provisioning or modern agent settings where required by the selected benchmark.
- Azure Policy assignments and exemptions that affect compliance.
- Defender regulatory compliance export tied to the selected benchmark version.

Evidence patterns:

```
azurerm_security_center_subscription_pricing
azurerm_security_center_contact
azurerm_security_center_auto_provisioning
azurerm_policy_assignment
azurerm_policy_exemption
Microsoft.Security/pricings
Microsoft.PolicyInsights
```

### Storage, Database, and Data Services

Review focus:

- Storage secure transfer, public access, minimum TLS, CMK, private endpoints, and soft delete.
- SQL auditing, firewall rules, TDE, Microsoft Entra admin, private access, and threat detection.
- Cosmos DB, PostgreSQL Flexible Server, MySQL Flexible Server, and other supported database services when present.

Terraform patterns:

```hcl
resource "azurerm_storage_account" "sa" {
  enable_https_traffic_only         = true
  allow_nested_items_to_be_public   = false
  min_tls_version                   = "TLS1_2"
  infrastructure_encryption_enabled = true
}

resource "azurerm_storage_account_network_rules" "sa" {
  default_action = "Deny"
}

resource "azurerm_mssql_server" "sql" {
  public_network_access_enabled = false
  minimum_tls_version           = "1.2"
}

resource "azurerm_postgresql_flexible_server" "pg" {
  public_network_access_enabled = false
}
```

### Logging and Monitoring

Review focus:

- Diagnostic settings for subscriptions, Key Vault, Network Security Groups, Storage, SQL, and other critical resources.
- Activity Log alerts for policy changes, NSG changes, SQL firewall changes, public IP changes, and security rule changes.
- Log Analytics workspace retention and routing evidence.

Evidence patterns:

```
azurerm_monitor_diagnostic_setting
azurerm_monitor_activity_log_alert
azurerm_log_analytics_workspace
Microsoft.Insights/diagnosticSettings
```

### Networking, Virtual Machines, and Compute

Review focus:

- NSG rules exposing RDP, SSH, or admin ports to `0.0.0.0/0`, `Internet`, or `::/0`.
- Flow logs, traffic analytics, and Network Watcher evidence.
- Azure Bastion or other controlled administrative access.
- Managed disks, disk encryption, approved VM extensions, and endpoint protection.
- Modern VM resources and deprecated resource aliases.

Terraform patterns:

```hcl
resource "azurerm_network_security_rule" "bad_ssh" {
  direction                 = "Inbound"
  access                    = "Allow"
  source_address_prefix     = "Internet"
  destination_port_range    = "22"
}

resource "azurerm_linux_virtual_machine" "vm" {
  disable_password_authentication = true
}

resource "azurerm_windows_virtual_machine" "vm" {
  provision_vm_agent = true
}
```

### Key Vault and App Service

Review focus:

- Key Vault soft delete, purge protection, RBAC authorization, private endpoints, and key/secret expiration.
- App Service HTTPS-only, minimum TLS, client certificates where required, managed identity, authentication, HTTP/2, and FTP restrictions.

Terraform patterns:

```hcl
resource "azurerm_key_vault" "kv" {
  soft_delete_retention_days = 90
  purge_protection_enabled   = true
  enable_rbac_authorization  = true
}

resource "azurerm_linux_web_app" "app" {
  https_only = true
  site_config {
    minimum_tls_version = "1.2"
    ftps_state          = "Disabled"
    http2_enabled       = true
  }
}

resource "azurerm_windows_web_app" "app" {
  https_only = true
  site_config {
    minimum_tls_version = "1.2"
    ftps_state          = "Disabled"
    http2_enabled       = true
  }
}
```

---

## Entra Boundary Rules

Current Azure Foundations v6.0.0-aware reports must not silently score Entra controls as Azure controls.

| Evidence Found | Requested Scope | Handling |
|----------------|-----------------|----------|
| Entra Security Defaults, MFA, Conditional Access, guest access, PIM, app registration settings | Azure Foundations v6 only | Report under `Entra/M365 Scope` and exclude from Azure score. |
| Same Entra evidence | Microsoft 365/Entra scope included | Evaluate in a separate Microsoft 365/Entra section with its own benchmark version and denominator. |
| Same Entra evidence | Legacy Azure v2.1.0 requested | Evaluate under `Legacy Azure v2.1.0` and mark the report as legacy. |
| No Entra evidence supplied | Azure Foundations v6 only | Record `entra_scope_handling: excluded` or `not-supplied`. |

Entra examples to route out of current Azure score:

- Security Defaults and Conditional Access equivalence.
- MFA for privileged and non-privileged users.
- Named/trusted locations and geographic access policies.
- Guest user access reviews and restrictions.
- Self-service password reset methods.
- Privileged Identity Management.
- App registration restrictions.

---

## Version Mapping and Scoring Rules

Use this table when the evidence includes current and legacy benchmark material:

| Control or Finding | Current Azure v6 Status | Legacy v2.1.0 Status | Entra/M365 Status | Evidence Source | Assessment Status |
|--------------------|-------------------------|----------------------|-------------------|-----------------|-------------------|
| Storage secure transfer | Current Azure v6 Scope | legacy mapped if supplied | none | Terraform + Azure Policy | Pass/Fail |
| Conditional Access MFA | Deleted or Migrated | Legacy Azure v2.1.0 | Entra/M365 Scope | Entra export | Excluded from Azure score |
| Key Vault purge protection | Current Azure v6 Scope | legacy mapped if supplied | none | Terraform + Defender | Pass/Fail |

Scoring rules:

1. Count only controls in the selected Azure Foundations denominator.
2. Do not count `Entra/M365 Scope`, `Legacy Azure v2.1.0`, `Deleted or Migrated`, or `Not Evaluable` as passing current Azure v6 controls.
3. A Defender for Cloud or Azure Policy finding can prove live status only for the tenant/subscription/resource scope named in the evidence.
4. IaC evidence can prove intended configuration, not live runtime compliance, unless backed by Defender, Azure Policy, Azure CLI, or portal exports.
5. If exact v6 IDs are unavailable, use service-family labels and mark exact mapping as requiring benchmark access.

---

## Legacy CIS Azure v2.1.0 Checklist

Use this section only when `legacy_baseline: true` or `entra_scope_handling: legacy-v2.1.0` is declared.

Legacy v2.1.0 grouped controls into nine sections:

| Legacy Section | Domain | Current Handling |
|----------------|--------|------------------|
| 1 | Identity and Access Management | Migrated out of current Azure Foundations; route to Entra/M365 or legacy mode. |
| 2 | Microsoft Defender for Cloud | Re-evaluate against v6 source before current scoring. |
| 3 | Storage Accounts | Re-evaluate against v6 source before current scoring. |
| 4 | Database Services | Re-evaluate against v6 source before current scoring. |
| 5 | Logging and Monitoring | Re-evaluate against v6 source before current scoring. |
| 6 | Networking | Re-evaluate against v6 source before current scoring. |
| 7 | Virtual Machines | Include modern VM resources when checking current IaC. |
| 8 | Key Vault | Re-evaluate against v6 source before current scoring. |
| 9 | App Service | Include Linux and Windows App Service variants. |

Legacy v2.1.0 examples remain useful as implementation patterns, but the report must not present them as current v6 control IDs unless a current mapping source is recorded.

---

## Output Checklist

Every final report must include:

- Benchmark version and source date.
- `legacy_baseline` and reason when true.
- `entra_scope_handling` and whether Entra evidence was excluded, included under Microsoft 365, or handled as legacy.
- Evidence source for every finding.
- Scope status for every finding.
- Denominator source.
- Separate counts for current Azure, Entra/M365, legacy, deleted/migrated, manual, and not-evaluable controls.
- Clear statement when the review is IaC-only and cannot prove live Azure posture.
