# CIS Azure Foundations Benchmark v2.1.0 -- Detailed Checklist

This file contains the detailed CIS benchmark checklist items for the Azure Security Posture Review skill. See [SKILL.md](SKILL.md) for the main skill definition, process overview, and output format.

---

## Section 1 -- Identity and Access Management

Evaluate Entra ID and IAM configurations against CIS Azure v2.1.0 Section 1 recommendations.

### CIS 1.1 -- Security Defaults and Conditional Access

#### CIS 1.1.1 -- Ensure Security Defaults is enabled on Microsoft Entra ID

Check for security defaults or conditional access policies:

```hcl
# Terraform AzureAD provider
resource "azuread_authentication_strength_policy" { ... }
```

**Note:** Security Defaults should be disabled ONLY when Conditional Access policies provide equivalent or stronger controls.

#### CIS 1.1.2 -- Ensure that Multi-Factor Authentication is enabled for all privileged users

Check for Conditional Access policies requiring MFA for admin roles:

```hcl
resource "azuread_conditional_access_policy" {
  conditions {
    users {
      included_roles = ["62e90394-69f5-4237-9190-012177145e10"] # Global Admin
    }
  }
  grant_controls {
    built_in_controls = ["mfa"]
  }
}
```

#### CIS 1.1.3 -- Ensure that Multi-Factor Authentication is enabled for all non-privileged users

Verify MFA requirement extends to all users, not just admins.

#### CIS 1.1.4 -- Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled

Check for MFA trust settings that weaken the control.

### CIS 1.2 -- Conditional Access Policies

#### CIS 1.2.1 -- Ensure Trusted Locations Are Defined

Check for named location definitions:

```hcl
resource "azuread_named_location" {
  display_name = "Corporate Network"
  ip {
    ip_ranges = ["203.0.113.0/24"]
    trusted   = true
  }
}
```

#### CIS 1.2.2 -- Ensure that an exclusionary Geographic Access Policy is considered

Verify country-based access restrictions exist in conditional access policies.

#### CIS 1.2.3 -- Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'

Check for tenant creation restrictions.

#### CIS 1.2.4 -- Ensure Guest Users are reviewed on a regular basis

Look for access review configurations targeting guest users.

#### CIS 1.2.5 -- Ensure that 'Number of methods required to reset' is set to '2'

Check SSPR (Self-Service Password Reset) configuration.

#### CIS 1.2.6 -- Ensure that password hash sync is enabled for hybrid deployments

Verify `password_hash_sync_enabled` in Entra Connect configurations.

### CIS 1.3 -- Privileged Identity Management

#### CIS 1.3.1 -- Ensure that 'Users can register applications' is set to 'No'

```hcl
# Check for app registration restrictions
resource "azuread_directory_role_assignment" { ... }
```

#### CIS 1.3.2 -- Ensure that 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects'

#### CIS 1.3.3 -- Ensure that 'Restrict access to Microsoft Entra admin center' is set to 'Yes'

---

## Section 2 -- Microsoft Defender for Cloud

Evaluate Defender for Cloud configurations against Section 2 recommendations.

### CIS 2.1 -- Defender Plans

#### CIS 2.1.1 -- Ensure that Microsoft Defender for Servers is set to 'On'

```hcl
resource "azurerm_security_center_subscription_pricing" {
  tier          = "Standard"  # Must be Standard, not Free
  resource_type = "VirtualMachines"
}
```

#### CIS 2.1.2 -- Ensure that Microsoft Defender for App Service is set to 'On'

```hcl
resource "azurerm_security_center_subscription_pricing" {
  tier          = "Standard"
  resource_type = "AppServices"
}
```

#### CIS 2.1.3 -- Ensure that Microsoft Defender for Azure SQL Database Servers is set to 'On'

Check for `resource_type = "SqlServers"` with `tier = "Standard"`.

#### CIS 2.1.4 -- Ensure that Microsoft Defender for SQL Servers on Machines is set to 'On'

Check for `resource_type = "SqlServerVirtualMachines"` with `tier = "Standard"`.

#### CIS 2.1.5 -- Ensure that Microsoft Defender for Open-Source Relational Databases is set to 'On'

Check for `resource_type = "OpenSourceRelationalDatabases"` pricing tier.

#### CIS 2.1.6 -- Ensure that Microsoft Defender for Azure Cosmos DB is set to 'On'

Check for `resource_type = "CosmosDbs"` pricing tier.

#### CIS 2.1.7 -- Ensure that Microsoft Defender for Storage is set to 'On'

Check for `resource_type = "StorageAccounts"` with `tier = "Standard"`.

#### CIS 2.1.8 -- Ensure that Microsoft Defender for Containers is set to 'On'

Check for `resource_type = "Containers"` pricing tier.

#### CIS 2.1.9 -- Ensure that Microsoft Defender for Key Vault is set to 'On'

Check for `resource_type = "KeyVaults"` pricing tier.

#### CIS 2.1.10 -- Ensure that Microsoft Defender for DNS is set to 'On'

Check for `resource_type = "Dns"` pricing tier.

#### CIS 2.1.11 -- Ensure that Microsoft Defender for Resource Manager is set to 'On'

Check for `resource_type = "Arm"` pricing tier.

### CIS 2.2 -- Security Policies and Contacts

#### CIS 2.2.1 -- Ensure that 'Auto provisioning of Log Analytics agent' is set to 'On'

```hcl
resource "azurerm_security_center_auto_provisioning" {
  auto_provision = "On"
}
```

#### CIS 2.2.2 -- Ensure that Microsoft Defender for Cloud Apps integration with Microsoft Defender for Cloud is selected

#### CIS 2.2.3 -- Ensure that Microsoft Defender for Endpoint integration with Microsoft Defender for Cloud is selected

#### CIS 2.2.4 -- Ensure that 'Email notification for high severity alerts' is set to 'On'

```hcl
resource "azurerm_security_center_contact" {
  alert_notifications = true
  alerts_to_admins    = true
  email               = "security@example.com"
  phone               = "+1-555-0100"
}
```

---

## Section 3 -- Storage Accounts

Evaluate Storage account configurations against Section 3 recommendations.

### CIS 3.1 -- Ensure that 'Secure transfer required' is set to 'Enabled'

```hcl
resource "azurerm_storage_account" {
  enable_https_traffic_only = true  # Must be true
}
```

### CIS 3.2 -- Ensure that 'Enable Infrastructure Encryption' for each Storage Account is checked

```hcl
resource "azurerm_storage_account" {
  infrastructure_encryption_enabled = true
}
```

### CIS 3.3 -- Ensure that 'Enable key rotation reminders' is enabled for each Storage Account

Check for key expiration policies.

### CIS 3.7 -- Ensure that 'Public access level' is disabled for storage accounts with blob containers

```hcl
resource "azurerm_storage_account" {
  allow_nested_items_to_be_public = false  # Must be false
}
```

### CIS 3.8 -- Ensure Default Network Access Rule for Storage Accounts is Set to Deny

**Critical check:**

```hcl
resource "azurerm_storage_account_network_rules" {
  default_action = "Deny"  # Must be Deny, not Allow
}

# Or within the storage account resource:
resource "azurerm_storage_account" {
  network_rules {
    default_action = "Deny"
  }
}
```

### CIS 3.9 -- Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled

Check for `bypass = ["AzureServices"]` in network rules.

### CIS 3.10 -- Ensure Private Endpoints are used to access Storage Accounts

Check for private endpoint configurations:

```hcl
resource "azurerm_private_endpoint" {
  private_service_connection {
    is_manual_connection           = false
    private_connection_resource_id = azurerm_storage_account.example.id
    subresource_names              = ["blob"]
  }
}
```

### CIS 3.11 -- Ensure Soft Delete is Enabled for Azure Containers and Blob Storage

```hcl
resource "azurerm_storage_account" {
  blob_properties {
    delete_retention_policy {
      days = 7  # Must be > 0
    }
    container_delete_retention_policy {
      days = 7
    }
  }
}
```

### CIS 3.12 -- Ensure Storage for Critical Data are Encrypted with Customer Managed Keys

Check for CMK encryption on storage accounts containing sensitive data:

```hcl
resource "azurerm_storage_account_customer_managed_key" {
  storage_account_id = azurerm_storage_account.example.id
  key_vault_id       = azurerm_key_vault.example.id
  key_name           = azurerm_key_vault_key.example.name
}
```

### CIS 3.13 -- Ensure Storage Logging is Enabled for Queue Service

Check for diagnostic settings on queue services.

### CIS 3.15 -- Ensure Minimum TLS Version is set to 1.2

```hcl
resource "azurerm_storage_account" {
  min_tls_version = "TLS1_2"  # Must be TLS1_2
}
```

---

## Section 4 -- Database Services

Evaluate database configurations against Section 4 recommendations.

### CIS 4.1 -- SQL Server Auditing

#### CIS 4.1.1 -- Ensure that 'Auditing' is set to 'On' for SQL servers

```hcl
resource "azurerm_mssql_server_extended_auditing_policy" {
  server_id              = azurerm_mssql_server.example.id
  storage_endpoint       = azurerm_storage_account.example.primary_blob_endpoint
  retention_in_days      = 90
}
```

#### CIS 4.1.2 -- Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0

**Critical check:**

```hcl
# BAD: Allow all Azure services
resource "azurerm_mssql_firewall_rule" {
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# BAD: Allow all IPs
resource "azurerm_mssql_firewall_rule" {
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
```

#### CIS 4.1.3 -- Ensure SQL Server Threat Detection is set to 'On'

```hcl
resource "azurerm_mssql_server_security_alert_policy" {
  state = "Enabled"
}
```

#### CIS 4.1.4 -- Ensure that 'Email service and co-administrators' is enabled for MSSQL

Check email notification settings in threat detection policies.

### CIS 4.2 -- PostgreSQL and MySQL

#### CIS 4.2.1 -- Ensure 'Enforce SSL connection' is set to 'Enabled' for PostgreSQL Database Server

```hcl
resource "azurerm_postgresql_server" {
  ssl_enforcement_enabled = true
}
```

#### CIS 4.2.2 -- Ensure 'Enforce SSL connection' is set to 'Enabled' for MySQL Database Server

```hcl
resource "azurerm_mysql_server" {
  ssl_enforcement_enabled = true
}
```

### CIS 4.3 -- Cosmos DB and Other Databases

#### CIS 4.3.1 -- Ensure that Azure Active Directory Admin is Configured for SQL Servers

```hcl
resource "azurerm_mssql_server_active_directory_administrator" {
  server_id  = azurerm_mssql_server.example.id
  login      = "sqladmin"
  object_id  = data.azuread_group.sql_admins.object_id
}
```

#### CIS 4.3.2 -- Ensure that 'Data encryption' is set to 'On' on a SQL Database

Check for Transparent Data Encryption (TDE):

```hcl
resource "azurerm_mssql_database" {
  transparent_data_encryption_enabled = true
}
```

#### CIS 4.3.8 -- Ensure that 'Public Network Access' is 'Disabled' for Cosmos DB accounts

```hcl
resource "azurerm_cosmosdb_account" {
  public_network_access_enabled = false
}
```

---

## Section 5 -- Logging and Monitoring

Evaluate logging configurations against Section 5 recommendations.

### CIS 5.1 -- Diagnostic Settings and Activity Logs

#### CIS 5.1.1 -- Ensure that a 'Diagnostic Setting' exists

Check for diagnostic settings on subscriptions:

```hcl
resource "azurerm_monitor_diagnostic_setting" {
  target_resource_id = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
}
```

#### CIS 5.1.2 -- Ensure Diagnostic Setting captures appropriate categories

Verify that Administrative, Security, ServiceHealth, Alert, Recommendation, Policy, Autoscale, and ResourceHealth categories are enabled.

#### CIS 5.1.3 -- Ensure the storage container storing the activity logs is not publicly accessible

Check storage account access level for the diagnostic logs container.

#### CIS 5.1.4 -- Ensure the storage account containing the container with activity logs is encrypted with a Customer Managed Key

Cross-reference the diagnostics storage account with CMK encryption.

#### CIS 5.1.5 -- Ensure that logging for Azure Key Vault is 'Enabled'

```hcl
resource "azurerm_monitor_diagnostic_setting" {
  target_resource_id = azurerm_key_vault.example.id
  enabled_log {
    category = "AuditEvent"
  }
}
```

### CIS 5.2 -- Activity Log Alerts

#### CIS 5.2.1 -- Ensure that Activity Log Alert exists for Create Policy Assignment

```hcl
resource "azurerm_monitor_activity_log_alert" {
  criteria {
    operation_name = "Microsoft.Authorization/policyAssignments/write"
    category       = "Administrative"
  }
}
```

**Required Activity Log Alerts (CIS 5.2.1 through 5.2.9):**

| CIS ID | Operation | Category |
|--------|-----------|----------|
| 5.2.1 | Create Policy Assignment | Microsoft.Authorization/policyAssignments/write |
| 5.2.2 | Delete Policy Assignment | Microsoft.Authorization/policyAssignments/delete |
| 5.2.3 | Create or Update Network Security Group | Microsoft.Network/networkSecurityGroups/write |
| 5.2.4 | Delete Network Security Group | Microsoft.Network/networkSecurityGroups/delete |
| 5.2.5 | Create or Update Security Solution | Microsoft.Security/securitySolutions/write |
| 5.2.6 | Delete Security Solution | Microsoft.Security/securitySolutions/delete |
| 5.2.7 | Create or Update SQL Server Firewall Rule | Microsoft.Sql/servers/firewallRules/write |
| 5.2.8 | Delete SQL Server Firewall Rule | Microsoft.Sql/servers/firewallRules/delete |
| 5.2.9 | Create or Update Public IP Address | Microsoft.Network/publicIPAddresses/write |

### CIS 5.3 -- Network Watcher

#### CIS 5.3.1 -- Ensure that Network Watcher is 'Enabled'

```hcl
resource "azurerm_network_watcher" {
  location = var.location
}
```

---

## Section 6 -- Networking

Evaluate network configurations against Section 6 recommendations.

### CIS 6.1 -- Ensure that RDP access from the Internet is evaluated and restricted

**Critical check:**

```hcl
# BAD: NSG allowing RDP from Internet
resource "azurerm_network_security_rule" {
  direction                  = "Inbound"
  access                     = "Allow"
  destination_port_range     = "3389"
  source_address_prefix      = "*"      # or "Internet" or "0.0.0.0/0"
}
```

### CIS 6.2 -- Ensure that SSH access from the Internet is evaluated and restricted

```hcl
# BAD: NSG allowing SSH from Internet
resource "azurerm_network_security_rule" {
  direction                  = "Inbound"
  access                     = "Allow"
  destination_port_range     = "22"
  source_address_prefix      = "*"
}
```

### CIS 6.3 -- Ensure that UDP access from the Internet is evaluated and restricted

Check for NSG rules allowing UDP from any source.

### CIS 6.4 -- Ensure that HTTP(S) access from the Internet is evaluated and restricted

Verify that ports 80 and 443 are only open where intended (e.g., load balancers, app gateways).

### CIS 6.5 -- Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'

```hcl
resource "azurerm_network_watcher_flow_log" {
  retention_policy {
    enabled = true
    days    = 90  # Must be >= 90
  }
}
```

### CIS 6.6 -- Ensure that Network Watcher flow logs capture and send data to Log Analytics

Check for `traffic_analytics` block in flow log configuration.

---

## Section 7 -- Virtual Machines

Evaluate VM configurations against Section 7 recommendations.

### CIS 7.1 -- Ensure an Azure Bastion Host Exists

Check for Azure Bastion deployment:

```hcl
resource "azurerm_bastion_host" { ... }
```

### CIS 7.2 -- Ensure Virtual Machines are utilizing Managed Disks

```hcl
resource "azurerm_virtual_machine" {
  storage_os_disk {
    managed_disk_type = "Premium_LRS"  # Using managed disk
  }
}
```

### CIS 7.3 -- Ensure that 'OS and Data' disks are encrypted with CMK

```hcl
resource "azurerm_disk_encryption_set" {
  key_vault_key_id = azurerm_key_vault_key.example.id
}
```

### CIS 7.4 -- Ensure that 'Unattached disks' are encrypted with CMK

Check for orphaned disks without encryption.

### CIS 7.5 -- Ensure that Only Approved Extensions Are Installed

Audit VM extensions for unauthorized or unnecessary extensions.

### CIS 7.6 -- Ensure that Endpoint Protection is installed for all Virtual Machines

Check for anti-malware extension deployment.

### CIS 7.7 -- Ensure that VHDs are Encrypted

Verify encryption for any legacy VHD-based disks.

---

## Section 8 -- Key Vault

Evaluate Key Vault configurations against Section 8 recommendations.

### CIS 8.1 -- Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults

```hcl
resource "azurerm_key_vault_key" {
  expiration_date = "2025-12-31T00:00:00Z"  # Must be set
}
```

### CIS 8.2 -- Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults

Same check for classic access policy-based Key Vaults.

### CIS 8.3 -- Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults

```hcl
resource "azurerm_key_vault_secret" {
  expiration_date = "2025-12-31T00:00:00Z"  # Must be set
}
```

### CIS 8.4 -- Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults

Same check for classic access policy-based Key Vaults.

### CIS 8.5 -- Ensure that the Key Vault is Recoverable

**Critical check -- enable soft delete and purge protection:**

```hcl
resource "azurerm_key_vault" {
  soft_delete_retention_days = 90
  purge_protection_enabled   = true  # Must be true
}
```

### CIS 8.6 -- Enable Role Based Access Control for Azure Key Vault

```hcl
resource "azurerm_key_vault" {
  enable_rbac_authorization = true  # Preferred over access policies
}
```

### CIS 8.7 -- Ensure that Private Endpoints are used for Azure Key Vault

Check for private endpoint connections to Key Vault:

```hcl
resource "azurerm_private_endpoint" {
  private_service_connection {
    private_connection_resource_id = azurerm_key_vault.example.id
    subresource_names              = ["vault"]
  }
}
```

---

## Section 9 -- App Service

Evaluate App Service configurations against Section 9 recommendations.

### CIS 9.1 -- Ensure App Service Authentication is set up for apps in Azure App Service

```hcl
resource "azurerm_linux_web_app" {
  auth_settings_v2 {
    auth_enabled = true
  }
}
```

### CIS 9.2 -- Ensure Web App Redirects All HTTP Traffic to HTTPS

```hcl
resource "azurerm_linux_web_app" {
  https_only = true  # Must be true
}
```

### CIS 9.3 -- Ensure Web App is using the latest version of TLS encryption

```hcl
resource "azurerm_linux_web_app" {
  site_config {
    minimum_tls_version = "1.2"  # Must be 1.2 or higher
  }
}
```

### CIS 9.4 -- Ensure the Web App has 'Client Certificates (Incoming client certificates)' set to 'On'

```hcl
resource "azurerm_linux_web_app" {
  client_certificate_mode    = "Required"
  client_certificate_enabled = true
}
```

### CIS 9.5 -- Ensure that Register with Entra ID is enabled on App Service

Check for identity configuration:

```hcl
resource "azurerm_linux_web_app" {
  identity {
    type = "SystemAssigned"
  }
}
```

### CIS 9.9 -- Ensure that 'HTTP20Enabled' is set for a Web App

```hcl
resource "azurerm_linux_web_app" {
  site_config {
    http2_enabled = true
  }
}
```

### CIS 9.10 -- Ensure FTP deployments are Disabled

```hcl
resource "azurerm_linux_web_app" {
  site_config {
    ftps_state = "Disabled"  # Must be Disabled, not AllAllowed or FtpsOnly
  }
}
```

---

## Supplemental -- Azure Container Apps and Workload Identity Federation

These evidence gates are CIS-adjacent Azure workload checks. They do not replace the CIS v2.1.0 section score, but they prevent App Service, Key Vault, and Entra ID checks from missing Container Apps-specific secret, ingress, and federated identity risk.

### AZ-ACA-01 -- Ensure production Container Apps secrets are not direct plaintext values

Flag direct secret values in Terraform, Bicep, ARM, CLI exports, or checked-in configuration for production workloads:

```hcl
resource "azurerm_container_app" "webhook" {
  secret {
    name  = "stripe-webhook-secret"
    value = "whsec_plaintext_value" # Finding: direct production secret value
  }
}
```

```json
{
  "type": "Microsoft.App/containerApps",
  "properties": {
    "configuration": {
      "secrets": [
        { "name": "payment-api-key", "value": "plain-secret" }
      ]
    }
  }
}
```

Benign calibration: local examples or non-production demos may include placeholder values, but production assessments should record environment, data classification, owner, and a migration plan to Key Vault references or managed identity.

### AZ-ACA-02 -- Verify Key Vault-backed Container Apps secrets have runtime identity and scoped vault access

A Key Vault reference is acceptable only when the Container App identity used for retrieval is explicit and has narrow Key Vault access:

```hcl
resource "azurerm_user_assigned_identity" "aca_runtime" {
  name                = "checkout-runtime"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
}

resource "azurerm_role_assignment" "runtime_can_read_secrets" {
  scope                = azurerm_key_vault.app.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.aca_runtime.principal_id
}

resource "azurerm_container_app" "checkout_api" {
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aca_runtime.id]
  }

  secret {
    name                = "payment-api-key"
    key_vault_secret_id = "${azurerm_key_vault.app.vault_uri}secrets/payment-api-key/0a1b2c3d4e5f"
    identity            = azurerm_user_assigned_identity.aca_runtime.id
  }
}
```

Record these fields for each Key Vault-backed secret:

| Field | Evidence |
|---|---|
| Secret reference type | direct value, Key Vault versioned URI, Key Vault latest-version URI |
| Runtime identity | system-assigned, user-assigned, missing, or not evaluable |
| Vault access scope | vault, resource group, subscription, management group, or unknown |
| Vault permission | `Key Vault Secrets User`, access policy `get/list`, broader contributor/owner, or unknown |
| Secret version | pinned version, latest version, or not evaluable |
| Vault controls | purge protection, RBAC authorization, private endpoint/logging where available |

Flag `AZ-ACA-02` when the runtime identity is missing, the vault access is broader than needed, or the URI is not a Key Vault reference for production secrets.

### AZ-ACA-03 -- Record Key Vault secret version and rotation evidence

Flag `AZ-ACA-03` when a production Container Apps Key Vault reference uses the latest secret version without documented rotation, rollback, change-control, or deployment-revision evidence. Treat an unpinned secret version as an evidence item rather than an automatic high-severity failure when rotation and rollback controls are documented.

### AZ-ACA-04 -- Verify env, volume, and scale-rule secret references resolve to controlled secrets

Environment variables and scale rules can safely reference Container Apps secrets, but the referenced secret must exist and be backed by the appropriate source:

```hcl
template {
  container {
    env {
      name        = "PAYMENT_API_KEY"
      secret_name = "payment-api-key" # Benign when payment-api-key is Key Vault-backed
    }
  }

  scale_rule {
    name             = "queue"
    custom_rule_type = "azure-queue"
    authentication {
      secret_name       = "queue-connection"
      trigger_parameter = "connection"
    }
  }
}
```

Do not flag an environment variable solely because its name contains `KEY`, `TOKEN`, or `SECRET`. Flag `AZ-ACA-04` when `secret_name`, `secretRef`, volume secret, or scale-rule secret references a missing secret, a direct production value, or a secret whose Key Vault identity/access evidence is missing.

### AZ-ACA-05 and AZ-ACA-06 -- Review external Container Apps ingress and insecure transport separately from VM/NSG exposure

Container Apps can expose HTTP endpoints without a VM public IP or obvious NSG rule. Review `ingress` and Container Apps Environment evidence:

```hcl
resource "azurerm_container_app" "admin_api" {
  ingress {
    external_enabled           = true
    target_port                = 8080
    allow_insecure_connections = true # Finding unless explicitly justified and protected
  }
}
```

For each external endpoint, collect:

| Field | Evidence |
|---|---|
| Ingress exposure | external, internal, private endpoint, or not evaluable |
| Transport | HTTPS-only, `allow_insecure_connections`, TLS termination evidence |
| Authentication | Entra auth, app gateway/front door auth, API gateway, mTLS/client certificate, or application auth evidence |
| Authorization | role/tenant checks, backend authorization policy, API gateway policy, or not evaluable |
| Workload context | public API, admin API, webhook, internal service, health endpoint |
| Data classification | public, internal, confidential, regulated, unknown |

`external_enabled = true` is not automatically a finding for a public API. Flag `AZ-ACA-05` when external ingress lacks authentication, authorization, private endpoint/internal environment, or data-classification evidence. Flag `AZ-ACA-06` when insecure connections are allowed or HTTPS-only enforcement evidence is missing. Assign severity based on authentication, authorization, transport security, private endpoint/internal environment design, allowed origins, and workload/data classification.

### AZ-WIF-01 -- Verify federated identity credential issuer, audience, and subject precision

Workload identity federation is preferred over long-lived client secrets, but wildcarded trust can over-authorize CI/CD:

```hcl
resource "azuread_application_federated_identity_credential" "github" {
  application_id = azuread_application.deploy.id
  display_name   = "github-main"
  issuer         = "https://token.actions.githubusercontent.com"
  audiences      = ["api://AzureADTokenExchange"]
  subject        = "repo:example-org/example-repo:*" # Finding: wildcard subject
}
```

Record issuer-specific constraints:

| Provider | Evidence to require |
|---|---|
| GitHub Actions | org/repo, branch/tag/environment, workflow or reusable workflow boundary where applicable, audience |
| GitLab | project path, ref type, ref, environment, audience |
| Terraform Cloud | organization, workspace, run phase, audience |
| Custom OIDC | issuer URL, signing/key trust, subject format, audience, claim mapping |

Flag findings for wildcard subjects such as `repo:org/repo:*`, unbounded branch/tag patterns, wrong audience, issuer mismatch, missing environment constraints for production deploys, or missing provider documentation.

### AZ-WIF-02 -- Verify Azure RBAC scope reached by the federated principal

Federated identity safety depends on both token claims and Azure permissions. For each federated service principal, map role assignments:

```hcl
resource "azurerm_role_assignment" "deploy" {
  scope                = azurerm_subscription.primary.id
  role_definition_name = "Owner" # Finding for a narrow app deploy workflow
  principal_id         = azuread_service_principal.deploy.object_id
}
```

Prefer resource group, app, or environment-specific roles over subscription-wide `Owner`, `Contributor`, `User Access Administrator`, or broad Key Vault permissions. Record scope, role name, principal ID, environment, owner, and business purpose.

### AZ-WIF-03 -- Check for leftover long-lived credentials after federation

If workload identity federation is implemented, verify that long-lived deployment credentials are removed or justified:

```hcl
resource "azuread_application_password" "deploy_secret" {
  application_id = azuread_application.deploy.id
  display_name   = "legacy-ci-secret" # Finding if still active without exception evidence
}
```

Not Evaluable reasons include missing Entra application export, missing service principal credentials export, missing Azure RBAC assignments, missing CI/CD OIDC configuration, or provider-specific subject/audience evidence unavailable.
