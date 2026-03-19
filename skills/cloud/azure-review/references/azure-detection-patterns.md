# Azure Detection Patterns Reference

Extracted from [benchmark-checklist.md](../benchmark-checklist.md). This file consolidates HCL and Bicep detection patterns used for CIS Azure v2.1.0 detection.

---

## Identity and Access Management (Section 1)

### Conditional Access MFA (CIS 1.1.2, 1.1.3)

```hcl
resource "azuread_conditional_access_policy" {
  conditions {
    users {
      included_roles = ["62e90394-69f5-4237-9190-012177145e10"]  # Global Admin
    }
  }
  grant_controls {
    built_in_controls = ["mfa"]
  }
}
```

### Named Locations (CIS 1.2.1)

```hcl
resource "azuread_named_location" {
  ip {
    ip_ranges = [...]
    trusted   = true
  }
}
```

---

## Microsoft Defender for Cloud (Section 2)

### Defender Plan Enablement (CIS 2.1.1-2.1.11)

```hcl
resource "azurerm_security_center_subscription_pricing" {
  tier          = "Standard"    # Must be "Standard", not "Free"
  resource_type = "<type>"      # VirtualMachines, AppServices, SqlServers, etc.
}
```

Detection regex:
```
azurerm_security_center_subscription_pricing
tier\s*=\s*"Standard"
resource_type\s*=\s*"(VirtualMachines|AppServices|SqlServers|SqlServerVirtualMachines|OpenSourceRelationalDatabases|CosmosDbs|StorageAccounts|Containers|KeyVaults|Dns|Arm)"
```

### Auto Provisioning (CIS 2.2.1)

```hcl
resource "azurerm_security_center_auto_provisioning" {
  auto_provision = "On"
}
```

### Security Contact (CIS 2.2.4)

```hcl
resource "azurerm_security_center_contact" {
  alert_notifications = true
  alerts_to_admins    = true
}
```

---

## Storage Accounts (Section 3)

### HTTPS Enforcement (CIS 3.1)

```
enable_https_traffic_only\s*=\s*(true|false)
```

### Infrastructure Encryption (CIS 3.2)

```
infrastructure_encryption_enabled\s*=\s*true
```

### Public Access Prevention (CIS 3.7)

```
allow_nested_items_to_be_public\s*=\s*false
allow_blob_public_access\s*=\s*(true|false)
```

### Network Default Action (CIS 3.8)

```
default_action\s*=\s*"(Deny|Allow)"
azurerm_storage_account_network_rules
```

### Soft Delete (CIS 3.11)

```
delete_retention_policy
container_delete_retention_policy
```

### TLS Version (CIS 3.15)

```
min_tls_version\s*=\s*"TLS1_2"
```

---

## Database Services (Section 4)

### SQL Auditing (CIS 4.1.1)

```
azurerm_mssql_server_extended_auditing_policy
```

### SQL Firewall Rules (CIS 4.1.2)

```hcl
# Critical: Detect overly permissive firewall rules
resource "azurerm_mssql_firewall_rule" {
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"   # FAIL
}
```

Detection regex:
```
start_ip_address\s*=\s*"0\.0\.0\.0"
end_ip_address\s*=\s*"(0\.0\.0\.0|255\.255\.255\.255)"
```

### SSL Enforcement (CIS 4.2.1, 4.2.2)

```
ssl_enforcement_enabled\s*=\s*(true|false)
```

### Cosmos DB Public Access (CIS 4.3.8)

```
public_network_access_enabled\s*=\s*false
```

---

## Logging and Monitoring (Section 5)

### Diagnostic Settings (CIS 5.1.1)

```
azurerm_monitor_diagnostic_setting
log_analytics_workspace_id
```

### Activity Log Alerts (CIS 5.2.1-5.2.9)

```
azurerm_monitor_activity_log_alert
operation_name\s*=\s*"Microsoft\.(Authorization|Network|Security|Sql|Network)/.*/(write|delete)"
```

### Network Watcher (CIS 5.3.1)

```
azurerm_network_watcher
```

---

## Networking (Section 6)

### NSG Open Admin Ports (CIS 6.1, 6.2)

```hcl
# Critical detection patterns
resource "azurerm_network_security_rule" {
  direction              = "Inbound"
  access                 = "Allow"
  destination_port_range = "3389"         # or "22"
  source_address_prefix  = "*"            # or "Internet" or "0.0.0.0/0"
}
```

Detection regex:
```
source_address_prefix\s*=\s*"(\*|Internet|0\.0\.0\.0/0)"
destination_port_range\s*=\s*"(22|3389)"
```

### Flow Log Retention (CIS 6.5)

```
azurerm_network_watcher_flow_log
retention_policy
days\s*=\s*\d+
```

---

## Key Vault (Section 8)

### Key/Secret Expiration (CIS 8.1-8.4)

```
expiration_date
azurerm_key_vault_key
azurerm_key_vault_secret
```

### Soft Delete and Purge Protection (CIS 8.5)

```
soft_delete_retention_days
purge_protection_enabled\s*=\s*true
```

### RBAC Authorization (CIS 8.6)

```
enable_rbac_authorization\s*=\s*true
```

---

## App Service (Section 9)

### Authentication (CIS 9.1)

```
auth_settings_v2
auth_enabled\s*=\s*true
```

### HTTPS Redirect (CIS 9.2)

```
https_only\s*=\s*true
```

### TLS Version (CIS 9.3)

```
minimum_tls_version\s*=\s*"1\.2"
```

### FTP State (CIS 9.10)

```
ftps_state\s*=\s*"(Disabled|AllAllowed|FtpsOnly)"
```
