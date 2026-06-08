resource "azurerm_kubernetes_cluster" "payments" {
  name                = "payments-prod"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "payments-prod"

  private_cluster_enabled             = true
  private_cluster_public_fqdn_enabled = false
  api_server_authorized_ip_ranges     = ["203.0.113.0/24"]
  role_based_access_control_enabled   = true
  local_account_disabled              = true
  oidc_issuer_enabled                 = true
  workload_identity_enabled           = true
  azure_policy_enabled                = true

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks.id]
  }

  default_node_pool {
    name           = "system"
    vm_size        = "Standard_D4s_v5"
    node_count     = 3
    vnet_subnet_id = azurerm_subnet.aks.id
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.aks.id
  }

  microsoft_defender {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.aks.id
  }
}
